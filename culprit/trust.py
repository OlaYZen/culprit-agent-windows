"""Who is really on the other end of a request.

Two questions the gate must answer before it looks at a cookie, and both are
about *trust in the network path*, not in the user:

1. **Is the peer a reverse proxy we declared?** Forwarding headers
   (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`, ...) are plain text any
   client can type. They are only meaningful when the socket peer is a proxy
   the operator named in Settings > Network trust (or `--trust-proxy` for one
   run). From such a peer the headers are honoured: the login limiter keys on
   the real client and the session cookie learns it crossed TLS. From anyone
   else a forwarding header is **refused** (400), not ignored. Ignoring it
   was the earlier behaviour and it hides a real misconfiguration: an
   undeclared proxy in front of the host means every visitor shares one
   limiter bucket (one attacker locks everyone out) and the host never learns
   the original scheme. Refusing makes the missing declaration visible on the
   first request instead of months later.

2. **Is the `Host` header one of ours?** When the operator lists the names
   the dashboard is reached at, any other `Host` is refused. That closes DNS
   rebinding (a hostile page resolving its own name to this machine) and
   mis-routed requests from a shared proxy. Empty list = not enforced, which
   is the default because a wrong list locks the operator out from the
   network. The machine's own names always pass without being listed:
   loopback, every interface address, the host name and FQDN
   (`local_names`). A rebinding page can only ever carry the attacker's own
   domain, so accepting our own addresses costs nothing -- and it means the
   list only has to hold the *extra* DNS names, and a shell on the host or
   an agent on the LAN can always get through.

Everything here is pure: no framework objects, so tools/check_auth.py can
assert each rule against literal headers.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Mapping

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Headers only a proxy has any business setting. Their presence on a request
# from an undeclared peer is the finding, whatever their value.
FORWARDING_HEADERS: tuple[str, ...] = (
    "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-forwarded-port", "x-forwarded-prefix", "x-forwarded-server",
    "x-real-ip", "x-client-ip", "true-client-ip", "cf-connecting-ip",
)

# Always an acceptable Host, whatever the allow-list says: the recovery path
# when the list is wrong is a shell on the machine itself.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_LOCAL_TTL = 60.0
_local_cache: tuple[float, frozenset[str]] = (0.0, frozenset())

# One-run additions from the command line (`--trust-proxy`), comma-separated.
ENV_PROXIES = "CULPRIT_TRUST_PROXY"

_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


# ------------------------------------------------------------------ parsing
def split_entries(value: object) -> list[str]:
    """A list, or one string with newline/comma/space separators, -> a
    de-duplicated list of stripped entries. Order is kept."""
    if isinstance(value, str):
        raw: Iterable[object] = re.split(r"[\s,]+", value)
    elif isinstance(value, (list, tuple)):
        raw = value
    else:
        raise ValueError("expected a list of entries")
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError("every entry must be text")
        text = item.strip()
        if text and text not in out:
            out.append(text)
    return out


def parse_network(text: str) -> Network:
    """'10.0.0.5', '10.0.0.0/8', '::1', '[::1]' -> a network (a bare address
    is a /32 or /128)."""
    candidate = text.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        raise ValueError(f"{text!r} is not an IP address or CIDR range") from None


def parse_proxies(entries: Iterable[str]) -> list[Network]:
    return [parse_network(entry) for entry in entries]


def clean_proxies(entries: Iterable[str]) -> list[str]:
    """Validate and return the entries as typed (brackets off), so the saved
    form stays what the operator wrote ('::1', not '::1/128')."""
    out: list[str] = []
    for entry in entries:
        parse_network(entry)
        text = entry.strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        if text not in out:
            out.append(text)
    return out


def parse_hosts(entries: Iterable[str]) -> list[str]:
    """Normalise host entries: lower-case, brackets and trailing dot off.
    Accepts hostnames, `*.suffix` wildcards, IPv4 and IPv6 literals. A port
    is rejected rather than silently stripped -- the request's port is never
    compared, and a saved `host:8787` that could never match would be a
    lock-out waiting to happen."""
    out: list[str] = []
    for entry in entries:
        text = entry.strip().lower().rstrip(".")
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        if not text:
            continue
        if text.startswith("*."):
            body = text[2:]
            if not body or not _valid_hostname(body):
                raise ValueError(f"{entry!r}: a wildcard needs a domain after '*.'")
        elif ":" in text:
            try:
                ipaddress.IPv6Address(text)
            except ValueError:
                raise ValueError(f"{entry!r}: leave the port off; only the host "
                                 "name is compared") from None
        elif not _valid_hostname(text):
            raise ValueError(f"{entry!r} is not a host name or IP address")
        if text not in out:
            out.append(text)
    return out


def _valid_hostname(text: str) -> bool:
    if len(text) > 253:
        return False
    return all(_HOST_LABEL.match(label) for label in text.split("."))


def local_names(refresh: bool = False) -> frozenset[str]:
    """Names that are this machine by definition: loopback, every interface
    address (IPv6 scope id stripped), the host name and the FQDN. A Host of
    one of these is never DNS rebinding -- a hostile page can only carry its
    own domain -- so they pass without being listed. Cached a minute so a
    DHCP renewal or a new Docker bridge needs no restart."""
    global _local_cache
    now = time.monotonic()
    if not refresh and now - _local_cache[0] < _LOCAL_TTL:
        return _local_cache[1]
    names = set(LOOPBACK_HOSTS)
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    names.add(addr.address.split("%", 1)[0].lower())
    except Exception:  # noqa: BLE001 -- psutil missing or sysfs gated: loopback still works
        pass
    for lookup in (socket.gethostname, socket.getfqdn):
        try:
            name = lookup().strip().lower().rstrip(".")
        except OSError:
            continue
        if name:
            names.add(name)
    _local_cache = (now, frozenset(names))
    return _local_cache[1]


def runtime_proxies() -> list[str]:
    """Proxies added for this run only via the environment / CLI."""
    return split_entries(os.environ.get(ENV_PROXIES, ""))


# ------------------------------------------------------------------- policy
@dataclass(frozen=True)
class Policy:
    proxies: tuple[Network, ...]
    hosts: tuple[str, ...]


@lru_cache(maxsize=8)
def _compile(proxies: tuple[str, ...], hosts: tuple[str, ...]) -> Policy:
    nets: list[Network] = []
    for entry in proxies:
        try:
            nets.append(parse_network(entry))
        except ValueError:
            continue  # config.load() already dropped and logged these
    names: list[str] = []
    for entry in hosts:
        try:
            names.extend(parse_hosts([entry]))
        except ValueError:
            continue
    return Policy(tuple(nets), tuple(names))


def policy(proxies: Iterable[str], hosts: Iterable[str],
           include_runtime: bool = True) -> Policy:
    """Parsed, cached lists. The saved lists plus the one-run additions."""
    extra = tuple(runtime_proxies()) if include_runtime else ()
    return _compile(tuple(proxies) + extra, tuple(hosts))


# --------------------------------------------------------------- resolution
def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = text.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped or addr


def is_trusted(peer: str | None, networks: Iterable[Network]) -> bool:
    addr = _address(peer or "")
    if addr is None:
        return False
    return any(addr in net for net in networks)


def host_of(header: str | None) -> str:
    """The comparable part of a Host header: no port, no brackets, lower-case,
    no trailing dot. `[::1]:8787` -> `::1`, `Dash.Example.com.` -> `dash.example.com`."""
    text = (header or "").strip().lower()
    if not text:
        return ""
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end > 0 else text
    if text.count(":") == 1:
        text = text.rsplit(":", 1)[0]
    return text.rstrip(".")


def host_allowed(host: str, allowed: Iterable[str],
                 local: frozenset[str] | None = None) -> bool:
    """`local` overrides the machine's own names (tests pass a fixed set)."""
    names = tuple(allowed)
    if not names:
        return True
    if host in (local_names() if local is None else local):
        return True
    for name in names:
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and len(host) > len(suffix):
                return True
        elif host == name:
            return True
    return False


def _forwarded_pairs(value: str) -> list[dict[str, str]]:
    """RFC 7239 `Forwarded`: `for=1.2.3.4;proto=https, for="[::1]:80"`."""
    elements: list[dict[str, str]] = []
    for element in value.split(","):
        pairs: dict[str, str] = {}
        for pair in element.split(";"):
            key, sep, val = pair.strip().partition("=")
            if not sep:
                continue
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] == '"':
                val = val[1:-1]
            pairs[key.strip().lower()] = val
        if pairs:
            elements.append(pairs)
    return elements


def _strip_port(text: str) -> str:
    """`[2001:db8::1]:1234` -> `2001:db8::1`, `1.2.3.4:56` -> `1.2.3.4`."""
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end > 0 else text
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


@dataclass
class Access:
    peer: str                 # the socket peer
    client: str               # who we hold responsible (peer, or forwarded)
    host: str                 # the comparable Host (forwarded when via proxy)
    scheme: str               # the scheme the client used
    via_proxy: bool           # forwarding headers were present AND honoured
    refusal: str | None = None
    reason: str | None = None  # "untrusted_proxy" | "untrusted_host"

    def public(self) -> dict[str, object]:
        return {"peer": self.peer, "client": self.client, "host": self.host,
                "scheme": self.scheme, "via_proxy": self.via_proxy}


def resolve(peer: str | None, headers: Mapping[str, str], pol: Policy,
            scheme: str = "http", local: frozenset[str] | None = None) -> Access:
    """Apply the policy to one request. Never raises; a refusal is a field.

    `headers` must look up case-insensitively (Starlette's does) or be
    lower-cased by the caller. `local` pins the machine's own names (tests).
    """
    peer_text = peer or "?"
    present = [name for name in FORWARDING_HEADERS if name in headers]
    host = host_of(headers.get("host"))
    access = Access(peer=peer_text, client=peer_text, host=host, scheme=scheme,
                    via_proxy=False)
    if present:
        if not is_trusted(peer_text, pol.proxies):
            access.refusal = (
                f"request carries {present[0]!r} but {peer_text} is not a trusted "
                "proxy; reverse proxies are refused until declared in Settings > "
                "Network trust (or --trust-proxy)")
            access.reason = "untrusted_proxy"
            return access
        access.via_proxy = True
        forwarded = _forwarded_pairs(headers.get("forwarded") or "")
        chain: list[str] = []
        xff = headers.get("x-forwarded-for")
        if xff:
            chain = [_strip_port(part) for part in xff.split(",") if part.strip()]
        elif forwarded:
            chain = [_strip_port(el["for"]) for el in forwarded if "for" in el]
        elif headers.get("x-real-ip"):
            chain = [_strip_port(headers["x-real-ip"])]
        # Walk from the right: each trusted hop appended the address it saw,
        # so the first entry not itself a trusted proxy is the real client.
        # Anything to its left was typed by the client and is never used.
        client = None
        for hop in reversed(chain):
            addr = _address(hop)
            if addr is None:
                break  # a proxy we trust wrote something unparseable: stop
            if is_trusted(str(addr), pol.proxies):
                client = str(addr)  # all hops trusted so far: the proxy itself
                continue
            client = str(addr)
            break
        if client:
            access.client = client
        xfh = headers.get("x-forwarded-host")
        if not xfh and forwarded:
            xfh = next((el["host"] for el in forwarded if "host" in el), None)
        if xfh:
            access.host = host_of(xfh.split(",")[0])
        proto = headers.get("x-forwarded-proto")
        if not proto and forwarded:
            proto = next((el["proto"] for el in forwarded if "proto" in el), None)
        if proto:
            proto = proto.split(",")[0].strip().lower()
            if proto in ("http", "https"):
                access.scheme = proto
    if not host_allowed(access.host, pol.hosts, local):
        access.refusal = (
            f"the request asked for Host {access.host!r}, which is not one of this "
            "dashboard's names (Settings > Network trust > Trusted host names); "
            "this machine's own addresses, host name and loopback always pass")
        access.reason = "untrusted_host"
    return access
