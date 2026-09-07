"""Network throughput, interfaces, sockets and connectivity health.

Two collectors again: per-interface byte counters are cheap enough for the fast
tick, while interface configuration, the socket table and reachability probes
run on the slow tick.

Interface config comes from /sys/class/net plus `ip -json route` and
systemd-resolved (falling back to /etc/resolv.conf) -- no daemon dependency.
Sockets come from psutil (which reads /proc/net/*): measured at ~3ms for this
machine's table, so the netlink sock_diag upgrade the porting notes suggest
was not worth a hand-rolled netlink client here; PID attribution would still
be fd-scanning either way. Sockets owned by other users list with pid=null
and the payload says how many.

Reachability keeps the Windows build's hardest-won lesson verbatim: probe with
TCP (not ICMP), try several ports, run them concurrently, and report a silent
host as **"filtered", not "down"** -- managed gateways routinely drop
everything they are not obliged to answer.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import socket
import struct
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil

from .. import linux
from ..util import rate

log = logging.getLogger("culprit.network")

# Interface name prefixes -> kind. Predictable-naming prefixes (en*, wl*) plus
# the classic ones; VPN and container plumbing by the names their drivers use.
_KIND_PREFIXES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("lo",), "loopback"),
    (("wg", "tun", "tap", "ppp", "tailscale", "zt", "nordlynx", "proton"), "vpn"),
    (("docker", "veth", "br-", "virbr", "lxc", "lxd", "cni", "flannel",
      "kube", "vnet"), "virtual"),
    (("wl",), "wifi"),
    (("en", "eth", "em", "eno", "ens", "enp"), "ethernet"),
    (("ww",), "cellular"),
    (("bond", "team"), "bond"),
)


def _classify(name: str) -> str:
    lowered = name.lower()
    for prefixes, kind in _KIND_PREFIXES:
        if lowered.startswith(prefixes):
            return kind
    # /sys uevent DEVTYPE catches renamed wifi/bridge interfaces.
    devtype = linux.parse_kv_file(f"/sys/class/net/{name}/uevent", sep="=").get(
        "DEVTYPE")
    if devtype == "wlan":
        return "wifi"
    if devtype in ("bridge", "vlan"):
        return "virtual"
    if devtype == "wwan":
        return "cellular"
    return "other"


# VPN interface name -> the software behind it, so the UI can say *which* VPN.
_VPN_TYPES: tuple[tuple[str, str], ...] = (
    ("nordlynx", "NordVPN"), ("proton", "ProtonVPN"), ("tailscale", "Tailscale"),
    ("wg", "WireGuard"), ("zt", "ZeroTier"), ("tun", "OpenVPN"),
    ("tap", "OpenVPN"), ("ppp", "PPP"),
)


def _vpn_type(name: str) -> str:
    low = name.lower()
    for prefix, label in _VPN_TYPES:
        if low.startswith(prefix):
            return label
    return "VPN"


# HTTP (not HTTPS) on purpose: the response is a single public IP, not a secret,
# and plain HTTP sidesteps CA-trust differences across minimal container images.
# ip-api additionally names the IP's owner and flags known proxy/VPN exits,
# which is how an upstream (router-level) VPN with no local interface is caught.
_WAN_INFO_URL = ("http://ip-api.com/json/?fields=status,query,isp,org,as,"
                 "proxy,hosting")
_WAN_ENDPOINTS = (
    "http://checkip.amazonaws.com",
    "http://ifconfig.me/ip",
    "http://icanhazip.com",
)

# Substrings that mark a WAN exit IP as a VPN provider's, from the IP's org/ISP/
# ASN. A plain datacenter IP is "hosting" but NOT a VPN, so the hosting flag is
# deliberately never used as a signal on its own -- only proxy or a name match.
_VPN_PROVIDER_HINTS = (
    "mullvad", "31173 services", "nordvpn", "nord vpn", "protonvpn",
    "proton vpn", "proton ag", "expressvpn", "express vpn", "surfshark",
    "private internet access", "cyberghost", "ipvanish", "windscribe",
    "tunnelbear", "azirevpn", "perfect privacy", "torguard", "vyprvpn",
    "purevpn", "hide.me", "ovpn ", "mullvad vpn", "datapacket",
)


def _looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _vpn_provider(*fields: object) -> str | None:
    """The VPN provider named in an IP's org/ISP/ASN, or None."""
    blob = " ".join(str(f).lower() for f in fields if f)
    return next((hint for hint in _VPN_PROVIDER_HINTS if hint in blob), None)


def _wan_ip() -> dict[str, object]:
    """The machine's public (WAN) IP, and -- where the lookup allows -- who owns
    it, so an upstream VPN can be recognised from its exit address.

    This is the one collector that deliberately reaches a third party, so it is
    cached hard by the caller (the IP changes rarely) and every failure degrades
    to an explicit unavailable+reason rather than a blank or a guess. Primary
    source ip-api.com returns the IP together with its ISP/org/ASN and a proxy
    flag in one request; a plain echo service is the IP-only fallback.
    """
    try:
        req = urllib.request.Request(_WAN_INFO_URL,
                                     headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read(4096).decode("utf-8", "replace"))
        ip = str(data.get("query") or "")
        if data.get("status") == "success" and _looks_like_ip(ip):
            return {"available": True, "ip": ip, "via": "ip-api.com",
                    "isp": data.get("isp") or None, "org": data.get("org") or None,
                    "asn": data.get("as") or None,
                    "proxy": bool(data.get("proxy")),
                    "hosting": bool(data.get("hosting")), "reason": None}
    except Exception:  # noqa: BLE001 -- fall through to the echo services
        pass

    for url in _WAN_ENDPOINTS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                text = resp.read(64).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001 -- any failure just tries the next host
            continue
        ip = text.split()[0] if text else ""
        if _looks_like_ip(ip):
            host = url.split("//", 1)[-1].split("/", 1)[0]
            return {"available": True, "ip": ip, "via": host, "isp": None,
                    "org": None, "asn": None, "proxy": None, "hosting": None,
                    "reason": None}
    return {"available": False, "ip": None, "via": None, "isp": None,
            "org": None, "asn": None, "proxy": None, "hosting": None,
            "reason": "no public-IP service answered (no outbound internet, or "
                      "HTTP egress is blocked)"}


class NetworkRateCollector:
    """Fast-tick per-interface throughput."""

    # Link speed and MTU change only on reconfiguration; net_if_stats() is the
    # expensive half of this collector, so it refreshes on a slow TTL.
    _STATS_TTL = 10.0

    def __init__(self) -> None:
        self._prev: dict[str, object] = {}
        self._prev_at = time.monotonic()
        self._stats: dict[str, object] = {}
        self._stats_at = 0.0
        try:
            self._prev = psutil.net_io_counters(pernic=True)
        except Exception:  # noqa: BLE001
            self._prev = {}

    def sample(self) -> dict[str, object]:
        moment = time.monotonic()
        elapsed = moment - self._prev_at
        try:
            current = psutil.net_io_counters(pernic=True)
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "reason": str(exc), "interfaces": []}

        if moment - self._stats_at > self._STATS_TTL:
            try:
                self._stats = psutil.net_if_stats()
            except Exception:  # noqa: BLE001
                self._stats = {}
            self._stats_at = moment
        stats = self._stats

        interfaces = []
        total_sent = total_recv = 0.0
        for name, counters in current.items():
            kind = _classify(name)
            if kind == "loopback":
                continue
            previous = self._prev.get(name)
            sent_rate = rate(counters.bytes_sent,
                             getattr(previous, "bytes_sent", None), elapsed)
            recv_rate = rate(counters.bytes_recv,
                             getattr(previous, "bytes_recv", None), elapsed)
            stat = stats.get(name)
            is_up = bool(getattr(stat, "isup", False))
            # A down interface with zero traffic is clutter; one that was just
            # carrying traffic is a symptom, so recently active ones stay.
            if not is_up and sent_rate == 0 and recv_rate == 0 and counters.bytes_recv == 0:
                continue
            total_sent += sent_rate
            total_recv += recv_rate
            speed = getattr(stat, "speed", 0)
            interfaces.append({
                "name": name,
                "up": is_up,
                "operstate": linux.read_line(f"/sys/class/net/{name}/operstate"),
                "speed_mbps": speed if speed and speed > 0 else None,
                "mtu": getattr(stat, "mtu", None),
                "duplex": _duplex(getattr(stat, "duplex", 0)),
                "sent_bytes_sec": round(sent_rate),
                "recv_bytes_sec": round(recv_rate),
                "sent_total": counters.bytes_sent,
                "recv_total": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "errors": counters.errin + counters.errout,
                "drops": counters.dropin + counters.dropout,
                "kind": kind,
            })

        interfaces.sort(key=lambda i: -(i["sent_bytes_sec"] + i["recv_bytes_sec"]))
        self._prev = current
        self._prev_at = moment

        return {
            "available": True,
            "reason": None,
            "interfaces": interfaces,
            "total": {
                "sent_bytes_sec": round(total_sent),
                "recv_bytes_sec": round(total_recv),
            },
        }


class NetworkDetailCollector:
    """Slow-tick interface config, socket table and connectivity probes."""

    def __init__(self) -> None:
        self._config: list[dict[str, object]] | None = None
        self._config_at = 0.0
        self._probe_cache: dict[str, object] = {}
        self._probe_at = 0.0
        self._wan: dict[str, object] | None = None
        self._wan_at = 0.0
        # (local, peer) -> (monotonic, bytes_sent, bytes_received) of the last
        # tick, so each established connection carries a byte rate.
        self._conn_prev: dict[tuple[str, str], tuple[float, int, int]] = {}

    def sample(self, processes: list[dict] | None = None) -> dict[str, object]:
        """`processes` (the latest process table) names the process and unit
        behind each connection, so the Map can say nginx, not pid 4242."""
        now = time.monotonic()
        # Config changes on VPN connect/disconnect and DHCP renewal, so it
        # refreshes every 60s rather than caching for the process lifetime.
        if self._config is None or now - self._config_at > 60:
            self._config = _adapter_config()
            self._config_at = now

        sockets = _socket_table(processes or [], self._conn_prev, now)

        if now - self._probe_at > 30:
            self._probe_cache = _connectivity(self._config or [])
            self._probe_at = now

        # The public IP changes rarely and the lookup is an outbound request, so
        # it refreshes far less often than the rest of the slow tier.
        if self._wan is None or now - self._wan_at > 300:
            self._wan = _wan_ip()
            self._wan_at = now

        vpn_active = [
            adapter for adapter in (self._config or [])
            if adapter.get("kind") == "vpn" and adapter.get("ip_addresses")
        ]

        # Second signal: the exit IP itself. An upstream/router VPN leaves no
        # local interface, so it is only visible as a WAN IP owned by a VPN
        # provider (name match) or flagged as a proxy/VPN exit. "hosting" alone
        # is never used -- a plain VPS is hosting but not a VPN.
        wan = self._wan or {}
        provider = _vpn_provider(wan.get("org"), wan.get("isp"), wan.get("asn"))
        via_exit_ip = bool(wan.get("proxy")) or provider is not None
        exit_provider = (wan.get("org") or wan.get("isp")) if via_exit_ip else None

        return {
            "adapters": self._config or [],
            "sockets": sockets,
            "connectivity": self._probe_cache,
            "wan_ip": self._wan,
            "vpn": {
                "active": bool(vpn_active) or via_exit_ip,
                # A VPN interface carrying the default route -- or an exit IP that
                # is itself the VPN's -- means all traffic leaves via the VPN.
                "full_tunnel": (any(a.get("default_route") for a in vpn_active)
                                or via_exit_ip),
                # Detected purely from the exit IP (no local VPN interface) --
                # i.e. the VPN runs upstream, on the router.
                "via_exit_ip": via_exit_ip,
                "exit_provider": exit_provider,
                "interfaces": [
                    {"name": a["description"],
                     "type": _vpn_type(str(a["description"])),
                     "addresses": a.get("ip_addresses") or [],
                     "default_route": bool(a.get("default_route"))}
                    for a in vpn_active
                ],
                "adapters": [a["description"] for a in vpn_active],
            },
        }


def _adapter_config() -> list[dict[str, object]]:
    """IP / gateway / DNS per interface from psutil, ip(8) and resolved."""
    try:
        addrs = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001
        addrs = {}

    routes = linux.run_json(["ip", "-json", "route", "show", "default"],
                            timeout=5)
    gateway_by_dev: dict[str, list[str]] = {}
    default_devs: set[str] = set()
    for route in routes if isinstance(routes, list) else []:
        dev = route.get("dev")
        if not dev:
            continue
        # A full-tunnel VPN default route may have no gateway (point-to-point),
        # so track the device separately from the gateway.
        default_devs.add(dev)
        gw = route.get("gateway")
        if gw:
            gateway_by_dev.setdefault(dev, []).append(str(gw))

    dns_servers, dns_domain, dns_source = _dns_config()

    out: list[dict[str, object]] = []
    for name, entries in addrs.items():
        kind = _classify(name)
        if kind == "loopback":
            continue
        ips, subnets, mac = [], [], None
        for entry in entries:
            family = getattr(entry.family, "name", str(entry.family))
            if family in ("AF_INET", "AF_INET6"):
                address = entry.address.split("%")[0]
                ips.append(address)
                if entry.netmask:
                    subnets.append(entry.netmask)
            elif family in ("AF_LINK", "AF_PACKET"):
                mac = entry.address
        gateways = gateway_by_dev.get(name, [])
        out.append({
            "description": name,
            "kind": kind,
            "ip_addresses": ips,
            "subnets": subnets,
            "gateways": gateways,
            "default_route": name in default_devs,
            # DNS on Linux is system-wide (resolved/resolv.conf), not
            # per-adapter; every row shows the same resolver set and its
            # provenance rather than pretending per-NIC DNS exists.
            "dns_servers": dns_servers,
            "dns_domain": dns_domain,
            "dns_source": dns_source,
            "dhcp": None,  # not knowable generically without the DHCP client's state
            "dhcp_server": None,
            "mac": mac,
            "operstate": linux.read_line(f"/sys/class/net/{name}/operstate"),
        })
    # Interfaces with a default route first -- they are the ones that matter.
    out.sort(key=lambda a: (0 if a["gateways"] else 1, str(a["description"])))
    return out


def _dns_config() -> tuple[list[str], str | None, str]:
    """Resolver list, preferring the real upstreams from systemd-resolved.

    /etc/resolv.conf frequently just says 127.0.0.53 (the resolved stub),
    which is true but useless for "is my DNS server reachable".
    """
    # `resolvectl dns` output is line-per-link: "Link 2 (enp6s18): 1.2.3.4".
    # (resolvectl 255 has no JSON mode for status; the text here is stable.)
    text = linux.run(["resolvectl", "dns"], timeout=5)
    if text:
        servers: list[str] = []
        for line in text.splitlines():
            _, found, tail = line.partition(":")
            if not found:
                continue
            for address in tail.split():
                if address not in servers:
                    servers.append(address)
        if servers:
            domain = None
            domain_text = linux.run(["resolvectl", "domain"], timeout=5) or ""
            for line in domain_text.splitlines():
                _, found, tail = line.partition(":")
                if found and tail.strip():
                    domain = tail.split()[0]
                    break
            return servers, domain, "systemd-resolved"
    servers = []
    domain = None
    for line in (linux.read_text("/etc/resolv.conf") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
        elif len(parts) >= 2 and parts[0] in ("domain", "search"):
            domain = domain or parts[1]
    return servers, domain, "/etc/resolv.conf"


def _socket_table(processes: list[dict], conn_prev: dict[tuple[str, str], tuple[float, int, int]],
                  now: float) -> dict[str, object]:
    """Aggregate socket state plus listeners and peers per process.

    /proc/net/* is world-readable, but mapping a socket inode to its owning
    PID needs that process's /proc/<pid>/fd -- so other users' sockets appear
    with pid=null. Counted and reported, never hidden.

    Each established TCP connection also carries what the kernel knows about
    it, read passively -- no probe is sent, so no peer sees anything: the
    smoothed round-trip time and retransmit count (`ss -ti`, ~10 ms for a
    few hundred sockets; the one unprivileged place tcp_info is exposed), the
    send and receive queues (a send queue that stays full means the peer is
    not draining; a receive queue that does means this process is not
    reading), and a byte rate from two readings of the connection's counters.
    Without `ss` the queues still come from /proc/net/tcp and the rest is
    honestly absent. Summed per process this is also "who is using the
    network", which no /proc counter gives directly.
    """
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        return {"available": False, "reason": f"access denied: {exc}",
                "by_state": {}, "entries": []}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": str(exc), "by_state": {},
                "entries": []}

    names: dict[int, tuple[str | None, str | None]] = {}
    for row in processes:
        try:
            names[int(row.get("pid"))] = (row.get("name"), row.get("unit"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    info, ss_reason = _ss_established()
    if ss_reason is not None:
        info = _proc_net_established()

    by_state: dict[str, int] = {}
    by_pid: dict[int, dict[str, object]] = {}
    listeners: list[dict[str, object]] = []
    established: list[dict[str, object]] = []
    unattributed = 0
    seen_keys: set[tuple[str, str]] = set()

    for conn in connections:
        state = conn.status or "NONE"
        by_state[state] = by_state.get(state, 0) + 1
        pid = conn.pid or 0
        if not conn.pid:
            unattributed += 1
        slot = by_pid.setdefault(pid, {"pid": pid, "established": 0,
                                       "listening": 0, "other": 0})
        local = _addr(conn.laddr)
        remote = _addr(conn.raddr)
        if state == psutil.CONN_LISTEN:
            slot["listening"] = int(slot["listening"]) + 1  # type: ignore[arg-type]
            listeners.append({"pid": pid, "local": local,
                              "family": "IPv6" if conn.family.name == "AF_INET6"
                                        else "IPv4"})
        elif state == psutil.CONN_ESTABLISHED:
            slot["established"] = int(slot["established"]) + 1  # type: ignore[arg-type]
            if pid and pid not in names:
                # Not in the (trimmed) process table: one /proc read names it.
                names[pid] = (linux.read_line(f"/proc/{pid}/comm"),
                              linux.unit_from_cgroup(pid))
            name, unit = names.get(pid, (None, None))
            entry: dict[str, object] = {"pid": pid, "name": name, "unit": unit,
                                        "local": local, "remote": remote}
            key = (str(local), str(remote))
            stats = info.get(key) if conn.type == socket.SOCK_STREAM else None
            if stats:
                entry.update(stats)
                sent, recv = stats.get("bytes_sent"), stats.get("bytes_received")
                if isinstance(sent, int) and isinstance(recv, int):
                    prev = conn_prev.get(key)
                    if prev and now > prev[0]:
                        dt = now - prev[0]
                        entry["send_bytes_sec"] = round(max(0, sent - prev[1]) / dt)
                        entry["recv_bytes_sec"] = round(max(0, recv - prev[2]) / dt)
                    conn_prev[key] = (now, sent, recv)
                    seen_keys.add(key)
            established.append(entry)
        else:
            slot["other"] = int(slot["other"]) + 1  # type: ignore[arg-type]

    # Connections that closed take their counters with them.
    for key in [k for k in conn_prev if k not in seen_keys]:
        del conn_prev[key]

    listeners.sort(key=lambda entry: str(entry["local"]))
    established.sort(key=lambda e: -(float(e.get("send_bytes_sec") or 0)
                                     + float(e.get("recv_bytes_sec") or 0)))
    return {
        "available": True,
        "reason": None,
        "total": len(connections),
        "by_state": by_state,
        "by_pid": by_pid,
        "unattributed": unattributed,
        "unattributed_note": (
            f"{unattributed} socket(s) belong to other users' processes; "
            "attributing them needs CAP_SYS_PTRACE or root"
            if unattributed else None),
        "listeners": listeners[:200],
        "established": established[:400],
        "per_process": _per_process(established, names),
        # Whether the per-connection RTT / retransmits / byte counters were
        # readable; the queues alone still come from /proc/net/tcp.
        "tcp_info": ss_reason is None,
        "tcp_info_reason": ss_reason,
    }


def _per_process(established: list[dict[str, object]],
                 names: dict[int, tuple[str | None, str | None]]) -> list[dict[str, object]]:
    """Who is using the network: each process's connections summed. Only
    what the kernel exposes per socket -- a process whose sockets are not
    attributable (another user's, without CAP_SYS_PTRACE) is not here, and
    the socket table's unattributed count says how many that is."""
    by_pid: dict[int, dict[str, object]] = {}
    for entry in established:
        pid = int(entry.get("pid") or 0)
        if not pid:
            continue
        slot = by_pid.setdefault(pid, {
            "pid": pid, "name": names.get(pid, (None, None))[0],
            "unit": names.get(pid, (None, None))[1], "connections": 0,
            "send_bytes_sec": 0, "recv_bytes_sec": 0, "rtt_ms": None,
            "retrans": 0, "tx_queue": 0, "rx_queue": 0, "peers": set(),
        })
        slot["connections"] = int(slot["connections"]) + 1  # type: ignore[arg-type]
        slot["send_bytes_sec"] = int(slot["send_bytes_sec"]) + int(entry.get("send_bytes_sec") or 0)  # type: ignore[arg-type]
        slot["recv_bytes_sec"] = int(slot["recv_bytes_sec"]) + int(entry.get("recv_bytes_sec") or 0)  # type: ignore[arg-type]
        rtt = entry.get("rtt_ms")
        if isinstance(rtt, (int, float)) and (slot["rtt_ms"] is None or rtt > float(slot["rtt_ms"])):  # type: ignore[arg-type]
            slot["rtt_ms"] = rtt
        slot["retrans"] = int(slot["retrans"]) + int(entry.get("retrans") or 0)  # type: ignore[arg-type]
        slot["tx_queue"] = max(int(slot["tx_queue"]), int(entry.get("tx_queue") or 0))  # type: ignore[arg-type]
        slot["rx_queue"] = max(int(slot["rx_queue"]), int(entry.get("rx_queue") or 0))  # type: ignore[arg-type]
        remote = str(entry.get("remote") or "")
        host = remote.rsplit(":", 1)[0] if remote else ""
        if host:
            slot["peers"].add(host)  # type: ignore[union-attr]
    out = []
    for slot in by_pid.values():
        slot["peers"] = len(slot["peers"])  # type: ignore[arg-type]
        out.append(slot)
    out.sort(key=lambda s: (-(int(s["send_bytes_sec"]) + int(s["recv_bytes_sec"])),  # type: ignore[arg-type]
                            -int(s["connections"])))  # type: ignore[arg-type]
    return out[:40]


_SS_FIELDS = {
    "rtt": "rtt_ms", "minrtt": "rtt_min_ms", "retrans": "retrans",
    "bytes_sent": "bytes_sent", "bytes_received": "bytes_received",
    "unacked": "unacked", "lastsnd": "last_send_ms", "lastrcv": "last_recv_ms",
}


def _ss_established() -> tuple[dict[tuple[str, str], dict[str, object]], str | None]:
    """{(local, peer): tcp_info fields} for every established TCP socket,
    from one `ss -tinH` (netlink inet_diag; no privilege needed). Second
    value is the reason when it could not be read."""
    if not shutil.which("ss"):
        return {}, "iproute2 (`ss`) is not installed: per-connection RTT, retransmits and byte rates are unknown"
    try:
        proc = subprocess.run(["ss", "-tinH"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        return {}, f"`ss -tin` failed: {exc}"
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return {}, f"`ss -tin` failed: {err[0] if err else f'exit {proc.returncode}'}"
    out: dict[tuple[str, str], dict[str, object]] = {}
    current: tuple[str, str] | None = None
    queues: tuple[int, int] = (0, 0)
    for line in proc.stdout.splitlines():
        if not line.startswith((" ", "\t")):
            fields = line.split()
            # ESTAB <recv-q> <send-q> <local> <peer>
            if len(fields) < 5 or fields[0] != "ESTAB":
                current = None
                continue
            current = (fields[3], fields[4])
            try:
                queues = (int(fields[2]), int(fields[1]))
            except ValueError:
                queues = (0, 0)
            out[current] = {"tx_queue": queues[0], "rx_queue": queues[1]}
            continue
        if current is None:
            continue
        stats = out[current]
        for token in line.split():
            key, sep, value = token.partition(":")
            name = _SS_FIELDS.get(key)
            if not sep or name is None:
                continue
            if key == "rtt":
                value = value.split("/", 1)[0]
            elif key == "retrans":
                value = value.split("/", 1)[-1]   # current/total: keep the total
            try:
                number = float(value)
            except ValueError:
                continue
            stats[name] = round(number, 3) if key in ("rtt", "minrtt") else int(number)
    return out, None


def _proc_net_established() -> dict[tuple[str, str], dict[str, object]]:
    """Queues per established socket from /proc/net/tcp{,6} -- the fallback
    when `ss` is absent. No RTT or byte counters live there."""
    out: dict[tuple[str, str], dict[str, object]] = {}
    for path, family in (("/proc/net/tcp", socket.AF_INET), ("/proc/net/tcp6", socket.AF_INET6)):
        text = linux.read_text(path)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "01":
                continue
            try:
                local = _hex_addr(fields[1], family)
                remote = _hex_addr(fields[2], family)
                tx, _, rx = fields[4].partition(":")
                out[(local, remote)] = {"tx_queue": int(tx, 16), "rx_queue": int(rx, 16),
                                        "retrans": int(fields[6], 16)}
            except (ValueError, OSError):
                continue
    return out


def _hex_addr(text: str, family: int) -> str:
    """'0100007F:1F90' -> '127.0.0.1:8080' in psutil's formatting."""
    hex_ip, _, hex_port = text.rpartition(":")
    port = int(hex_port, 16)
    if family == socket.AF_INET:
        ip = socket.inet_ntop(family, struct.pack("<I", int(hex_ip, 16)))
        return f"{ip}:{port}"
    words = [int(hex_ip[i:i + 8], 16) for i in range(0, 32, 8)]
    ip = socket.inet_ntop(family, struct.pack("<IIII", *words))
    return f"[{ip}]:{port}"


def _connectivity(adapters: list[dict[str, object]]) -> dict[str, object]:
    """Probe the gateway, the DNS resolver, DNS itself and the open internet.

    Ported unchanged in design from the Windows build, where both lessons were
    learned the hard way:

    * **A gateway that ignores you is normal.** Several ports are tried, and
      if every one times out the verdict is *filtered* -- explicitly not the
      same as *down*.
    * **Probes must not be sequential.** Every (host, port) pair is its own
      concurrent job, so the worst case is one timeout, not the sum.
    """
    gateway = next((g for a in adapters for g in (a.get("gateways") or [])), None)
    dns = next(
        (d for a in adapters for d in (a.get("dns_servers") or [])
         if not str(d).startswith("127.")), None)

    targets: dict[str, tuple[str, tuple[int, ...]]] = {}
    if gateway:
        # Any answer proves the host is alive -- a RST counts just as well as
        # an accepted connection.
        targets["gateway"] = (str(gateway), (53, 80, 443, 22))
    if dns:
        targets["dns_server"] = (str(dns).split("#")[0], (53, 853))
    targets["internet"] = ("1.1.1.1", (443,))

    probes: list[tuple[str, str, int]] = [
        (label, host, port)
        for label, (host, ports) in targets.items()
        for port in ports
    ]

    results: dict[str, object] = {}
    per_target: dict[str, list[dict[str, object]]] = {label: [] for label in targets}

    with ThreadPoolExecutor(max_workers=min(12, len(probes) + 1),
                            thread_name_prefix="tpc-probe") as pool:
        futures = {
            pool.submit(_tcp_probe, host, port): (label, port)
            for label, host, port in probes
        }
        futures[pool.submit(_resolve_probe, "example.com")] = ("dns_resolution", 0)
        try:
            for future in as_completed(futures, timeout=5.0):
                label, port = futures[future]
                try:
                    outcome = future.result()
                except Exception as exc:  # noqa: BLE001
                    outcome = {"ok": False, "error": type(exc).__name__}
                if label == "dns_resolution":
                    results[label] = outcome
                else:
                    per_target[label].append(outcome)
        except TimeoutError:
            pass

    for label, attempts in per_target.items():
        host = targets[label][0]
        answered = next((a for a in attempts if a.get("ok")), None)
        if answered:
            results[label] = {**answered, "attempts": _slim_attempts(attempts)}
        else:
            ports = targets[label][1]
            results[label] = {
                "ok": False, "state": "filtered", "host": host,
                "attempts": _slim_attempts(attempts),
                "note": f"No response on {', '.join(str(p) for p in ports)}. The "
                        "host may be up but filtering traffic, which is normal "
                        "for a managed gateway. This is not proof it is down.",
            }

    results["checked_at"] = time.time()
    return results


def _slim_attempts(attempts: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        ({"port": a.get("port"), "ok": a.get("ok"), "state": a.get("state"),
          "latency_ms": a.get("latency_ms")} for a in attempts),
        key=lambda a: int(a["port"] or 0),
    )


def _tcp_probe(host: str, port: int, timeout: float = 0.7) -> dict[str, object]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"ok": True, "state": "open", "host": host, "port": port,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except ConnectionRefusedError:
        # Refused means something answered: the host is up, the port is closed.
        return {"ok": True, "state": "refused", "host": host, "port": port,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "state": "no answer", "host": host, "port": port,
                "error": type(exc).__name__}


def _resolve_probe(hostname: str) -> dict[str, object]:
    started = time.perf_counter()
    try:
        # A per-call timeout is not exposed by getaddrinfo, and mutating the
        # module-wide default from a worker thread would race with other
        # sockets, so this relies on the resolver's own timeout.
        socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        return {"ok": True, "host": hostname,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "host": hostname, "error": type(exc).__name__,
                "note": "DNS resolution failed. Package installs, sync clients "
                        "and most of the web will fail while this is broken."}


def _duplex(value: int) -> str | None:
    return {1: "half", 2: "full"}.get(int(value or 0))


def _addr(addr: object) -> str | None:
    if not addr:
        return None
    ip = getattr(addr, "ip", None)
    port = getattr(addr, "port", None)
    if ip is None:
        return None
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"
