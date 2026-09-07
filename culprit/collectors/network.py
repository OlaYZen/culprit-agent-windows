"""Network throughput, adapters, sockets and connectivity health.

Two collectors again: per-adapter byte counters are cheap enough for the fast
tick, while adapter configuration, the socket table and reachability probes
are not and run on the slow tick.

Adapter configuration comes from WMI (Win32_NetworkAdapterConfiguration) and
the route table (Win32_IP4RouteTable for the default route); sockets from
psutil, which on Windows reads the extended TCP/UDP tables that carry the
owning PID for every socket without elevation -- the one place Windows is
*more* forthcoming than Linux, where other users' sockets go unattributed.
What Windows does not hand out is per-connection TCP state: RTT, retransmits
and byte counters live behind GetPerTcpConnectionEStats, which needs the
connection to have been opted in and administrator rights, so `tcp_info` is
honestly False and the per-process view sums connection counts only.

Reachability uses a TCP connect rather than ICMP: raw sockets need elevation,
and `ping.exe` costs a process spawn per target. A TCP handshake against the
gateway/DNS resolver answers "is the network actually usable" more honestly
anyway, since plenty of corporate networks drop ICMP -- and a silent host is
reported as **filtered, not down**.

The WAN-IP lookup and the VPN-provider recognition are the Linux agent's,
verbatim: they are HTTP and string matching, nothing platform-specific.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil

from .. import windows
from ..util import rate

log = logging.getLogger("culprit.network")

# Interfaces that exist on every Windows box and only add noise.
_BORING = ("loopback pseudo-interface", "isatap", "teredo")

_VPN_HINTS = (
    "vpn", "anyconnect", "globalprotect", "forticlient", "pulse", "wireguard",
    "openvpn", "tap-windows", "zscaler", "netmotion", "tailscale", "zerotier",
    "checkpoint", "sonicwall", "ipsec", "juniper", "sophos", "nordlynx",
    "proton", "mullvad", "surfshark",
)

_VIRTUAL_HINTS = ("hyper-v", "vethernet", "vmware", "virtualbox", "wsl", "docker",
                  "bluetooth", "npcap", "microsoft kernel debug", "wan miniport")


def _classify(name: str) -> str:
    lowered = name.lower()
    if any(hint in lowered for hint in _VPN_HINTS):
        return "vpn"
    if any(hint in lowered for hint in _VIRTUAL_HINTS):
        return "virtual"
    if "wi-fi" in lowered or "wireless" in lowered or "wlan" in lowered or "802.11" in lowered:
        return "wifi"
    if "ethernet" in lowered or "gbe" in lowered or "gigabit" in lowered or "realtek pcie" in lowered:
        return "ethernet"
    if "loopback" in lowered:
        return "loopback"
    if "cellular" in lowered or "mobile broadband" in lowered or "wwan" in lowered:
        return "cellular"
    return "other"


def _is_boring(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in _BORING)



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
    """Fast-tick per-adapter throughput."""

    # Link speed, MTU and duplex change only when an adapter is reconfigured,
    # but `net_if_stats()` is the expensive half of this collector -- together
    # with the byte counters it cost ~98ms on every 1-second tick. Refreshing it
    # every 10s instead brings the fast tick down to ~30ms.
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
            return {"available": False, "reason": str(exc), "interfaces": [],
                    "total": {"sent_bytes_sec": None, "recv_bytes_sec": None}}

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
            if _is_boring(name):
                continue
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
            # A down adapter with zero traffic is clutter; a down adapter that
            # was just carrying traffic is a symptom, so keep recently active ones.
            if not is_up and sent_rate == 0 and recv_rate == 0 and counters.bytes_recv == 0:
                continue
            total_sent += sent_rate
            total_recv += recv_rate
            speed = getattr(stat, "speed", 0)
            interfaces.append({
                "name": name,
                "up": is_up,
                "operstate": "up" if is_up else "down",
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
    """Slow-tick adapter config, socket table and connectivity probes."""

    def __init__(self) -> None:
        self._config: list[dict[str, object]] | None = None
        self._config_at = 0.0
        self._probe_cache: dict[str, object] = {}
        self._probe_at = 0.0
        self._wan: dict[str, object] | None = None
        self._wan_at = 0.0

    def sample(self, processes: list[dict] | None = None) -> dict[str, object]:
        """`processes` (the latest process table) names the process behind
        each connection, so the Map can say chrome.exe, not pid 4242."""
        now = time.monotonic()
        # Adapter config changes on VPN connect/disconnect and DHCP renewal, so
        # refresh it every 60s rather than caching for the process lifetime.
        if self._config is None or now - self._config_at > 60:
            self._config = _adapter_config()
            self._config_at = now

        sockets = _socket_table(processes or [])

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
                "full_tunnel": (any(a.get("default_route") for a in vpn_active)
                                or via_exit_ip),
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
    """IP/DNS/gateway/DHCP per adapter, from WMI, plus which adapter carries
    the default route (Win32_IP4RouteTable destination 0.0.0.0)."""
    out: list[dict[str, object]] = []
    default_ifaces: set[int] = set()
    for route in windows.wmi_query(
            "SELECT InterfaceIndex, Metric1 FROM Win32_IP4RouteTable "
            "WHERE Destination = '0.0.0.0'", ("InterfaceIndex", "Metric1")):
        try:
            default_ifaces.add(int(route.get("InterfaceIndex")))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    for cfg in windows.wmi_query(
        "SELECT Description, IPAddress, IPSubnet, DefaultIPGateway, "
        "DNSServerSearchOrder, DHCPEnabled, DHCPServer, MACAddress, "
        "DNSDomain, InterfaceIndex "
        "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
        ("Description", "IPAddress", "IPSubnet", "DefaultIPGateway",
         "DNSServerSearchOrder", "DHCPEnabled", "DHCPServer", "MACAddress",
         "DNSDomain", "InterfaceIndex"),
    ):
        description = str(cfg.get("Description") or "")
        try:
            index: int | None = int(cfg.get("InterfaceIndex"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            index = None
        gateways = _tuple(cfg.get("DefaultIPGateway"))
        out.append({
            "description": description,
            "kind": _classify(description),
            "ip_addresses": _tuple(cfg.get("IPAddress")),
            "subnets": _tuple(cfg.get("IPSubnet")),
            "gateways": gateways,
            "default_route": (index in default_ifaces) if default_ifaces else bool(gateways),
            "dns_servers": _tuple(cfg.get("DNSServerSearchOrder")),
            "dns_domain": cfg.get("DNSDomain"),
            "dns_source": "adapter configuration (WMI)",
            "dhcp": bool(cfg.get("DHCPEnabled")),
            "dhcp_server": cfg.get("DHCPServer"),
            "mac": cfg.get("MACAddress"),
            "operstate": "up",
            "interface_index": index,
        })
    if not out and not windows.IS_WINDOWS:
        log.debug("adapter config: %s", windows.wmi_reason())
    return out


_TCP_INFO_REASON = windows.not_capable(
    "per-connection RTT, retransmits and byte counters need "
    "GetPerTcpConnectionEStats, which requires the connection to have been "
    "opted in and administrator rights; only the socket table is read")


def _socket_table(processes: list[dict]) -> dict[str, object]:
    """Aggregate socket state, plus the listeners and remote peers per process.

    The extended TCP/UDP tables name the owning PID of every socket, so a
    Windows box has no unattributed sockets in the Linux sense; psutil can
    still raise AccessDenied for the table as a whole under a restricted
    account, which is reported, not raised.
    """
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        return _no_sockets(f"access denied: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _no_sockets(str(exc))

    names: dict[int, tuple[str | None, str | None]] = {}
    for row in processes:
        try:
            names[int(row.get("pid"))] = (row.get("name"), None)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

    by_state: dict[str, int] = {}
    by_pid: dict[int, dict[str, object]] = {}
    listeners: list[dict[str, object]] = []
    established: list[dict[str, object]] = []
    unattributed = 0

    for conn in connections:
        state = conn.status or "NONE"
        by_state[state] = by_state.get(state, 0) + 1
        pid = conn.pid or 0
        if not conn.pid:
            unattributed += 1
        slot = by_pid.setdefault(pid, {"pid": pid, "established": 0, "listening": 0,
                                       "other": 0})
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
                names[pid] = (_name_of(pid), None)
            name, unit = names.get(pid, (None, None))
            established.append({
                "pid": pid, "name": name, "unit": unit, "local": local,
                "remote": remote,
                # Not readable without ESTATS: None, never 0.
                "tx_queue": None, "rx_queue": None, "rtt_ms": None,
                "rtt_min_ms": None, "retrans": None,
                "send_bytes_sec": None, "recv_bytes_sec": None,
            })
        else:
            slot["other"] = int(slot["other"]) + 1  # type: ignore[arg-type]

    listeners.sort(key=lambda entry: str(entry["local"]))
    return {
        "available": True,
        "reason": None,
        "total": len(connections),
        "by_state": by_state,
        "by_pid": by_pid,
        "unattributed": unattributed,
        "unattributed_note": (
            f"{unattributed} socket(s) have no owning process in the TCP/UDP "
            "tables (closing, or owned by the kernel)" if unattributed else None),
        "listeners": listeners[:200],
        "established": established[:400],
        "per_process": _per_process(established, names),
        "tcp_info": False,
        "tcp_info_reason": _TCP_INFO_REASON,
    }


def _no_sockets(reason: str) -> dict[str, object]:
    return {"available": False, "reason": reason, "total": 0, "by_state": {},
            "by_pid": {}, "unattributed": 0, "unattributed_note": None,
            "listeners": [], "established": [], "per_process": [],
            "tcp_info": False, "tcp_info_reason": _TCP_INFO_REASON}


def _name_of(pid: int) -> str | None:
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None


def _tuple(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return [str(value)]



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

