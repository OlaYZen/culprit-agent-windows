"""The port map -- what is listening, and the one place to kill what holds a port.

Every other collector answers "what is this machine doing". This one answers a
question an operator asks constantly and no utilisation number can: *what is
listening on port N, and let me stop it.* It is `netstat -abno` with the
chores netstat leaves you to do by hand -- name the service behind each
socket, then go find and end that process -- folded into one row with a
button.

Sockets come from psutil, which on Windows reads the extended TCP/UDP tables
(GetExtendedTcpTable / GetExtendedUdpTable): every socket carries its owning
PID without elevation, so the Linux agent's "unattributed, needs
CAP_SYS_PTRACE" case does not arise here. Service attribution comes from the
SCM's pid map (a svchost row names what it hosts) threaded in from the
services collector.

**Killing a port is killing the process(es) bound to it**, so the action reuses
`processes.terminate` untouched: the critical-process guards (csrss, lsass,
services.exe, ...) and the remote CommandBroker relay both apply with no new
code.

UDP has no LISTEN state, so a "listener" there is any bound UDP socket with no
peer -- that is what makes 53/udp (a resolver) show up beside 3389/tcp.

**Turned-away clients** -- the accept queue against the listen backlog and the
kernel's ListenOverflows counter -- are a Linux kernel interface. Windows
keeps no readable accept-queue depth per listener (`\\TCPv4\\Connection
Failures` is machine-wide and counts every failed handshake, not backlog
drops), so `backlog` is honestly unavailable and no row ever claims to be
turning clients away.
"""

from __future__ import annotations

import logging
import os
import socket
import time

import psutil

from .. import windows
from . import processes as proc_mod

log = logging.getLogger("culprit.ports")


def _is_loopback(ip: str) -> bool:
    """A bind only reachable from the machine itself. Everything else -- a
    wildcard (0.0.0.0 / ::) or a concrete interface address -- is exposed."""
    if not ip:
        return False
    low = ip.lower()
    return low.startswith("127.") or low == "::1" or low.startswith("::ffff:127.")


_BACKLOG_REASON = windows.not_capable(
    "the accept-queue depth and the ListenOverflows counter are Linux kernel "
    "interfaces; Windows exposes neither per listener")


class PortsCollector:
    def __init__(self) -> None:
        self._identities: dict[int, tuple[float, dict[str, object]]] = {}

    def sample(self, service_map: dict[str, list] | None = None,
               unit_desc: dict[str, str] | None = None) -> dict[str, object]:  # noqa: ARG002
        service_map = service_map or {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            return _unavailable(f"access denied: {exc}")
        except Exception as exc:  # noqa: BLE001
            return _unavailable(str(exc))

        listeners: list[tuple[int, str, str, str, int | None]] = []
        inbound: dict[tuple[int, str], int] = {}
        for conn in conns:
            laddr = conn.laddr
            port = getattr(laddr, "port", 0) if laddr else 0
            if not port:
                continue
            family = "IPv6" if conn.family.name == "AF_INET6" else "IPv4"
            proto = "udp" if conn.type == socket.SOCK_DGRAM else "tcp"
            ip = getattr(laddr, "ip", "") or ""
            if conn.status == psutil.CONN_LISTEN:
                listeners.append((port, proto, ip, family, conn.pid))
            elif proto == "udp" and not conn.raddr:
                listeners.append((port, proto, ip, family, conn.pid))
            elif conn.status == psutil.CONN_ESTABLISHED:
                key = (port, proto)
                inbound[key] = inbound.get(key, 0) + 1

        by_port: dict[int, dict[str, object]] = {}
        for port, proto, ip, family, pid in listeners:
            slot = by_port.setdefault(port, {
                "protocols": set(), "addresses": set(), "families": set(),
                "pids": set(), "unattributed": 0, "public": False,
            })
            slot["protocols"].add(proto)  # type: ignore[union-attr]
            if ip:
                slot["addresses"].add(ip)  # type: ignore[union-attr]
            slot["families"].add(family)  # type: ignore[union-attr]
            if not _is_loopback(ip):
                slot["public"] = True
            if pid:
                slot["pids"].add(pid)  # type: ignore[union-attr]
            else:
                slot["unattributed"] = int(slot["unattributed"]) + 1  # type: ignore[arg-type]

        now = time.monotonic()
        ports_out: list[dict[str, object]] = []
        public_count = tcp_ports = udp_ports = total_conns = total_unattr = 0
        for port in sorted(by_port):
            slot = by_port[port]
            protocols = sorted(slot["protocols"])  # type: ignore[type-var]
            conns_here = sum(inbound.get((port, p), 0) for p in protocols)
            processes = [self._identify(pid, service_map, now)
                         for pid in sorted(slot["pids"])]  # type: ignore[union-attr]
            scope = "public" if slot["public"] else "local"
            unattr = int(slot["unattributed"])
            public_count += scope == "public"
            tcp_ports += "tcp" in protocols
            udp_ports += "udp" in protocols
            total_conns += conns_here
            total_unattr += unattr
            ports_out.append({
                "port": port,
                "protocols": protocols,
                "scope": scope,
                "addresses": sorted(slot["addresses"]),  # type: ignore[type-var]
                "families": sorted(slot["families"]),  # type: ignore[type-var]
                "connections": conns_here,
                "unattributed": unattr,
                "owners": [],
                "processes": processes,
                "killable": any(p["can_kill"] for p in processes),
                "accept_queue": None,
                "turned_away": False,
            })

        # Drop identities of processes that no longer hold a port.
        live = {pid for slot in by_port.values() for pid in slot["pids"]}  # type: ignore[union-attr]
        for pid in [p for p in self._identities if p not in live]:
            del self._identities[pid]

        return {
            "available": True,
            "reason": None,
            "ports": ports_out,
            "totals": {
                "ports": len(ports_out),
                "public": public_count,
                "local": len(ports_out) - public_count,
                "tcp": tcp_ports,
                "udp": udp_ports,
                "connections": total_conns,
                "unattributed": total_unattr,
                "turned_away": 0,
            },
            "unattributed_note": (
                f"{total_unattr} listening socket(s) have no owning process in the "
                "TCP/UDP tables (a kernel-mode listener such as http.sys or SMB)"
                if total_unattr else None),
            "backlog": {
                "available": False, "reason": _BACKLOG_REASON, "interval": None,
                "totals": {}, "overflows_sec": None, "drops_sec": None,
                "syn_drops_sec": None, "syn_cookies_sec": None,
                "queues_available": False, "queues_reason": _BACKLOG_REASON,
                "somaxconn": None, "turned_away": [], "note": None,
            },
        }

    def _identify(self, pid: int, service_map: dict[str, list],
                  now: float) -> dict[str, object]:
        """Identity is resolved once per PID and kept for a minute: psutil's
        per-process calls cost milliseconds each on Windows, and a listener
        does not change its name."""
        cached = self._identities.get(pid)
        if cached and now - cached[0] < 60:
            return cached[1]
        identity = _identity(pid, service_map)
        self._identities[pid] = (now, identity)
        return identity


def _unavailable(reason: str) -> dict[str, object]:
    return {"available": False, "reason": reason, "ports": [], "totals": {},
            "unattributed_note": None,
            "backlog": {"available": False, "reason": _BACKLOG_REASON}}


def _identity(pid: int, service_map: dict[str, list]) -> dict[str, object]:
    """Name, command line, owner and hosted services for one listening PID.

    `can_act` supplies the exact same kill-eligibility verdict, and reason,
    that the terminate endpoint will enforce, so the button's enabled state
    never disagrees with what pressing it would do.
    """
    name = f"pid-{pid}"
    exe = cmdline = username = None
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            exe = proc_mod._try(proc.exe)
            cmdline = proc_mod._join(proc_mod._try(proc.cmdline))
            username = proc_mod._short_user(proc_mod._try(proc.username))
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        pass
    units = (service_map.get(str(pid)) or [])[:4]
    can_kill, kill_reason = proc_mod.can_act(pid, "end")
    return {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": cmdline or None,
        "username": username,
        # The hosted Windows services (display names), where Linux lists the
        # systemd unit's description; `unit` is the first service's name.
        "units": units,
        "unit": units[0] if units else None,
        "can_kill": can_kill,
        "kill_reason": kill_reason,
        "is_self": pid == os.getpid(),
    }
