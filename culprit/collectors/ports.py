"""The port map -- what is listening, and the one place to kill what holds a port.

Every other collector answers "what is this machine doing". This one answers a
question an operator asks constantly and no utilisation number can: *what is
listening on port N, and let me stop it.* It is `ss -tulnp` with the two chores
`ss` leaves you to do by hand -- resolve each socket to the service behind it,
then go find and signal that process -- folded into one row with a button.

Sockets come from psutil (which reads /proc/net/* and, for attribution, each
owner's /proc/<pid>/fd), exactly as `network.py` does, and the same permission
truth applies: a listener owned by another user shows with **no PID and is
counted, never hidden** -- attributing or killing it needs CAP_SYS_PTRACE or
root, and the payload says so. What it *can* still show is *who* owns it: the
owner uid comes from world-readable /proc/net, so such a row is named by owner
even when the process itself is out of reach. Process identity (name, cmdline, user) is read
straight from /proc for the handful of listening PIDs -- the cheap path
`processes.py` established -- and systemd unit attribution is threaded in from
the services collector's pid->unit map, so a row can name `nginx.service`, the
honest target of a `systemctl stop`.

**Killing a port is killing the process(es) bound to it**, so the action reuses
`processes.terminate` untouched: the critical-process guards (PID 1, kernel
threads, sshd/systemd/dbus/...) and the remote CommandBroker relay both apply
with no new code, and an agent kills a port with the same call the host does.

UDP has no LISTEN state, so a "listener" there is any bound UDP socket with no
peer -- that is what makes 53/udp (a resolver) show up beside 22/tcp.

**Turned-away clients.** A listener can be up, attributed and busy while the
kernel is refusing connections on its behalf: once the accept queue (the
completed handshakes the service has not yet `accept()`ed) reaches the
listen backlog, the next client is dropped or reset before the service ever
sees it, and `TcpExt.ListenOverflows` in /proc/net/netstat ticks. That is the
user-facing symptom of "the service is too slow", and it is invisible in every
utilisation number. Each TCP row therefore carries its accept queue against
its backlog (`ss -ltn`, the one place the backlog maximum is exposed; without
`ss` the current depth still comes from /proc/net/tcp and the row says the
maximum is unknown), and the payload carries the machine's overflow rate over
the sampling interval. A row is *turning clients away* when its queue is full
while overflows tick -- only a full queue can overflow, so that is the honest
join. Both are per network namespace: a container with its own stack keeps
its own counters, and they are not in here.
"""

from __future__ import annotations

import logging
import os
import pwd
import shutil
import socket
import subprocess
import time

import psutil

from .. import linux
from . import processes as proc_mod

log = logging.getLogger("culprit.ports")


def _is_loopback(ip: str) -> bool:
    """A bind only reachable from the machine itself. Everything else -- a
    wildcard (0.0.0.0 / ::) or a concrete interface address -- is exposed."""
    if not ip:
        return False
    low = ip.lower()
    return low.startswith("127.") or low == "::1" or low.startswith("::ffff:127.")


# /proc/net files carry the owner uid and inode of every socket, unlike psutil.
# TCP LISTEN is state 0A; a bound UDP socket (our "listener") is state 07.
_PROC_NET = (
    ("tcp", "IPv4", "/proc/net/tcp", "0A"),
    ("tcp", "IPv6", "/proc/net/tcp6", "0A"),
    ("udp", "IPv4", "/proc/net/udp", "07"),
    ("udp", "IPv6", "/proc/net/udp6", "07"),
)


def _proc_net_owners() -> dict[tuple[str, str, int], list[tuple[str, int, int]]]:
    """{(proto, family, port): [(inode, uid, rx_queue), ...]} for every
    listening socket.

    /proc/net/* is world-readable and names each socket's owner uid even when
    that owner's /proc/<pid>/fd is not -- so an unattributed port can still be
    named by *who* owns it. The inode lets us recover the PID via our own fd
    scan where psutil's attribution came up empty. For a TCP listener the
    rx_queue column is the accept queue's current depth (sk_ack_backlog); the
    backlog maximum is not in this file, only `ss` has it.
    """
    out: dict[tuple[str, str, int], list[tuple[str, int, int]]] = {}
    for proto, family, path, want_state in _PROC_NET:
        text = linux.read_text(path)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != want_state:
                continue
            _, _, hexport = fields[1].rpartition(":")
            try:
                port = int(hexport, 16)
                uid = int(fields[7])
                _tx, _, rx = fields[4].partition(":")
                rx_queue = int(rx, 16)
            except ValueError:
                continue
            out.setdefault((proto, family, port), []).append((fields[9], uid, rx_queue))
    return out


def _inode_to_pid() -> dict[str, int]:
    """{socket-inode: pid} from our own /proc/<pid>/fd walk.

    psutil does the same scan, but this one runs in-process and skips nothing it
    can read, so it recovers PIDs psutil sometimes leaves unattributed in a
    container. Costs one readlink per open fd; only built when a port needs it.
    """
    out: dict[str, int] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{name}/fd")
        except OSError:
            continue  # gone, or not ours to read
        pid = int(name)
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{name}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                out[target[8:-1]] = pid
    return out


_uid_cache: dict[int, str] = {}


def _uid_name(uid: int) -> str:
    if uid not in _uid_cache:
        try:
            _uid_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_cache[uid] = f"uid {uid}"
    return _uid_cache[uid]


def _unattr_note(count: int, owners: list[str]) -> str | None:
    if not count:
        return None
    who = f" (owned by {', '.join(owners)})" if owners else ""
    return (f"{count} listening socket(s){who} could not be mapped to a "
            "process ID from here -- killing them needs CAP_SYS_PTRACE or root.")


# ------------------------------------------------------- turned-away clients
# TcpExt counters (per network namespace, since boot) that each mean "a client
# was refused before the service ever saw it".
_BACKLOG_COUNTERS = {
    # accept queue full: the handshake's final ACK (or the SYN) was dropped
    "ListenOverflows": "overflows",
    # every listen-time drop; a superset of overflows (adds memory pressure,
    # a failed socket clone, ...)
    "ListenDrops": "drops",
    # SYN queue full and syncookies off: the SYN was dropped
    "TCPReqQFullDrop": "syn_drops",
    # SYN queue full, answered with a SYN cookie: the client gets in, minus
    # window scaling / SACK -- a flood, or a service too slow to accept
    "TCPReqQFullDoCookies": "syn_cookies",
}


def _netstat_tcpext() -> dict[str, int] | None:
    """The four listen-drop counters from /proc/net/netstat (~0.07 ms)."""
    text = linux.read_text("/proc/net/netstat")
    if not text:
        return None
    lines = text.splitlines()
    for i in range(0, len(lines) - 1, 2):
        keys, vals = lines[i].split(), lines[i + 1].split()
        if keys and vals and keys[0] == "TcpExt:" and vals[0] == "TcpExt:":
            row = dict(zip(keys[1:], vals[1:]))
            out: dict[str, int] = {}
            for name, short in _BACKLOG_COUNTERS.items():
                try:
                    out[short] = int(row[name])
                except (KeyError, ValueError):
                    continue
            return out or None
    return None


def _accept_queues() -> tuple[dict[int, list[tuple[int, int]]], str | None]:
    """{port: [(current, backlog_max), ...]} for every TCP listener, from
    `ss -ltnH` (~20 ms, one netlink dump filtered to listeners -- it does not
    grow with the connection count the way /proc/net/tcp does). Second value
    is the reason when it could not be read.

    `ss` is the only unprivileged place the listen backlog *maximum* is
    exposed (sk_max_ack_backlog, via inet_diag); /proc/net/tcp shows the
    current depth alone.
    """
    if not shutil.which("ss"):
        return {}, "iproute2 (`ss`) is not installed, so the listen backlog of each port is unknown"
    try:
        proc = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        return {}, f"`ss -ltn` failed: {exc}"
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return {}, f"`ss -ltn` failed: {err[0] if err else f'exit {proc.returncode}'}"
    out: dict[int, list[tuple[int, int]]] = {}
    for line in proc.stdout.splitlines():
        fields = line.split()
        # LISTEN <recv-q> <send-q> <local addr:port> <peer>
        if len(fields) < 5 or fields[0] != "LISTEN":
            continue
        _, _, port_text = fields[3].rpartition(":")
        try:
            out.setdefault(int(port_text), []).append((int(fields[1]), int(fields[2])))
        except ValueError:
            continue
    return out, None


def _queue_of(sockets: list[tuple[int, int | None]]) -> dict[str, object] | None:
    """One accept-queue figure for a port: its fullest socket (the one that
    overflows first). `max` is None when only /proc/net/tcp was readable."""
    if not sockets:
        return None
    best: tuple[int, int | None] | None = None
    best_pct = -1.0
    for current, maximum in sockets:
        pct = (100.0 * current / maximum) if maximum else -0.5 if maximum is None else 0.0
        if pct > best_pct or (pct == best_pct and best is not None and current > best[0]):
            best, best_pct = (current, maximum), pct
    current, maximum = best  # type: ignore[misc]
    return {
        "current": current,
        "max": maximum,
        "pct": round(100.0 * current / maximum, 1) if maximum else None,
    }


class PortsCollector:
    """Slow-tick listening-port map with kill-ready process attribution, and
    the accept-queue side that says whether a listener is refusing clients."""

    def __init__(self) -> None:
        # (monotonic time, counters) of the previous sample, for the rates.
        self._last_counters: tuple[float, dict[str, int]] | None = None

    def _backlog(self) -> tuple[dict[str, object], dict[int, list[tuple[int, int]]]]:
        """Machine-level listen-drop rates over the sampling interval, plus the
        per-port accept queues. Rates are None on the first sample (a counter
        needs two readings) and the payload says so."""
        now = time.monotonic()
        counters = _netstat_tcpext()
        queues, queues_reason = _accept_queues()
        somaxconn = linux.read_line("/proc/sys/net/core/somaxconn")
        payload: dict[str, object] = {
            "available": counters is not None,
            "reason": None if counters is not None else
                      "/proc/net/netstat has no TcpExt counters here (the network "
                      "namespace hides them)",
            "interval": None,
            "totals": counters or {},
            "queues_available": queues_reason is None,
            "queues_reason": queues_reason,
            "somaxconn": int(somaxconn) if somaxconn and somaxconn.isdigit() else None,
            "turned_away": [],
            "note": None,
        }
        for short in _BACKLOG_COUNTERS.values():
            payload[f"{short}_sec"] = None
        if counters is None:
            return payload, queues
        if self._last_counters is not None:
            then, previous = self._last_counters
            elapsed = now - then
            if elapsed >= 0.5:
                payload["interval"] = round(elapsed, 1)
                for short, value in counters.items():
                    delta = value - previous.get(short, value)
                    # A counter that went backwards is a namespace switch or
                    # a reset, not a negative rate.
                    payload[f"{short}_sec"] = round(max(0, delta) / elapsed, 3)
        self._last_counters = (now, counters)
        return payload, queues

    def sample(self, service_map: dict[str, list] | None = None,
               unit_desc: dict[str, str] | None = None) -> dict[str, object]:
        service_map = service_map or {}
        unit_desc = unit_desc or {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            return {"available": False, "reason": f"access denied: {exc}",
                    "ports": [], "totals": {}, "unattributed_note": None}
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "reason": str(exc),
                    "ports": [], "totals": {}, "unattributed_note": None}

        # (port, proto, ip, family, pid) for every listening socket, plus a
        # count of established inbound connections per local (port, proto) so a
        # row can show how busy a service is right now.
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
                # A bound UDP socket with no peer is a service listening.
                listeners.append((port, proto, ip, family, conn.pid))
            elif conn.status == psutil.CONN_ESTABLISHED:
                key = (port, proto)
                inbound[key] = inbound.get(key, 0) + 1

        # Owner uid of every listening socket, straight from /proc/net (world-
        # readable). This is how a socket psutil can't attribute still gets a
        # name: even when /proc/<pid>/fd is unreadable, the uid is not.
        owners = _proc_net_owners()
        inode_pid: dict[str, int] | None = None  # our own fd scan, built lazily
        backlog, queues = self._backlog()
        overflows_sec = backlog.get("overflows_sec")
        overflowing = isinstance(overflows_sec, (int, float)) and overflows_sec > 0

        by_port: dict[int, dict[str, object]] = {}
        for port, proto, ip, family, pid in listeners:
            slot = by_port.setdefault(port, {
                "protocols": set(), "addresses": set(), "families": set(),
                "pids": set(), "unattributed": 0, "public": False,
                "owner_uids": set(),
            })
            slot["protocols"].add(proto)  # type: ignore[union-attr]
            if ip:
                slot["addresses"].add(ip)  # type: ignore[union-attr]
            slot["families"].add(family)  # type: ignore[union-attr]
            if not _is_loopback(ip):
                slot["public"] = True
            if not pid:
                # psutil left it unattributed. Try our own /proc/<pid>/fd scan
                # (more permissive than psutil's in some container sandboxes),
                # then fall back to the /proc/net uid so the row is at least
                # named by owner even when no PID is reachable.
                entries = owners.get((proto, family, port)) or []
                for inode, _uid, _rx in entries:
                    if inode_pid is None:
                        inode_pid = _inode_to_pid()
                    recovered = inode_pid.get(inode)
                    if recovered:
                        pid = recovered
                        break
                if not pid:
                    for _inode, uid, _rx in entries:
                        slot["owner_uids"].add(uid)  # type: ignore[union-attr]
            if pid:
                slot["pids"].add(pid)  # type: ignore[union-attr]
            else:
                slot["unattributed"] = int(slot["unattributed"]) + 1  # type: ignore[arg-type]

        # Identity is resolved once per PID even when a process holds many ports.
        identities: dict[int, dict[str, object]] = {}

        def identify(pid: int) -> dict[str, object]:
            if pid not in identities:
                identities[pid] = _identity(pid, service_map, unit_desc)
            return identities[pid]

        ports_out: list[dict[str, object]] = []
        public_count = tcp_ports = udp_ports = total_conns = total_unattr = 0
        all_owners: set[str] = set()
        for port in sorted(by_port):
            slot = by_port[port]
            protocols = sorted(slot["protocols"])  # type: ignore[type-var]
            conns_here = sum(inbound.get((port, p), 0) for p in protocols)
            processes = [identify(pid)
                         for pid in sorted(slot["pids"])]  # type: ignore[union-attr]
            scope = "public" if slot["public"] else "local"
            unattr = int(slot["unattributed"])
            owner_names = sorted(_uid_name(uid)
                                 for uid in slot["owner_uids"])  # type: ignore[union-attr]
            all_owners.update(owner_names)

            public_count += scope == "public"
            tcp_ports += "tcp" in protocols
            udp_ports += "udp" in protocols
            total_conns += conns_here
            total_unattr += unattr

            # The accept queue of the port's fullest TCP socket. From `ss`
            # when it ran (depth *and* backlog max); otherwise the depth
            # alone from /proc/net/tcp, with the max honestly unknown.
            queue: dict[str, object] | None = None
            if "tcp" in protocols:
                sockets: list[tuple[int, int | None]] = list(queues.get(port) or [])
                if not sockets:
                    sockets = [(rx, None) for fam in ("IPv4", "IPv6")
                               for _ino, _uid, rx in owners.get(("tcp", fam, port)) or []]
                queue = _queue_of(sockets)
            # Only a full queue can overflow: a port whose queue is at its
            # backlog while the machine's overflow counter ticks is the one
            # refusing clients. Never claimed when the max is unknown.
            turned_away = bool(
                overflowing and queue and isinstance(queue.get("max"), int)
                and queue["max"] > 0 and int(queue["current"]) >= int(queue["max"]))  # type: ignore[arg-type]
            if turned_away:
                backlog["turned_away"].append(port)  # type: ignore[union-attr]

            ports_out.append({
                "port": port,
                "protocols": protocols,
                "scope": scope,
                "addresses": sorted(slot["addresses"]),  # type: ignore[type-var]
                "families": sorted(slot["families"]),  # type: ignore[type-var]
                "connections": conns_here,
                "unattributed": unattr,
                # Owner login name(s) of any socket we couldn't map to a PID --
                # so the row names *who* owns it even when the process is out of
                # reach. Empty when everything on the port is attributed.
                "owners": owner_names,
                "processes": processes,
                # A row is actionable only if at least one owner can be signalled
                # from here; the UI uses this to enable the Kill button.
                "killable": any(p["can_kill"] for p in processes),
                # Completed handshakes waiting for accept(), against the
                # listen backlog. None for UDP or when nothing could be read.
                "accept_queue": queue,
                "turned_away": turned_away,
            })

        if overflowing and not backlog["turned_away"]:
            # The kernel refused clients during the interval but no queue was
            # full at the instant we looked: a burst that has drained. Name
            # the deepest queues as the place to look, not as the verdict.
            deepest = sorted(
                (p for p in ports_out if isinstance(p.get("accept_queue"), dict)
                 and (p["accept_queue"].get("pct") or 0) > 0),  # type: ignore[union-attr]
                key=lambda p: -(p["accept_queue"].get("pct") or 0))[:3]  # type: ignore[union-attr]
            where = (", ".join(
                f":{p['port']} ({p['accept_queue']['current']} of {p['accept_queue']['max']} waiting)"  # type: ignore[index]
                for p in deepest) if deepest else "every queue was empty by then")
            backlog["note"] = (
                f"{float(overflows_sec):.1f} connection attempt(s)/s were dropped for a full "  # type: ignore[arg-type]
                f"accept queue (ListenOverflows) over the last {backlog.get('interval') or '?'}s, "
                "but no listener's queue was full at the moment of sampling -- the burst had "
                f"drained. Deepest queues at that moment: {where}.")

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
                "turned_away": len(backlog["turned_away"]),  # type: ignore[arg-type]
            },
            "unattributed_note": _unattr_note(total_unattr, sorted(all_owners)),
            "backlog": backlog,
        }


def _identity(pid: int, service_map: dict[str, list],
              unit_desc: dict[str, str]) -> dict[str, object]:
    """Name, command line, owner and hosting unit for one listening PID.

    Read straight from /proc (comm/cmdline/status) rather than through psutil --
    the same reason `processes.py` does. `can_act` supplies the exact same
    kill-eligibility verdict, and reason, that the terminate endpoint will
    enforce, so the button's enabled state never disagrees with what pressing
    it would do.
    """
    name = linux.read_line(f"/proc/{pid}/comm") or f"pid-{pid}"
    try:
        exe: str | None = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = None
    raw = linux.read_text(f"/proc/{pid}/cmdline")
    cmdline = raw.replace("\x00", " ").strip() if raw else None

    username: str | None = None
    uid_row = linux.parse_kv_file(f"/proc/{pid}/status").get("Uid", "").split()
    if uid_row:
        try:
            username = pwd.getpwuid(int(uid_row[0])).pw_name
        except (KeyError, ValueError):
            username = uid_row[0] or None

    # Prefer the unit from the process's own cgroup (reliable, no systemctl);
    # describe it via the services map when available, else show the unit name.
    # Fall back to the MainPID map for a process whose cgroup names no unit.
    unit = linux.unit_from_cgroup(pid)
    if unit:
        units = [unit_desc.get(unit) or unit]
    else:
        units = (service_map.get(str(pid)) or [])[:4]

    can_kill, kill_reason = proc_mod.can_act(pid, "end")
    return {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": cmdline or None,
        "username": username,
        "units": units,
        # The raw unit name from the cgroup (`units` carries its description),
        # so a finding can say "nginx.service" exactly.
        "unit": unit,
        "can_kill": can_kill,
        "kill_reason": kill_reason,
        "is_self": pid == os.getpid(),
    }
