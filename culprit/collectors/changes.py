"""What changed: the question every engineer asks first, kept as a record.

A finding says *what* is slow and *who* is doing it. The question after that
is "what changed?" -- and the answer is usually scattered across systemctl,
journalctl, apt history, `ss`, `mount` and someone's memory of a login. This
collector watches the sections the other tiers already produce and writes
down every transition it can see:

- units started, stopped, restarted or failed (with systemd's own `Result`)
- timers that fired (exact time, from the timer's own `last` stamp)
- filesystems mounted or unmounted
- ports that started or stopped listening, with the process behind them
- interfaces up/down, addresses changed, default route or VPN state changed
- containers started or stopped
- CPU quotas and memory limits set or changed on a unit (Culprit's own
  Throttle shows up here like anything else -- honesty cuts both ways)
- packages installed or upgraded (from the apt history the events tier reads)
- sessions opened (an SSH login from where)
- processes that appeared and stayed: a name not running before, or a
  newcomer that is already heavy 20 s in

Every entry is a *fact with a time*, and the Lag Doctor attaches the ones from
the minutes before a finding began as "coincides with" -- never "caused by".
Correlation is left to the reader, labelled as such, because inventing a cause
from proximity is exactly the kind of confident wrong answer this tool exists
to avoid.

Windows had the Event Log for some of this; here nothing keeps such a
timeline, so the agent keeps its own: an in-memory ring of the last few hours
(the host persists what it receives, so history survives agent restarts).
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque

_KEEP_SECONDS = 6 * 3600
_CAP = 600
_PROCESS_MIN_AGE = 20.0     # a process must live this long to count
_HEAVY_CPU = 5.0            # % (rolling average) that makes a newcomer notable
_HEAVY_RSS = 256 * 1024 ** 2
_HEAVY_IO = 1024 ** 2       # bytes/s


class ChangeLog:
    def __init__(self, boot_time: float | None = None) -> None:
        self._lock = threading.Lock()
        self._events: deque[dict[str, object]] = deque()
        self.recording_since = time.time()
        # Baselines per domain; None until first observed (no events on
        # the first observation -- a baseline is not a change).
        self._units: dict[str, tuple[str, float | None, int]] | None = None
        self._timers: dict[str, float | None] | None = None
        self._mounts: dict[str, str] | None = None
        self._ports: dict[str, str] | None = None
        self._net: dict[str, object] | None = None
        self._containers: dict[str, str] | None = None
        self._limits: dict[str, tuple[float | None, int | None]] | None = None
        self._packages: set[str] | None = None
        self._sessions: dict[str, dict] | None = None
        self._primed = False                 # first process tick seen
        self._proc_reported: set[int] = set()
        self._name_since: dict[str, float] = {}
        # name -> when it was last reported, so a burst of same-named
        # siblings (a browser's helper processes) is one entry, not six.
        self._name_reported: dict[str, float] = {}
        if boot_time and time.time() - boot_time < 300:
            self._add(boot_time, "boot", "system", "System booted",
                      "The machine came up; everything below started after this.",
                      severity="info", subject="boot")

    # ---------------------------------------------------------------- output
    def snapshot(self) -> dict[str, object]:
        with self._lock:
            self._trim()
            events = list(self._events)
        events.reverse()
        return {
            "available": True,
            "reason": None,
            "recording_since": self.recording_since,
            "count": len(events),
            "events": events,
        }

    def around(self, ts: float, before: float = 600.0, after: float = 10.0,
               limit: int = 6) -> list[dict[str, object]]:
        """Changes in the window before (and just after) a moment, newest
        first -- what a finding attaches as 'coincides with'."""
        low, high = ts - before, ts + after
        with self._lock:
            hits = [e for e in self._events if low <= float(e["ts"]) <= high]
        hits.sort(key=lambda e: -float(e["ts"]))
        out = []
        for event in hits[:limit]:
            entry = dict(event)
            entry["offset_seconds"] = round(float(event["ts"]) - ts)
            out.append(entry)
        return out

    # ------------------------------------------------------------- observers
    def observe_services(self, payload: dict | None) -> None:
        if not payload or not payload.get("available"):
            return
        now = time.time()
        current: dict[str, tuple[str, float | None, int]] = {}
        for unit in payload.get("services") or []:
            name = str(unit.get("name") or "")
            if not name:
                continue
            key = f"{unit.get('scope') or 'system'}:{name}"
            current[key] = (str(unit.get("status") or "unknown"),
                            _f(unit.get("since")), int(unit.get("restarts") or 0))
        timers: dict[str, float | None] = {
            str(t.get("unit")): _f(t.get("last"))
            for t in (payload.get("timers") or []) if t.get("unit")
        }
        with self._lock:
            if self._units is not None:
                for key, (status, since, restarts) in current.items():
                    name = key.partition(":")[2]
                    scope = key.partition(":")[0]
                    label = name if scope == "system" else f"{name} (user)"
                    old = self._units.get(key)
                    if old is None:
                        if status in ("running", "activating"):
                            self._add(since or now, "unit_started", "units",
                                      f"{label} started", None, subject=name,
                                      exact=since is not None)
                        continue
                    old_status, old_since, old_restarts = old
                    if restarts > old_restarts:
                        self._add(since or now, "unit_restarted", "units",
                                  f"{label} restarted by systemd",
                                  f"Restart {restarts} since it was started -- "
                                  "it crashed or exited and its Restart= policy "
                                  "brought it back.", severity="warn",
                                  subject=name, exact=since is not None)
                    elif status == old_status == "running" and since and old_since \
                            and since - old_since > 1.0:
                        self._add(since, "unit_restarted", "units",
                                  f"{label} restarted", None, subject=name)
                    elif status != old_status:
                        if status == "failed":
                            self._add(now, "unit_failed", "units", f"{label} failed",
                                      "systemd marked the unit failed.",
                                      severity="warn", subject=name, exact=False)
                        elif status in ("running", "activating"):
                            self._add(since or now, "unit_started", "units",
                                      f"{label} started", None, subject=name,
                                      exact=since is not None)
                        elif old_status in ("running", "activating") \
                                and status in ("stopped", "exited", "deactivating"):
                            self._add(now, "unit_stopped", "units", f"{label} stopped",
                                      None, subject=name, exact=False)
                for key in self._units:
                    if key not in current:
                        name = key.partition(":")[2]
                        self._add(now, "unit_gone", "units", f"{name} is gone",
                                  "The unit no longer exists (a transient unit "
                                  "finished, or a package was removed).",
                                  subject=name, exact=False)
            self._units = current
            if self._timers is not None:
                for unit, last in timers.items():
                    old = self._timers.get(unit)
                    if last and (old is None or last > old + 0.5):
                        activates = next((t.get("activates") for t in
                                          (payload.get("timers") or [])
                                          if t.get("unit") == unit), None)
                        self._add(last, "timer_fired", "timers", f"{unit} fired",
                                  f"Started {activates}." if activates else None,
                                  subject=str(activates or unit))
            self._timers = timers

    def observe_volumes(self, payload: dict | None) -> None:
        if not payload:
            return
        now = time.time()
        current = {str(v.get("mountpoint")): str(v.get("fstype") or "?")
                   for v in (payload.get("volumes") or []) if v.get("mountpoint")}
        with self._lock:
            if self._mounts is not None:
                for mount, fstype in current.items():
                    if mount not in self._mounts:
                        self._add(now, "mounted", "mounts", f"{mount} mounted ({fstype})",
                                  None, subject=mount, exact=False)
                for mount, fstype in self._mounts.items():
                    if mount not in current:
                        self._add(now, "unmounted", "mounts", f"{mount} unmounted ({fstype})",
                                  None, subject=mount, exact=False)
            self._mounts = current

    def observe_ports(self, payload: dict | None) -> None:
        if not payload or not payload.get("available"):
            return
        now = time.time()
        current: dict[str, str] = {}
        for port in payload.get("ports") or []:
            number = port.get("port")
            if number is None:
                continue
            protos = "/".join(str(p) for p in (port.get("protocols") or []))
            procs = port.get("processes") or []
            first = procs[0] if procs and isinstance(procs[0], dict) else {}
            who = (first.get("name") or (first.get("units") or [None])[0]
                   or (port.get("owners") or [None])[0])
            current[f"{number}/{protos}"] = str(who or "?")
        with self._lock:
            if self._ports is not None:
                for key, who in current.items():
                    if key not in self._ports:
                        self._add(now, "port_opened", "ports",
                                  f"{who} started listening on :{key}", None,
                                  subject=who, exact=False)
                for key, who in self._ports.items():
                    if key not in current:
                        self._add(now, "port_closed", "ports",
                                  f":{key} stopped listening ({who})", None,
                                  subject=who, exact=False)
            self._ports = current

    def observe_network(self, payload: dict | None) -> None:
        if not payload:
            return
        now = time.time()
        adapters: dict[str, tuple[str, tuple[str, ...]]] = {}
        default = None
        for adapter in payload.get("adapters") or []:
            name = str(adapter.get("description") or "")
            if not name:
                continue
            ips = tuple(sorted(str(ip) for ip in (adapter.get("ip_addresses") or [])
                               if not str(ip).startswith("fe80")))
            adapters[name] = (str(adapter.get("operstate") or "?"), ips)
            if adapter.get("default_route"):
                default = name
        vpn = payload.get("vpn") or {}
        vpn_on = bool(vpn.get("active"))
        wan = (payload.get("wan_ip") or {}).get("ip") if isinstance(payload.get("wan_ip"), dict) else None
        current = {"adapters": adapters, "default": default, "vpn": vpn_on, "wan": wan}
        with self._lock:
            old = self._net
            if old is not None:
                old_adapters = old["adapters"]  # type: ignore[index]
                for name, (state, ips) in adapters.items():
                    prev = old_adapters.get(name)  # type: ignore[union-attr]
                    if prev is None:
                        self._add(now, "iface_added", "network", f"{name} appeared",
                                  None, subject=name, exact=False)
                    elif prev[0] != state:
                        self._add(now, "iface_state", "network", f"{name} went {state}",
                                  None, severity="warn" if state != "up" else "info",
                                  subject=name, exact=False)
                    elif prev[1] != ips:
                        self._add(now, "ip_changed", "network",
                                  f"{name} address changed",
                                  f"{', '.join(prev[1]) or 'none'} -> {', '.join(ips) or 'none'}",
                                  subject=name, exact=False)
                for name in old_adapters:  # type: ignore[union-attr]
                    if name not in adapters:
                        self._add(now, "iface_removed", "network", f"{name} disappeared",
                                  None, severity="warn", subject=name, exact=False)
                if old["default"] != default and (old["default"] or default):
                    self._add(now, "route_changed", "network",
                              f"Default route moved to {default or 'nothing'}",
                              f"was {old['default'] or 'nothing'}",
                              severity="warn" if not default else "info",
                              subject=str(default), exact=False)
                if old["vpn"] != vpn_on:
                    self._add(now, "vpn", "network",
                              "VPN connected" if vpn_on else "VPN disconnected",
                              None, subject="vpn", exact=False)
                if old["wan"] and wan and old["wan"] != wan:
                    self._add(now, "wan_changed", "network", "Public IP changed",
                              f"{old['wan']} -> {wan}", subject="wan", exact=False)
            self._net = current

    def observe_cgroups(self, payload: dict | None) -> None:
        if not payload or not payload.get("available"):
            return
        now = time.time()
        limits: dict[str, tuple[float | None, int | None]] = {}
        for unit in payload.get("units") or []:
            cgroup = str(unit.get("cgroup") or "")
            limits[cgroup] = (unit.get("cpu_quota_pct"), unit.get("memory_max"))
        with self._lock:
            if self._limits is not None:
                for cgroup, (quota, mem_max) in limits.items():
                    old = self._limits.get(cgroup)
                    if old is None:
                        continue
                    unit = cgroup.rsplit("/", 1)[-1]
                    if old[0] != quota:
                        self._add(now, "quota_changed", "limits",
                                  f"CPU quota on {unit} changed",
                                  f"{_quota_text(old[0])} -> {_quota_text(quota)}",
                                  severity="warn", subject=unit, exact=False)
                    if old[1] != mem_max:
                        self._add(now, "memlimit_changed", "limits",
                                  f"Memory limit on {unit} changed",
                                  f"{_bytes_text(old[1])} -> {_bytes_text(mem_max)}",
                                  severity="warn", subject=unit, exact=False)
            self._limits = limits

    def observe_events(self, payload: dict | None) -> None:
        """Package history and sessions come from the events tier (2 min)."""
        if not payload:
            return
        now = time.time()
        updates = ((payload.get("updates") or {}).get("events")) or []
        ids = {str(e.get("record_id")): e for e in updates if isinstance(e, dict)
               and e.get("record_id")}
        sessions = (payload.get("sessions") or {}).get("current") or []
        current_sessions = {str(s.get("id")): s for s in sessions
                            if isinstance(s, dict) and s.get("id")}
        with self._lock:
            if self._packages is not None:
                for record_id, event in ids.items():
                    if record_id in self._packages:
                        continue
                    ts = _f(event.get("timestamp")) or now
                    self._add(ts, "packages", "packages",
                              str(event.get("title") or "Packages changed")[:200],
                              str(event.get("detail") or "") or None,
                              subject="apt")
            self._packages = set(ids)
            if self._sessions is not None:
                for sid, session in current_sessions.items():
                    if sid in self._sessions:
                        continue
                    user = session.get("user") or "?"
                    host = session.get("remote_host")
                    via = session.get("service") or session.get("type") or "?"
                    self._add(now, "login", "logins",
                              f"{user} signed in via {via}"
                              + (f" from {host}" if host else ""),
                              None, subject=str(user), exact=False)
            self._sessions = current_sessions

    def observe_processes(self, processes: list[dict]) -> None:
        """Newcomers that stayed. Called every proc tick with the full table.

        A process counts once it has lived 20 s, and only when its *name* was
        not running before it started (a second copy of something already
        running is not a change) or when it is already heavy by then.
        """
        now = time.time()
        own = os.getpid()
        with self._lock:
            live: set[int] = set()
            live_names: set[str] = set()
            fresh: list[dict] = []
            containers: dict[str, str] = {}
            for proc in processes:
                if proc.get("is_kthread"):
                    continue
                where = proc.get("container")
                if isinstance(where, dict) and where.get("id"):
                    containers[str(where["id"])] = str(where.get("name")
                                                       or str(where["id"])[:12])
                pid = int(proc.get("pid") or 0)
                if int(proc.get("ppid") or 0) == own or proc.get("is_self"):
                    continue    # our own helpers (journalctl, systemctl) are not news
                name = str(proc.get("name"))
                elapsed = float(proc.get("elapsed_seconds") or 0)
                started = now - elapsed
                live.add(pid)
                live_names.add(name)
                # The earliest start among processes carrying this name --
                # "was this name running before this process began?"
                first = self._name_since.get(name)
                if first is None or started < first:
                    self._name_since[name] = started
                if pid in self._proc_reported or elapsed < _PROCESS_MIN_AGE:
                    continue
                self._proc_reported.add(pid)
                if not self._primed or started < self.recording_since:
                    continue    # baseline, or older than the record itself
                fresh.append(proc)
            for proc in fresh:
                pid = int(proc["pid"])
                name = str(proc.get("name"))
                started = now - float(proc.get("elapsed_seconds") or 0)
                new_name = self._name_since.get(name, started) >= started - 1.0
                heavy = (float(proc.get("cpu_avg") or 0) >= _HEAVY_CPU
                         or float(proc.get("working_set") or 0) >= _HEAVY_RSS
                         or float(proc.get("io_bytes_sec") or 0) >= _HEAVY_IO)
                if not (new_name or heavy):
                    continue
                if now - self._name_reported.get(name, 0.0) < 120.0 and not heavy:
                    continue
                self._name_reported[name] = now
                where = proc.get("container") or {}
                inside = (f" in {where.get('name')}" if isinstance(where, dict)
                          and where.get("name") else "")
                unit = proc.get("unit")
                detail = (f"pid {pid}, user {proc.get('username') or '?'}"
                          + (f", unit {unit}" if unit else "")
                          + (". Already heavy 20 s in: "
                             f"{float(proc.get('cpu_avg') or 0):.0f}% CPU, "
                             f"{float(proc.get('working_set') or 0) / 1024 ** 2:.0f} MB, "
                             f"{float(proc.get('io_bytes_sec') or 0) / 1024 ** 2:.1f} MB/s IO"
                             if heavy else ""))
                self._add(started, "process_started", "processes",
                          f"{name}{inside} started", detail, subject=name)
            # Containers come and go with their processes; the cgroup list
            # only carries the notable ones, so this is the honest source.
            if self._containers is not None:
                for cid, name in containers.items():
                    if cid not in self._containers:
                        self._add(now, "container_started", "containers",
                                  f"container {name} started", None,
                                  subject=name, exact=False)
                for cid, name in self._containers.items():
                    if cid not in containers:
                        self._add(now, "container_stopped", "containers",
                                  f"container {name} stopped", None,
                                  subject=name, exact=False)
            self._containers = containers
            self._primed = True
            self._proc_reported &= live
            for name in [n for n in self._name_since if n not in live_names]:
                del self._name_since[name]

    # --------------------------------------------------------------- private
    def _add(self, ts: float, kind: str, source: str, title: str,
             detail: str | None, severity: str = "info", subject: str = "",
             exact: bool = True) -> None:
        # Caller holds the lock (or is the constructor).
        self._events.append({
            "id": f"{ts:.3f}:{kind}:{subject}"[:200],
            "ts": float(ts),
            "kind": kind,
            "source": source,
            "title": title[:200],
            "detail": detail,
            "subject": subject[:120],
            "severity": severity,
            # False when the time is when the change was *noticed* (a slow
            # tick later), not when it happened.
            "exact": exact,
        })
        self._trim()

    def _trim(self) -> None:
        cutoff = time.time() - _KEEP_SECONDS
        while self._events and (float(self._events[0]["ts"]) < cutoff
                                or len(self._events) > _CAP):
            self._events.popleft()


def _f(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if number == number else None


def _quota_text(quota: object) -> str:
    return "none" if quota is None else f"{float(quota):.0f}% of one core"


def _bytes_text(value: object) -> str:
    if value is None:
        return "none"
    number = float(value)
    if number >= 1024 ** 3:
        return f"{number / 1024 ** 3:.1f} GB"
    return f"{number / 1024 ** 2:.0f} MB"
