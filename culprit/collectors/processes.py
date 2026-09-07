"""The process table.

**Why this uses performance counters instead of psutil for the table.**

psutil is the obvious choice and it is the wrong one here, for a measured
reason. On Windows its per-process live metrics each cost 5-14ms *per process*,
because the backend re-enumerates the whole system per call. Profiled on the
original dev machine (443 processes):

    status()        13.4 ms/proc      5,951 ms total
    num_threads()   14.0 ms/proc      6,205 ms total
    ppid()          23.7 ms/proc     10,495 ms total
    memory_info()    5.7 ms/proc      2,518 ms total
    cpu_percent()    7.5 ms/proc      3,336 ms total
    io_counters()    6.1 ms/proc      2,678 ms total

`oneshot()` does not fix it -- the same cheap set inside `oneshot()` still took
13.5 seconds. That is O(n^2) behaviour and it makes a 2-second tick impossible.

The `\\Process V2` performance-counter object returns all of it for every
process in a single collect: **~105ms for 445 processes** with the ten counters
below. Two orders of magnitude better, and the values agree with psutil to
within 0.3% (verified against `memory_info().rss`).

Three specifics that are easy to get wrong:

1. **`PDH_FMT_NOCAP100` is mandatory.** Without it PDH clamps every percentage
   counter at 100, which silently hides the worst offenders. On that machine
   the flag is the difference between seeing `Memory Compression` at 100% and
   seeing its real 252% (it is summed across cores, so a 12-core box tops out
   at 1200%).

2. **`\\Process V2` instances are `name:pid`, which is unique.** The older
   `\\Process` object names duplicates `svchost`, `svchost#1`, ... and pywin32
   returns the array as a *dict*, so same-named processes collapse: 449 real
   processes came back as 159 rows. Any tool built on V1 is quietly missing two
   thirds of the machine.

3. **Elapsed Time replaces `create_time()`**, and the IO/fault counters are
   already per-second rates, so no manual delta bookkeeping is needed.

psutil is still used where it is genuinely cheap (`exe`, `username` at ~0.4ms
each, resolved once per process and cached for its lifetime) and for the
on-demand detail of a single process, where its cost is irrelevant.

**The shape is the Linux agent's.** Rows carry every key the dashboard reads;
the Linux-only ones (`run_delay_ms`, `major_faults_sec`, `wchan`, `stuck`,
`is_kthread`, `container`, `unit`) are None / False here, and the one thing
Windows has that Linux does not -- a window that has stopped pumping
messages, Task Manager's "Not responding" -- rides as `hung` / `hung_title`
and the state "not responding", which the Lag Doctor scores like Linux
scores D-state.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import psutil

from .. import windows
from .containers import ContainerResolver

log = logging.getLogger("culprit.processes")

# Instance names come back as "<image name>:<pid>". Image names cannot contain
# a colon on Windows, so rsplit on the last one is unambiguous.
_TOTAL_INSTANCE = "_Total"

# key -> (counter name, needs the no-cap flag)
_COUNTERS: tuple[tuple[str, str, bool], ...] = (
    ("cpu", "% Processor Time", True),
    ("working_set", "Working Set", False),
    ("working_set_private", "Working Set - Private", False),
    ("private_bytes", "Private Bytes", False),
    ("threads", "Thread Count", False),
    ("handles", "Handle Count", False),
    ("ppid", "Creating Process ID", False),
    ("io_read", "IO Read Bytes/sec", False),
    ("io_write", "IO Write Bytes/sec", False),
    ("page_faults", "Page Faults/sec", False),
    ("elapsed", "Elapsed Time", False),
)

# Pseudo-processes. Idle's "CPU time" is the absence of work, so it must never
# be counted as load or ranked as an offender.
IDLE_PIDS = {0}
SYSTEM_PIDS = {0, 4}

# Static fields resolved per process per tick. psutil costs ~0.4ms each, so the
# first tick on a 445-process machine would spend ~400ms here; budgeting spreads
# that over a few ticks and then costs nothing but new processes.
_STATIC_BUDGET = 140


@dataclass
class _Static:
    """Immutable per-process facts, resolved once and cached for its lifetime."""

    name: str
    exe: str | None = None
    username: str | None = None
    resolved: bool = False
    denied: bool = False


class ProcessCollector:
    def __init__(self, logical_cores: int | None = None) -> None:
        self.cores = logical_cores or psutil.cpu_count(logical=True) or 1
        self._own_pid = os.getpid()
        self._static: dict[int, _Static] = {}
        self._cpu_history: dict[int, list[float]] = {}
        self.last_duration_ms = 0.0
        # The Linux resolver's interface, for the sampler and the cgroups stub.
        self.containers = ContainerResolver()

        self.query = windows.PdhQuery("process")
        self.mode = "pdh"
        self.degraded_reason: str | None = None
        for key, counter, nocap in _COUNTERS:
            ok = self.query.add(
                key, rf"\Process V2(*)\{counter}",
                array=True, nocap=nocap,
                fmt="large" if key in ("working_set", "working_set_private",
                                       "private_bytes", "ppid") else "double",
            )
            if not ok and key in ("cpu", "working_set", "ppid"):
                self.mode = "psutil"
                if windows.win32pdh is None:
                    self.degraded_reason = (
                        f"{windows.missing('win32pdh')}, so the process table "
                        "falls back to psutil. It is accurate but far slower "
                        "(seconds per scan), so it samples less often.")
                else:
                    # A core counter is missing -- almost certainly a Windows
                    # build older than 1903, which has no "Process V2" object.
                    self.degraded_reason = (
                        "The 'Process V2' performance counters are not available on "
                        "this Windows build, so the process table falls back to "
                        "psutil. It is accurate but far slower, so it samples less "
                        "often.")
                break

        if self.mode == "pdh":
            # First collect enumerates ~450 instances (~550ms). Paid once, here,
            # inside the startup warm-up rather than on a live tick.
            self.query.collect()
        else:
            log.warning("%s", self.degraded_reason)
            self._fallback = _PsutilFallback(self.cores)

    # ------------------------------------------------------------------ public
    def sample(self, gpu_per_pid: dict[int, dict[str, float]] | None = None,
               limit: int = 250) -> dict[str, object]:  # noqa: ARG002
        started = time.perf_counter()
        rows = (self._scan_pdh() if self.mode == "pdh"
                else self._fallback.scan())

        gpu_per_pid = gpu_per_pid or {}
        hung = hung_window_pids()

        for row in rows:
            pid = row["pid"]
            gpu = gpu_per_pid.get(pid)
            row["gpu"] = gpu["total"] if gpu else 0.0
            row["gpu_engines"] = gpu.get("engines") if gpu else None
            row["vram"] = (gpu or {}).get("vram_dedicated") or 0
            row["vram_shared"] = (gpu or {}).get("vram_shared") or 0
            row["hung"] = pid in hung
            row["hung_title"] = hung.get(pid)
            row["state"] = _derive_state(row)

        real = [r for r in rows if r["pid"] not in IDLE_PIDS]
        denied = sum(1 for r in rows if r.get("access_denied"))
        totals = {
            "count": len(rows),
            "threads": sum(int(r["threads"] or 0) for r in real),
            "handles": sum(int(r["handles"] or 0) for r in real),
            "cpu": round(sum(float(r["cpu"]) for r in real), 1),
            "working_set": sum(int(r["working_set"] or 0) for r in real),
            "private": sum(int(r["private"] or 0) for r in real),
            "read_bytes_sec": round(sum(float(r["read_bytes_sec"] or 0) for r in real)),
            "write_bytes_sec": round(sum(float(r["write_bytes_sec"] or 0) for r in real)),
            # Windows has no D-state / kernel threads / zombies; the number
            # that plays the same role is the hung-window count.
            "d_state": None,
            "stuck": None,
            "hung": sum(1 for r in rows if r["hung"]),
            "kernel_threads": None,
            "zombies": None,
            # PDH reports IO for every process; only identity can be denied.
            "io_unreadable": 0,
            "unresolved": sum(1 for r in rows if not r.get("username")),
            "identity_denied": denied,
            "containers": None,
            "container_processes": None,
        }
        by_state: dict[str, int] = {}
        for row in rows:
            key = str(row["state"])
            by_state[key] = by_state.get(key, 0) + 1

        self.last_duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            "processes": rows,
            "totals": totals,
            "by_state": by_state,
            "hung_pids": sorted(hung),
            "sample_ms": self.last_duration_ms,
            "cores": self.cores,
            "mode": self.mode,
            "degraded_reason": self.degraded_reason,
            "io_note": (
                f"exe path and user of {denied} process(es) are not readable at "
                "this privilege level (other users' processes; run the agent "
                "elevated). Their CPU, memory and I/O still come from the "
                "performance counters." if denied else None),
            "container_note": self.containers.note(),
        }

    # -------------------------------------------------------------- PDH scan
    def _scan_pdh(self) -> list[dict[str, object]]:
        self.query.collect()
        arrays = {key: self.query.array(key) for key, _, _ in _COUNTERS}
        cpu_array = arrays.get("cpu") or {}

        now = time.time()
        rows: list[dict[str, object]] = []
        live_pids: set[int] = set()
        budget = _STATIC_BUDGET

        for instance in cpu_array:
            if instance == _TOTAL_INSTANCE:
                continue
            name, _, pid_text = instance.rpartition(":")
            if not name or not pid_text.isdigit():
                # Unexpected instance shape; skip rather than guess.
                continue
            pid = int(pid_text)
            live_pids.add(pid)

            def value(key: str, default: float = 0.0) -> float:
                got = arrays.get(key, {}).get(instance)
                return float(got) if isinstance(got, (int, float)) else default

            cpu_raw = value("cpu")
            static = self._static.get(pid)
            if static is None:
                static = _Static(name=name)
                self._static[pid] = static
            if not static.resolved and budget > 0:
                budget -= 1
                self._resolve_static(pid, static)

            history = self._cpu_history.setdefault(pid, [])
            history.append(cpu_raw)
            if len(history) > 30:
                del history[:-30]
            cpu_avg_raw = sum(history) / len(history)

            elapsed = value("elapsed")
            read = value("io_read")
            write = value("io_write")

            rows.append(_row(
                pid=pid, ppid=int(value("ppid")), name=name, exe=static.exe,
                username=static.username, threads=int(value("threads")),
                handles=int(value("handles")), cpu_raw=cpu_raw,
                cpu_avg_raw=cpu_avg_raw, cores=self.cores,
                working_set=int(value("working_set")),
                working_set_private=int(value("working_set_private")),
                private=int(value("private_bytes")),
                page_faults_sec=round(value("page_faults"), 1),
                read=read, write=write,
                elapsed=elapsed, create_time=(now - elapsed) if elapsed > 0 else None,
                own_pid=self._own_pid, access_denied=static.denied))

        # Forget exited processes so the caches cannot grow without bound on a
        # machine that churns short-lived processes.
        for pid in set(self._static) - live_pids:
            self._static.pop(pid, None)
            self._cpu_history.pop(pid, None)

        return rows

    def _resolve_static(self, pid: int, static: _Static) -> None:
        """Fill in exe and username. ~0.4ms each; done once per process."""
        if pid in SYSTEM_PIDS:
            static.username = "NT AUTHORITY\\SYSTEM"
            static.resolved = True
            return
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                try:
                    static.exe = proc.exe() or None
                except (psutil.AccessDenied, OSError):
                    static.denied = True
                try:
                    static.username = _short_user(proc.username())
                except (psutil.AccessDenied, OSError):
                    static.denied = True
        except psutil.NoSuchProcess:
            pass
        except Exception as exc:  # noqa: BLE001
            log.debug("static resolve for pid %s failed: %s", pid, exc)
        static.resolved = True

    # ------------------------------------------------------------------ detail
    def detail(self, pid: int,
               extras: frozenset[str] = frozenset()) -> dict[str, object] | None:
        """Everything about one process, collected on demand.

        psutil is the right tool here: the calls that cost 14ms each across 445
        processes cost 14ms total for one, and it reaches things no performance
        counter exposes -- command line, open handles, sockets, per-thread times.

        Two of those calls are not cheap even for a single process, measured on
        the original machine: `open_files()` costs 265ms and `threads()` 74ms,
        and both scale with how many handles the target holds -- an editor or a
        browser can push `open_files()` into whole seconds. They are therefore
        opt-in via `extras`, so the detail panel opens immediately and those two
        sections load only when the reader actually expands them.
        """
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                mem = proc.memory_info()
                cpu_times = proc.cpu_times()
                detail: dict[str, object] = {
                    "pid": pid,
                    "name": proc.name(),
                    "exe": _try(proc.exe),
                    "cmdline": _join(_try(proc.cmdline)),
                    "cwd": _try(proc.cwd),
                    "username": _short_user(_try(proc.username)),
                    "status": _try(proc.status),
                    "ppid": _try(proc.ppid),
                    "create_time": _try(proc.create_time),
                    "num_threads": _try(proc.num_threads),
                    "num_handles": _handles(proc),
                    "priority": _priority_label(_try(proc.nice)),
                    "cpu_times": {
                        "user": round(cpu_times.user, 2),
                        "system": round(cpu_times.system, 2),
                    },
                    "memory": {
                        "working_set": mem.rss,
                        "private": getattr(mem, "private", None),
                        "shared": None,
                        "virtual": mem.vms,
                        "text": None,
                        "pss": None,
                        "swap_pss": None,
                        "peak_working_set": getattr(mem, "peak_wset", None),
                        "pagefile": getattr(mem, "pagefile", None),
                        "peak_pagefile": getattr(mem, "peak_pagefile", None),
                        "paged_pool": getattr(mem, "paged_pool", None),
                        "nonpaged_pool": getattr(mem, "nonpaged_pool", None),
                        "page_faults": getattr(mem, "num_page_faults", None),
                    },
                }
                try:
                    io = proc.io_counters()
                    detail["io"] = {
                        "read_bytes": io.read_bytes, "write_bytes": io.write_bytes,
                        "read_count": io.read_count, "write_count": io.write_count,
                        "read_chars": None, "write_chars": None,
                        "other_bytes": getattr(io, "other_bytes", None),
                    }
                except (psutil.AccessDenied, NotImplementedError):
                    detail["io"] = None

            # Linux-only facts, absent by construction rather than zero.
            detail.update({
                "run_delay_total_ms": None, "wchan": None, "cgroup": None,
                "oom_score": None, "container": None, "kernel": None,
                "stuck": False,
            })
            detail["unit"] = unit_info(pid)
            # Outside oneshot: each of these is its own enumeration.
            detail["parent"] = _parent_summary(proc)
            detail["children"] = _children_summary(proc)
            detail["connections"] = _connections(proc)
            detail["environ_count"] = _environ_count(proc)
            # Expensive, so only when asked for. `None` means "not requested",
            # which the UI renders as a collapsed, loadable section -- distinct
            # from `[]` meaning "requested, and there are none".
            detail["open_files"] = _open_files(proc) if "files" in extras else None
            detail["threads"] = _threads(proc) if "threads" in extras else None
            detail["extras_loaded"] = sorted(extras)

            history = self._cpu_history.get(pid)
            if history:
                detail["cpu_avg"] = round(sum(history) / len(history) / self.cores, 2)
                detail["cpu_peak"] = round(max(history) / self.cores, 2)
                detail["cpu_samples"] = len(history)
            hung = hung_window_pids()
            detail["hung"] = pid in hung
            detail["hung_title"] = hung.get(pid)
            detail["throttle"] = _job_state(pid)
            return detail
        except psutil.NoSuchProcess:
            return None
        except psutil.AccessDenied as exc:
            return {"pid": pid, "access_denied": True, "reason": str(exc)}

    def close(self) -> None:
        self.query.close()


def _row(*, pid: int, ppid: int, name: str, exe: str | None, username: str | None,
         threads: int, handles: int, cpu_raw: float, cpu_avg_raw: float, cores: int,
         working_set: int, working_set_private: int, private: int,
         page_faults_sec: float, read: float, write: float, elapsed: float,
         create_time: float | None, own_pid: int, access_denied: bool) -> dict[str, object]:
    """One process row in the Linux agent's shape."""
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": exe,
        "username": username,
        "threads": threads,
        # Win32 handle count -- the same column Linux fills with open file
        # descriptors. Same idea (kernel objects held), different unit.
        "handles": handles,
        # Percent of the whole machine, matching Task Manager.
        "cpu": round(cpu_raw / cores, 2),
        "cpu_avg": round(cpu_avg_raw / cores, 2),
        # Per-core-sum: above 100 means genuinely multi-threaded.
        "cpu_raw": round(cpu_raw, 1),
        "working_set": working_set,
        "working_set_private": working_set_private,
        # Private Bytes: committed private virtual memory, the number that
        # counts against the commit limit (Linux reports anonymous RSS here).
        "private": private,
        "page_faults_sec": page_faults_sec,
        # PDH has no per-process *hard* fault rate; ETW would. None, not 0.
        "major_faults_sec": None,
        "run_delay_ms": None,
        "read_bytes_sec": round(read),
        "write_bytes_sec": round(write),
        "io_bytes_sec": round(read + write),
        "io_unreadable": False,
        "elapsed_seconds": round(elapsed, 1),
        "create_time": create_time,
        "raw_state": None,
        "stuck": False,
        "wchan": None,
        "is_kthread": False,
        "is_system": pid in SYSTEM_PIDS,
        "is_idle": pid in IDLE_PIDS,
        "is_self": pid == own_pid,
        "access_denied": access_denied,
        "container": None,
        "unit": None,
        "kernel": None,
    }


class _PsutilFallback:
    """Slow-but-correct path for Windows builds without `\\Process V2`.

    Kept deliberately simple. It is accurate; it is just expensive (seconds, not
    milliseconds), which is why the sampler raises the process interval when this
    path is active and the UI shows a degraded notice.
    """

    def __init__(self, cores: int) -> None:
        self.cores = cores
        self._procs: dict[int, psutil.Process] = {}
        self._cpu_history: dict[int, list[float]] = {}
        self._prev_io: dict[int, tuple[float, int, int]] = {}
        self._own_pid = os.getpid()

    def scan(self) -> list[dict[str, object]]:
        now = time.time()
        rows: list[dict[str, object]] = []
        live = set(psutil.pids())
        for pid in list(self._procs):
            if pid not in live:
                self._procs.pop(pid, None)
                self._cpu_history.pop(pid, None)
                self._prev_io.pop(pid, None)
        for pid in live:
            proc = self._procs.get(pid)
            try:
                if proc is None:
                    proc = psutil.Process(pid)
                    self._procs[pid] = proc
                    proc.cpu_percent()
                with proc.oneshot():
                    cpu_raw = proc.cpu_percent()
                    mem = proc.memory_info()
                    name = proc.name()
                    ppid = proc.ppid()
                    exe = _try(proc.exe)
                    username = _short_user(_try(proc.username))
                    threads = proc.num_threads()
                    handles = _handles(proc) or 0
                    create_time = proc.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

            history = self._cpu_history.setdefault(pid, [])
            history.append(cpu_raw)
            if len(history) > 30:
                del history[:-30]
            cpu_avg_raw = sum(history) / len(history)

            read = write = 0.0
            try:
                io = proc.io_counters()
                previous = self._prev_io.get(pid)
                if previous:
                    dt = now - previous[0]
                    if dt > 0:
                        read = max(0.0, (io.read_bytes - previous[1]) / dt)
                        write = max(0.0, (io.write_bytes - previous[2]) / dt)
                self._prev_io[pid] = (now, io.read_bytes, io.write_bytes)
            except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
                pass

            elapsed = max(0.0, now - float(create_time or now))
            rows.append(_row(
                pid=pid, ppid=ppid, name=name, exe=exe, username=username,
                threads=threads, handles=int(handles), cpu_raw=cpu_raw,
                cpu_avg_raw=cpu_avg_raw, cores=self.cores, working_set=mem.rss,
                working_set_private=getattr(mem, "private", 0) or 0,
                private=getattr(mem, "private", 0) or 0,
                # psutil has no per-process fault *rate* here; cumulative only.
                page_faults_sec=0.0, read=read, write=write, elapsed=elapsed,
                create_time=create_time, own_pid=self._own_pid,
                access_denied=exe is None and username is None))
        return rows


# ----------------------------------------------------------------- hung windows
_hung_cache: tuple[float, dict[int, str]] = (0.0, {})


def hung_window_pids(max_age: float = 1.0) -> dict[int, str]:
    """PIDs owning a top-level window that has stopped pumping messages.

    This is Task Manager's "(Not responding)", and it is the most direct answer
    to "what is lagging?" that exists: a process blocked on a network share sits
    at 0% CPU with a completely frozen UI, so no resource counter would ever
    flag it. Costs ~6ms for ~30 visible windows, cached for a second because both
    the process tick and the detail endpoint ask for it. Empty under a
    non-interactive account (a scheduled task as SYSTEM sees no desktop
    windows) -- the payload's `hung_reason` says so.
    """
    global _hung_cache
    now = time.monotonic()
    if now - _hung_cache[0] < max_age:
        return _hung_cache[1]

    gui, process = windows.win32gui, windows.win32process
    if gui is None or process is None:
        return {}

    hung: dict[int, str] = {}

    def visit(hwnd: int, _ctx: object) -> bool:
        try:
            if not gui.IsWindowVisible(hwnd):
                return True
            if not gui.IsHungAppWindow(hwnd):
                return True
            pid = process.GetWindowThreadProcessId(hwnd)[1]
            hung.setdefault(pid, gui.GetWindowText(hwnd) or "")
        except Exception:  # noqa: BLE001 -- a window can vanish mid-walk
            pass
        return True

    try:
        gui.EnumWindows(visit, None)
    except Exception as exc:  # noqa: BLE001
        log.debug("EnumWindows failed: %s", exc)
    _hung_cache = (now, hung)
    return hung


def hung_reason() -> str | None:
    """Why hung-window detection may be blind, for the payload."""
    if windows.win32gui is None:
        return windows.missing("win32gui")
    if os.environ.get("CULPRIT_AGENT_TASK") and windows.is_elevated():
        return ("running as a scheduled task without a desktop: windows of "
                "interactive sessions are not visible to it, so 'not responding' "
                "cannot be detected")
    return None


def _derive_state(row: dict[str, object]) -> str:
    """A state that is actually informative.

    psutil's `status()` reports "running" for essentially every Windows process
    and costs 13ms each to obtain, so it is not worth collecting for the table.
    These states are free and say something real. Identity being unreadable
    says nothing about activity -- the performance counters still report CPU,
    memory and I/O for every process -- so it is carried separately in
    `access_denied` and shown as an unresolved user instead.
    """
    if row.get("hung"):
        return "not responding"
    if float(row.get("cpu_avg") or 0) < 0.05 and float(row.get("io_bytes_sec") or 0) < 1:
        return "idle"
    return "active"


# ---------------------------------------------------------------------- actions
CRITICAL_NAMES = {
    "system", "system idle process", "idle", "registry", "memory compression",
    "csrss", "csrss.exe", "wininit", "wininit.exe", "winlogon", "winlogon.exe",
    "services", "services.exe", "lsass", "lsass.exe", "smss", "smss.exe",
    "dwm", "dwm.exe", "fontdrvhost", "fontdrvhost.exe", "sihost", "sihost.exe",
    "ntoskrnl.exe", "lsaiso", "lsaiso.exe", "secure system", "explorer",
    "explorer.exe",
}


def can_act(pid: int, action: str = "act on") -> tuple[bool, str]:
    """Refuse actions that would take the machine down or kill this agent.

    `action` only shapes the wording. It exists because the same guard backs
    terminate, priority and throttle, and a refusal that said "ending it would
    sign you out" in response to a priority change described something the
    caller had not asked for.
    """
    if pid in SYSTEM_PIDS:
        return False, "PID 0 and 4 are kernel pseudo-processes, not real processes"
    if pid == os.getpid():
        return False, "that is Culprit itself"
    try:
        name = psutil.Process(pid).name().lower()
    except psutil.NoSuchProcess:
        return False, "process no longer exists"
    except psutil.AccessDenied:
        return False, "access denied"
    if name in CRITICAL_NAMES or name.removesuffix(".exe") in CRITICAL_NAMES:
        return False, (f"{name} is a critical Windows process, so Culprit will not "
                       f"{action} it")
    return True, ""


def terminate(pid: int, force: bool = False) -> dict[str, object]:
    allowed, reason = can_act(pid, "end")
    if not allowed:
        return {"ok": False, "reason": reason}
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        # Windows has no SIGTERM: psutil's terminate() and kill() are both
        # TerminateProcess. `force` is honoured for the API's sake and the
        # answer says what actually happened.
        if force:
            proc.kill()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=3)
            return {"ok": True, "pid": pid, "name": name, "exited": True}
        except psutil.TimeoutExpired:
            return {"ok": True, "pid": pid, "name": name, "exited": False,
                    "note": "TerminateProcess was called, but the process has not "
                            "exited yet (it may be blocked in the kernel)."}
    except psutil.NoSuchProcess:
        return {"ok": True, "pid": pid, "exited": True, "note": "already gone"}
    except psutil.AccessDenied:
        return {"ok": False,
                "reason": "Access denied -- the process runs as another user or is "
                          "protected. Running the agent elevated would allow it."}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": str(exc)}


# The five level names the host relays are the Linux agent's (nice-derived);
# here they map onto Windows priority classes. REALTIME is deliberately not
# offered: it outranks input and audio threads and can leave a machine
# unusable until it is rebooted.
_PRIORITIES = {
    "idle": getattr(psutil, "IDLE_PRIORITY_CLASS", 0x40),
    "below_normal": getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", 0x4000),
    "normal": getattr(psutil, "NORMAL_PRIORITY_CLASS", 0x20),
    "above_normal": getattr(psutil, "ABOVE_NORMAL_PRIORITY_CLASS", 0x8000),
    "high": getattr(psutil, "HIGH_PRIORITY_CLASS", 0x80),
}

PRIORITY_LABELS = {int(v): k for k, v in _PRIORITIES.items()}
PRIORITY_LABELS[int(getattr(psutil, "REALTIME_PRIORITY_CLASS", 0x100))] = "realtime"


def set_priority(pid: int, level: str) -> dict[str, object]:
    """Lower (or raise) a process's priority class.

    Dropping a runaway build to below_normal is the genuinely useful direction,
    and it is reversible.
    """
    if level not in _PRIORITIES:
        return {"ok": False,
                "reason": f"unknown priority {level!r}; expected one of "
                          f"{', '.join(_PRIORITIES)}"}
    allowed, reason = can_act(pid, "change the priority of")
    if not allowed:
        return {"ok": False, "reason": reason}
    try:
        proc = psutil.Process(pid)
        previous = _priority_label(proc.nice())
        proc.nice(_PRIORITIES[level])
        return {"ok": True, "pid": pid, "name": proc.name(),
                "priority": level, "previous": previous}
    except psutil.NoSuchProcess:
        return {"ok": False, "reason": "process no longer exists"}
    except psutil.AccessDenied:
        return {"ok": False, "reason": "Access denied -- run the agent elevated."}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": str(exc)}


# ------------------------------------------------------------------- throttle
# Throttle levels: the same names the Linux agent takes (a cgroup CPUQuota
# there). Here the cap is a Job Object with CPU rate control -- the kernel
# scheduler enforces it, it applies to the process and everything it spawns
# afterwards, and it is reversible. IO weight has no Windows equivalent
# (Windows has IO priority per handle, not a share), so only CPU is capped.
_THROTTLE_LEVELS = {"half": 50, "quarter": 25}
# pid -> (job handle, create_time): the handle must stay open for the rate
# control to keep applying, and it is dropped when the process is gone.
_jobs: dict[int, tuple[object, float]] = {}
# Processes the Windows session cannot survive without, beyond CRITICAL_NAMES.
_UNTHROTTLEABLE = {"svchost", "svchost.exe", "audiodg", "audiodg.exe"}


def unit_info(pid: int) -> dict[str, object] | None:
    """What throttling would act on: on Linux the process's systemd unit;
    on Windows the process itself (and its future children) through a Job
    Object. Returns the Linux shape so the dialog can say what it will do."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        create_time = proc.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    job = _job_state(pid, create_time)
    return {
        "name": name,
        "manager": "job",
        "cgroup": None,
        "process_count": 1 + len(_try(proc.children) or []),
        "cpu_quota_pct": job.get("cpu_quota_pct") if job else None,
        "io_weight": None,
        "io_controller": False,
        "throttled": bool(job and job.get("cpu_quota_pct") is not None),
        "container": False,
    }


def _job_state(pid: int, create_time: float | None = None) -> dict[str, object] | None:
    entry = _jobs.get(pid)
    if entry is None:
        return None
    handle, born = entry
    if create_time is not None and abs(born - create_time) > 1.0:
        # The pid was reused: the job we hold belongs to a dead process.
        _close_job(pid)
        return None
    return {"cpu_quota_pct": getattr(handle, "_culprit_rate", None), "job": True}


def _close_job(pid: int) -> None:
    entry = _jobs.pop(pid, None)
    if entry and windows.win32api is not None:
        try:
            windows.win32api.CloseHandle(entry[0])
        except Exception:  # noqa: BLE001
            pass


def throttle(pid: int, level: str) -> dict[str, object]:
    """Cap a process's CPU share with a Job Object, or release the cap.

    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP makes the scheduler stop running the
    job's threads once they have used their share of each interval, which is
    what "half" and "quarter" mean here: a share of the whole machine, like
    the Linux CPUQuota scaled by core count. A process already inside another
    job (an app container, a Docker-launched process) can still be assigned on
    Windows 8+ through nested jobs; older builds refuse, and the reason is
    named. `release` sets the rate control off and closes the job -- the
    process stays in the (now empty) job until it exits, which changes
    nothing else about it.
    """
    if level not in _THROTTLE_LEVELS and level != "release":
        return {"ok": False,
                "reason": f"unknown throttle level {level!r}; expected half, quarter or release"}
    allowed, reason = can_act(pid, "throttle")
    if not allowed:
        return {"ok": False, "reason": reason}
    job_mod = windows.win32job
    if job_mod is None:
        return {"ok": False, "reason": windows.missing("win32job")}
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        create_time = proc.create_time()
    except psutil.NoSuchProcess:
        return {"ok": False, "reason": "process no longer exists"}
    except psutil.AccessDenied:
        return {"ok": False, "reason": "Access denied -- run the agent elevated."}
    if name.lower() in _UNTHROTTLEABLE:
        return {"ok": False, "reason": f"{name} hosts system services; throttling it "
                                       "throttles Windows itself"}
    before = unit_info(pid)
    try:
        if level == "release":
            entry = _jobs.get(pid)
            if entry is None:
                return {"ok": False, "reason": "this process is not throttled by Culprit"}
            info = job_mod.QueryInformationJobObject(
                entry[0], job_mod.JobObjectCpuRateControlInformation)
            info["ControlFlags"] = 0
            job_mod.SetInformationJobObject(
                entry[0], job_mod.JobObjectCpuRateControlInformation, info)
            _close_job(pid)
            note = ("The CPU cap was removed. The process stays in the empty job "
                    "object until it exits, which changes nothing else.")
        else:
            rate = _THROTTLE_LEVELS[level]
            entry = _jobs.get(pid)
            if entry is None:
                job = job_mod.CreateJobObject(None, f"culprit-throttle-{pid}")
                handle = windows.win32api.OpenProcess(  # type: ignore[union-attr]
                    windows.win32con.PROCESS_SET_QUOTA | windows.win32con.PROCESS_TERMINATE,  # type: ignore[union-attr]
                    False, pid)
                try:
                    job_mod.AssignProcessToJobObject(job, handle)
                finally:
                    windows.win32api.CloseHandle(handle)  # type: ignore[union-attr]
                _jobs[pid] = (job, create_time)
            else:
                job = entry[0]
            info = job_mod.QueryInformationJobObject(
                job, job_mod.JobObjectCpuRateControlInformation)
            info["ControlFlags"] = (job_mod.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                                    | job_mod.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP)
            # CpuRate is in hundredths of a percent of the whole machine.
            info["CpuRate"] = rate * 100
            job_mod.SetInformationJobObject(
                job, job_mod.JobObjectCpuRateControlInformation, info)
            setattr(job, "_culprit_rate", float(rate))
            note = (f"Capped at {rate}% of the machine's CPU through a Job Object "
                    "(hard cap). Applies to this process and anything it starts "
                    "from now on; disk IO cannot be weighted on Windows.")
    except Exception as exc:  # noqa: BLE001
        text = windows.short_error(exc)
        if "denied" in text.lower():
            return {"ok": False, "reason": "Access denied -- assigning another user's "
                                           "process to a job needs the agent elevated."}
        return {"ok": False, "reason": f"job object: {text}"}
    return {
        "ok": True, "pid": pid, "name": name, "unit": name, "level": level,
        "manager": "job", "before": before, "after": unit_info(pid),
        "process_count": (before or {}).get("process_count"),
        "runtime_only": True, "note": note,
    }


def truncate_deleted(pid: int, path: str) -> dict[str, object]:  # noqa: ARG001
    """Linux frees a deleted-but-open file through /proc/<pid>/fd. Windows
    refuses to delete an open file in the first place, so the situation this
    verb fixes cannot arise -- there is nothing to truncate."""
    return {"ok": False, "reason": windows.not_capable(
        "a file open by a process cannot be deleted on Windows, so no space is "
        "ever held by a deleted file; free the space by closing or ending the "
        "process that holds it")}


# ---------------------------------------------------------------------- helpers
def _handles(proc: psutil.Process) -> int | None:
    """psutil exposes num_handles only on Windows; elsewhere it is absent."""
    getter = getattr(proc, "num_handles", None)
    return _try(getter) if getter else None


def _try(fn):  # type: ignore[no-untyped-def]
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, NotImplementedError):
        return None


def _join(value: object) -> str | None:
    if not value:
        return None
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


def _short_user(username: str | None) -> str | None:
    """'HOST\\olai.boe' -> 'olai.boe', but keep NT AUTHORITY prefixes."""
    if not username:
        return None
    if "\\" in username:
        domain, _, user = username.partition("\\")
        if domain.upper() in ("NT AUTHORITY", "NT SERVICE", "WINDOW MANAGER",
                              "NT VIRTUAL MACHINE", "FONT DRIVER HOST"):
            return username
        return user
    return username


def _priority_label(value: object) -> str | None:
    if value is None:
        return None
    try:
        return PRIORITY_LABELS.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def _parent_summary(proc: psutil.Process) -> dict[str, object] | None:
    try:
        parent = proc.parent()
        if parent is None:
            return None
        return {"pid": parent.pid, "name": parent.name()}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _children_summary(proc: psutil.Process) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    try:
        for child in proc.children():
            try:
                out.append({"pid": child.pid, "name": child.name(),
                            "working_set": child.memory_info().rss})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                out.append({"pid": child.pid, "name": "?", "working_set": None})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return out[:60]


def _connections(proc: psutil.Process) -> list[dict[str, object]] | None:
    try:
        conns = proc.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return None
    return [
        {"status": conn.status, "local": _fmt_addr(conn.laddr),
         "remote": _fmt_addr(conn.raddr),
         "family": "IPv6" if conn.family.name == "AF_INET6" else "IPv4"}
        for conn in conns[:80]
    ]


def _open_files(proc: psutil.Process) -> list[str] | None:
    try:
        return [f.path for f in proc.open_files()[:60]]
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return None


def _threads(proc: psutil.Process) -> list[dict[str, object]] | None:
    try:
        threads = proc.threads()
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return None
    ranked = sorted(threads, key=lambda t: -(t.user_time + t.system_time))[:25]
    return [{"id": t.id, "user_time": round(t.user_time, 2),
             "system_time": round(t.system_time, 2)} for t in ranked]


def _environ_count(proc: psutil.Process) -> int | None:
    # The values can contain secrets, so only the count is reported.
    try:
        return len(proc.environ())
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError, OSError):
        return None


def _fmt_addr(addr: object) -> str | None:
    ip = getattr(addr, "ip", None)
    if ip is None:
        return None
    port = getattr(addr, "port", None)
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"
