"""The process table.

**Why this reads /proc directly instead of going through psutil.**

The Windows build had to abandon psutil because its per-process calls cost
5-14ms *each* there (13.5 seconds for one full pass). On Linux that O(n^2)
problem does not exist -- but it was still worth measuring before choosing, and
the measurement decided it (229 processes, this machine):

    psutil.process_iter with the needed attrs      44.8 ms
    raw /proc stat+statm for every pid              8.4 ms
    /proc/<pid>/schedstat for every pid             4.2 ms

Direct reads are ~5x cheaper *and* expose things psutil's iterator does not
surface: scheduling run delay (`schedstat`), per-process major faults
(`stat` field 12), D-state with the blocking kernel function (`wchan`), and
block-IO delay ticks (`stat` field 42). Those feed the lag score with more
direct evidence of "this process is being made to wait" than anything the
Windows build had. psutil remains the right tool for the on-demand single
process detail, where its convenience costs nothing.

Permission honesty: `/proc/<pid>/io` and `/proc/<pid>/fd` are only readable for
your own processes without CAP_SYS_PTRACE (and Yama's ptrace_scope can tighten
even that). Measured here: 8 of 229 readable. The payload counts how many
processes have unreadable IO instead of quietly showing zeros -- on a monitoring
tool the difference between 0 and unknown is the whole point.
"""

from __future__ import annotations

import logging
import os
import pwd
import signal
import stat
import subprocess
import time
from dataclasses import dataclass

import psutil

from .. import linux
from . import kernel as kernel_mod
from .containers import ContainerResolver, identify

log = logging.getLogger("culprit.processes")

_CLK_TCK = os.sysconf("SC_CLK_TCK")
_PAGE = os.sysconf("SC_PAGE_SIZE")

# /proc/<pid>/stat single-letter states -> what the reader should see.
_STATES = {
    "R": "running", "S": "sleeping", "D": "uninterruptible", "Z": "zombie",
    "T": "stopped", "t": "traced", "I": "idle-kthread", "X": "dead",
}

# PID 1 (systemd/init) is the closest thing Linux has to a pseudo-process the
# tool must never touch. Kernel threads (children of kthreadd, PID 2) are
# handled by flag rather than by list.
SYSTEM_PIDS = {1, 2}
IDLE_PIDS: set[int] = set()  # no Linux analogue of the Idle pseudo-process


@dataclass
class _Static:
    """Per-process facts resolved once and cached for the process lifetime."""

    name: str
    starttime: int                      # jiffies since boot, identity check
    exe: str | None = None
    username: str | None = None
    is_kthread: bool = False
    # (runtime, container id) when the cgroup path says the process lives in
    # a container; the name is looked up (and cached) by the resolver.
    container: tuple[str, str] | None = None
    # The systemd unit / container scope owning the process, from the same
    # cgroup read. Lets the Lag Doctor rank culprits *inside* one unit.
    unit: str | None = None
    # What a kernel thread does (kernel.explain), resolved once per name.
    kernel: dict[str, object] | None = None


class ProcessCollector:
    def __init__(self, logical_cores: int | None = None) -> None:
        self.cores = logical_cores or os.cpu_count() or 1
        self._own_pid = os.getpid()
        self._own_uid = os.getuid()
        self._static: dict[int, _Static] = {}
        self._prev_cpu: dict[int, tuple[float, int]] = {}   # pid -> (mono, jiffies)
        self._prev_io: dict[int, tuple[float, int, int]] = {}
        self._prev_faults: dict[int, tuple[float, int, int]] = {}
        self._prev_delay: dict[int, tuple[float, int]] = {}
        self._cpu_history: dict[int, list[float]] = {}
        self._d_streak: dict[int, int] = {}
        self._boot_time = psutil.boot_time()
        self.containers = ContainerResolver()
        self.mode = "proc"
        self.degraded_reason: str | None = None
        self.last_duration_ms = 0.0
        # Prime the deltas so the first live tick has real rates.
        self.sample(limit=0)

    # ------------------------------------------------------------------ public
    def sample(self, gpu_per_pid: dict[int, dict[str, float]] | None = None,
               limit: int = 250) -> dict[str, object]:
        started = time.perf_counter()
        gpu_per_pid = gpu_per_pid or {}
        now = time.monotonic()
        wall = time.time()

        rows: list[dict[str, object]] = []
        live_pids: set[int] = set()
        io_denied = 0
        self.containers.begin_tick()

        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            row = self._scan_pid(pid, now, wall)
            if row is None:
                continue
            live_pids.add(pid)
            if row.pop("_io_denied", False):
                io_denied += 1

            gpu = gpu_per_pid.get(pid)
            row["gpu"] = gpu["total"] if gpu else 0.0
            row["gpu_engines"] = gpu.get("engines") if gpu else None
            row["vram"] = (gpu or {}).get("vram_dedicated") or 0
            row["state"] = _derive_state(row)
            rows.append(row)

        # Forget exited processes so the caches cannot grow without bound.
        for cache in (self._static, self._prev_cpu, self._prev_io,
                      self._prev_faults, self._prev_delay, self._cpu_history,
                      self._d_streak):
            for pid in set(cache) - live_pids:
                cache.pop(pid, None)
        self.containers.forget_except(self.containers.seen)

        real = [r for r in rows if not r["is_kthread"]]
        totals = {
            "count": len(rows),
            "threads": sum(int(r["threads"] or 0) for r in rows),
            "handles": _sum_or_none([r["handles"] for r in real]),
            "cpu": round(sum(float(r["cpu"]) for r in rows), 1),
            "working_set": sum(int(r["working_set"] or 0) for r in real),
            "private": sum(int(r["private"] or 0) for r in real),
            "read_bytes_sec": round(sum(float(r["read_bytes_sec"] or 0) for r in rows)),
            "write_bytes_sec": round(sum(float(r["write_bytes_sec"] or 0) for r in rows)),
            # D-state: uninterruptible sleep, almost always stuck on IO or a
            # dead network mount. The nearest kernel-level relative of the
            # Windows "not responding" count -- but it is NOT the same claim,
            # and the UI labels it as what it is.
            "d_state": sum(1 for r in rows if r["raw_state"] == "D"),
            "stuck": sum(1 for r in rows if r["stuck"]),
            "kernel_threads": sum(1 for r in rows if r["is_kthread"]),
            "zombies": sum(1 for r in rows if r["raw_state"] == "Z"),
            "io_unreadable": io_denied,
            "unresolved": sum(1 for r in rows if not r.get("username")),
            # Distinct containers with at least one live process.
            "containers": len(self.containers.seen),
            "container_processes": sum(1 for r in rows if r.get("container")),
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
            "sample_ms": self.last_duration_ms,
            "cores": self.cores,
            "mode": self.mode,
            "degraded_reason": self.degraded_reason,
            "io_note": (
                f"per-process disk I/O readable for "
                f"{len(rows) - io_denied} of {len(rows)} processes; the rest "
                "need CAP_SYS_PTRACE (ptrace_scope="
                f"{linux.ptrace_scope()})" if io_denied else None
            ),
            # Why some container processes carry only an id: names the socket.
            "container_note": self.containers.note(),
        }

    # ---------------------------------------------------------------- per-pid
    def _scan_pid(self, pid: int, now: float, wall: float) -> dict | None:
        stat_line = linux.read_text(f"/proc/{pid}/stat")
        if stat_line is None:
            return None  # exited between scandir and read
        parsed = _parse_stat(stat_line)
        if parsed is None:
            return None
        name, state, ppid, minflt, majflt, utime, stime, threads, starttime = parsed

        static = self._static.get(pid)
        if static is None or static.starttime != starttime:
            static = self._resolve_static(pid, name, starttime)
            self._static[pid] = static

        jiffies = utime + stime
        cpu_raw = self._cpu_rate(pid, now, jiffies)
        history = self._cpu_history.setdefault(pid, [])
        history.append(cpu_raw)
        if len(history) > 30:
            del history[:-30]
        cpu_avg_raw = sum(history) / len(history)

        # statm field 2 = resident pages. Cheaper than status and enough for
        # the table; PSS (the fair shared-memory split) is permission-gated to
        # own processes, so it lives in the detail panel, not here.
        rss = private = 0
        statm = linux.read_text(f"/proc/{pid}/statm")
        if statm:
            parts = statm.split()
            try:
                rss = int(parts[1]) * _PAGE
                # resident - shared file pages ~= anonymous (private) memory.
                private = max(0, (int(parts[1]) - int(parts[2]))) * _PAGE
            except (IndexError, ValueError):
                pass

        # Fault rates: minor faults are normal memory churn; MAJOR faults are
        # reads from disk and are the per-process paging signal PDH never had.
        fault_prev = self._prev_faults.get(pid)
        self._prev_faults[pid] = (now, minflt, majflt)
        faults_sec = majflt_sec = 0.0
        if fault_prev and now > fault_prev[0]:
            dt = now - fault_prev[0]
            faults_sec = max(0.0, (minflt + majflt - fault_prev[1] - fault_prev[2]) / dt)
            majflt_sec = max(0.0, (majflt - fault_prev[2]) / dt)

        # schedstat field 2 = run_delay: nanoseconds spent runnable but waiting
        # for a CPU. Direct per-process evidence of CPU starvation; Windows
        # cannot provide this at all.
        run_delay_ms = None
        sched = linux.read_text(f"/proc/{pid}/schedstat")
        if sched:
            try:
                delay_ns = int(sched.split()[1])
                prev = self._prev_delay.get(pid)
                self._prev_delay[pid] = (now, delay_ns)
                if prev and now > prev[0]:
                    # ms of waiting per second of wall time, 0..1000*ncpu-ish.
                    run_delay_ms = max(
                        0.0, (delay_ns - prev[1]) / 1e6 / (now - prev[0]))
            except (IndexError, ValueError):
                pass

        # /proc/<pid>/io: rchar/wchar (syscall level, page cache included) and
        # read_bytes/write_bytes (actual block IO). The table shows block IO --
        # "did the disk really get touched" -- keeping the distinction Windows
        # conflated. Permission-gated; failure is counted, never zeroed.
        read_rate = write_rate = None
        io_denied = False
        io_text = linux.read_text(f"/proc/{pid}/io")
        if io_text is None:
            io_denied = True
        else:
            read_b = write_b = 0
            for line in io_text.splitlines():
                if line.startswith("read_bytes:"):
                    read_b = int(line.split()[1])
                elif line.startswith("write_bytes:"):
                    write_b = int(line.split()[1])
            prev_io = self._prev_io.get(pid)
            self._prev_io[pid] = (now, read_b, write_b)
            read_rate = write_rate = 0.0
            if prev_io and now > prev_io[0]:
                dt = now - prev_io[0]
                read_rate = max(0.0, (read_b - prev_io[1]) / dt)
                write_rate = max(0.0, (write_b - prev_io[2]) / dt)

        # Sustained D-state. One tick in D is normal disk IO; several
        # consecutive ticks means genuinely stuck, and wchan names the kernel
        # function it is stuck in.
        streak = self._d_streak.get(pid, 0)
        streak = streak + 1 if state == "D" else 0
        self._d_streak[pid] = streak
        stuck = streak >= 3
        wchan = linux.read_line(f"/proc/{pid}/wchan") if state == "D" else None

        elapsed = max(0.0, wall - (self._boot_time + starttime / _CLK_TCK))

        return {
            "pid": pid,
            "ppid": ppid,
            "name": static.name,
            "exe": static.exe,
            "username": static.username,
            "threads": threads,
            "handles": self._fd_count(pid),
            # Percent of the whole machine, like the CPU column everyone knows.
            "cpu": round(cpu_raw / self.cores, 2),
            "cpu_avg": round(cpu_avg_raw / self.cores, 2),
            # Summed across cores: above 100 means genuinely multi-threaded.
            "cpu_raw": round(cpu_raw, 1),
            "working_set": rss,
            "working_set_private": private,
            "private": private,
            "page_faults_sec": round(faults_sec, 1),
            "major_faults_sec": round(majflt_sec, 2),
            "run_delay_ms": None if run_delay_ms is None else round(run_delay_ms, 2),
            "read_bytes_sec": None if read_rate is None else round(read_rate),
            "write_bytes_sec": None if write_rate is None else round(write_rate),
            "io_bytes_sec": (None if read_rate is None
                             else round(read_rate + write_rate)),
            "io_unreadable": io_denied,
            "elapsed_seconds": round(elapsed, 1),
            "create_time": self._boot_time + starttime / _CLK_TCK,
            "raw_state": state,
            "stuck": stuck,
            "wchan": wchan if wchan not in ("", "0") else None,
            "is_kthread": static.is_kthread,
            "is_system": pid in SYSTEM_PIDS,
            "is_idle": False,
            "is_self": pid == self._own_pid,
            "access_denied": static.username is None,
            # {runtime, id, name, image, service, project} or None. Looked up
            # per tick from the resolver's cache so a name that becomes
            # readable later (socket access granted) shows up without a
            # restart; the cgroup read itself happened once, in _resolve_static.
            "container": (self.containers.entry(*static.container)
                          if static.container else None),
            "unit": static.unit,
            # Kernel threads: what this one *is*, so "kworker/u8:3+flush-252:0
            # at 40%" reads as "writeback for device 252:0" and nobody tries
            # to kill it. Only carried while it is doing something.
            "kernel": (static.kernel if static.is_kthread
                       and (cpu_raw / self.cores >= 0.5 or stuck) else None),
            "_io_denied": io_denied,
        }

    def _cpu_rate(self, pid: int, now: float, jiffies: int) -> float:
        prev = self._prev_cpu.get(pid)
        self._prev_cpu[pid] = (now, jiffies)
        if not prev or now <= prev[0] or jiffies < prev[1]:
            return 0.0
        return 100.0 * (jiffies - prev[1]) / _CLK_TCK / (now - prev[0])

    def _resolve_static(self, pid: int, name: str, starttime: int) -> _Static:
        static = _Static(name=name, starttime=starttime)
        status = linux.parse_kv_file(f"/proc/{pid}/status")
        uid_row = status.get("Uid", "").split()
        if uid_row:
            try:
                static.username = _username(int(uid_row[0]))
            except ValueError:
                pass
        try:
            static.exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            static.exe = None
        # Kernel threads have no userspace image; PF_KTHREAD shows as an empty
        # cmdline plus no exe link. Their "memory use" is kernel memory and
        # must not be summed into userland totals.
        cmdline = linux.read_text(f"/proc/{pid}/cmdline")
        static.is_kthread = (not cmdline or cmdline == "\x00") and static.exe is None
        # Prefer the comm from stat, but a zero-length name means a race.
        if not static.name:
            static.name = status.get("Name", f"pid-{pid}")
        if not static.is_kthread:
            cgroup = linux.cgroup_path_of(pid)
            static.container = identify(cgroup)
            static.unit = _unit_of_cgroup(cgroup)
        else:
            static.kernel = kernel_mod.explain(static.name)
        return static

    def _fd_count(self, pid: int) -> int | None:
        """Open file descriptors -- the closest Linux relative of a handle
        count. Readable for own processes; None (not zero) elsewhere."""
        try:
            return len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            return None

    # ------------------------------------------------------------------ detail
    def detail(self, pid: int,
               extras: frozenset[str] = frozenset()) -> dict[str, object] | None:
        """Everything about one process, collected on demand.

        psutil is the right tool here: one process's worth of its calls costs
        single-digit milliseconds on Linux, and it reaches command line,
        sockets, per-thread times and open files without reimplementation.
        Direct /proc reads add what psutil does not expose: PSS from
        smaps_rollup, run delay, wchan and cgroup membership.
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
                    "username": _try(proc.username),
                    "status": _try(proc.status),
                    "ppid": _try(proc.ppid),
                    "create_time": _try(proc.create_time),
                    "num_threads": _try(proc.num_threads),
                    "num_handles": _try(proc.num_fds),
                    "priority": _nice_label(_try(proc.nice)),
                    "cpu_times": {
                        "user": round(cpu_times.user, 2),
                        "system": round(cpu_times.system, 2),
                    },
                    "memory": {
                        "working_set": mem.rss,
                        "private": getattr(mem, "data", None),
                        "shared": getattr(mem, "shared", None),
                        "virtual": getattr(mem, "vms", None),
                        "text": getattr(mem, "text", None),
                    },
                }
                try:
                    io = proc.io_counters()
                    detail["io"] = {
                        "read_bytes": io.read_bytes, "write_bytes": io.write_bytes,
                        "read_count": io.read_count, "write_count": io.write_count,
                        # Syscall-level totals include page-cache hits; the
                        # block-IO numbers above are what touched the disk.
                        "read_chars": getattr(io, "read_chars", None),
                        "write_chars": getattr(io, "write_chars", None),
                    }
                except (psutil.AccessDenied, NotImplementedError):
                    detail["io"] = None

            # PSS: each shared page divided by its mapper count -- the honest
            # per-process footprint, better than RSS. smaps_rollup is gated
            # like /proc/<pid>/io, so None means unreadable, not zero.
            rollup = linux.parse_kv_file(f"/proc/{pid}/smaps_rollup")
            detail["memory"]["pss"] = linux.meminfo_kb(rollup, "Pss")  # type: ignore[index]
            detail["memory"]["swap_pss"] = linux.meminfo_kb(rollup, "SwapPss")  # type: ignore[index]

            sched = linux.read_text(f"/proc/{pid}/schedstat")
            if sched:
                try:
                    detail["run_delay_total_ms"] = round(int(sched.split()[1]) / 1e6, 1)
                except (IndexError, ValueError):
                    pass
            detail["wchan"] = linux.read_line(f"/proc/{pid}/wchan") or None
            detail["cgroup"] = _cgroup_of(pid)
            detail["oom_score"] = linux.read_int(f"/proc/{pid}/oom_score")
            detail["container"] = self.containers.resolve(detail["cgroup"])
            # The systemd unit (or container scope) this process runs in, with
            # its current CPU quota / IO weight and how many processes share
            # it -- what a throttle would act on, stated before it is offered.
            detail["unit"] = unit_info(pid)
            if detail.get("is_kthread") or (not detail.get("cmdline") and not detail.get("exe")):
                detail["kernel"] = kernel_mod.explain(str(detail.get("name") or ""))

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
            detail["stuck"] = self._d_streak.get(pid, 0) >= 3
            return detail
        except psutil.NoSuchProcess:
            return None
        except psutil.AccessDenied as exc:
            return {"pid": pid, "access_denied": True, "reason": str(exc)}

    def close(self) -> None:
        pass


# ------------------------------------------------------------------ stat parse
def _parse_stat(line: str) -> tuple | None:
    """Fields from /proc/<pid>/stat.

    The comm field is in parentheses and may itself contain spaces and parens
    ("(tmux: server)"), so split on the LAST ')' -- a plain str.split() is
    wrong for any process with a space in its name.
    """
    try:
        left, _, right = line.rpartition(")")
        name = left.partition("(")[2]
        fields = right.split()
        # fields[0] is state (stat field 3); indices below are field# - 3.
        return (
            name,
            fields[0],                # state
            int(fields[1]),           # ppid
            int(fields[7]),           # minflt
            int(fields[9]),           # majflt
            int(fields[11]),          # utime
            int(fields[12]),          # stime
            int(fields[17]),          # num_threads
            int(fields[19]),          # starttime (jiffies since boot)
        )
    except (IndexError, ValueError):
        return None


_user_cache: dict[int, str] = {}


def _username(uid: int) -> str:
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _user_cache[uid] = str(uid)
    return _user_cache[uid]


def _derive_state(row: dict) -> str:
    """A state that is actually informative.

    Raw kernel states collapse almost everything into 'S', so activity is
    folded in: a sleeping process doing IO or burning CPU is 'active'. D-state
    is surfaced by name because it is the one sleep state that means "stuck
    waiting on the kernel" -- the nearest thing Linux has to not-responding.
    """
    raw = str(row.get("raw_state") or "?")
    if row.get("stuck"):
        return "uninterruptible"
    if raw == "Z":
        return "zombie"
    if raw in ("T", "t"):
        return "stopped"
    if row.get("is_kthread"):
        return "kernel"
    if (float(row.get("cpu_avg") or 0) < 0.05
            and float(row.get("io_bytes_sec") or 0) < 1):
        return "idle"
    return "active"


def _sum_or_none(values: list) -> int | None:
    known = [int(v) for v in values if v is not None]
    return sum(known) if known else None


def _unit_of_cgroup(path: str | None) -> str | None:
    """Deepest .service/.scope segment of a cgroup path (same rule as
    linux.unit_from_cgroup, without a second /proc read)."""
    if not path:
        return None
    segments = [s for s in path.strip("/").split("/") if s and s != ".."]
    for suffix in (".service", ".socket", ".scope", ".mount"):
        for seg in reversed(segments):
            if seg.endswith(suffix):
                return seg
    return None


def _cgroup_of(pid: int) -> str | None:
    text = linux.read_text(f"/proc/{pid}/cgroup")
    if not text:
        return None
    # cgroup v2: a single "0::/path" line.
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            return parts[2]
    return None


# ---------------------------------------------------------------------- actions
# Killing any of these takes the machine or the session down with it.
CRITICAL_NAMES = {
    "systemd", "init", "kthreadd", "dbus-daemon", "systemd-journald",
    "systemd-logind", "systemd-udevd", "sshd", "NetworkManager", "login",
}


def can_act(pid: int, action: str = "act on") -> tuple[bool, str]:
    """Refuse actions that would take the machine down or kill this server."""
    if pid == 1:
        return False, "PID 1 is the init system; killing it panics the machine"
    if pid == os.getpid():
        return False, "that is Culprit itself"
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        return False, "process no longer exists"
    except psutil.AccessDenied:
        return False, "access denied"
    try:
        if linux.read_text(f"/proc/{pid}/cmdline") in (None, "", "\x00"):
            return False, (f"{name} is a kernel thread; it cannot be terminated "
                           "from userspace")
    except OSError:
        pass
    if name in CRITICAL_NAMES:
        return False, (f"{name} is a critical system process, so Culprit will "
                       f"not {action} it")
    return True, ""


def terminate(pid: int, force: bool = False) -> dict[str, object]:
    allowed, reason = can_act(pid, "end")
    if not allowed:
        return {"ok": False, "reason": reason}
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.send_signal(signal.SIGKILL if force else signal.SIGTERM)
        try:
            proc.wait(timeout=3)
            return {"ok": True, "pid": pid, "name": name, "exited": True}
        except psutil.TimeoutExpired:
            return {"ok": True, "pid": pid, "name": name, "exited": False,
                    "note": "SIGTERM sent, but the process has not exited yet. "
                            "Use force to send SIGKILL."}
    except psutil.NoSuchProcess:
        return {"ok": True, "pid": pid, "exited": True, "note": "already gone"}
    except psutil.AccessDenied:
        return {"ok": False,
                "reason": "Permission denied -- the process belongs to another "
                          "user. Signalling it needs root (or CAP_KILL)."}
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}


# Niceness: -20 (highest priority) .. 19 (lowest). An unprivileged process can
# only *raise* its targets' niceness, which suits the genuinely useful
# direction: dropping a runaway job below everything interactive.
_PRIORITIES = {
    "idle": 19,
    "below_normal": 10,
    "normal": 0,
    "above_normal": -5,
    "high": -10,
}


def set_priority(pid: int, level: str) -> dict[str, object]:
    """Change a process's niceness.

    Real-time scheduling classes are deliberately not offered, for the same
    reason REALTIME was excluded on Windows: they outrank input handling and
    can leave a machine unusable.
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
        previous = _nice_label(proc.nice())
        proc.nice(_PRIORITIES[level])
        return {"ok": True, "pid": pid, "name": proc.name(),
                "priority": level, "previous": previous}
    except psutil.NoSuchProcess:
        return {"ok": False, "reason": "process no longer exists"}
    except psutil.AccessDenied:
        return {"ok": False,
                "reason": "Permission denied. Lowering niceness (raising "
                          "priority) needs root or CAP_SYS_NICE, and another "
                          "user's process cannot be reniced at all."}
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}


# Throttling: cap the *unit* (cgroup) a process belongs to, via systemd's
# runtime properties. A backup or indexer that is hurting interactive work
# should usually be slowed, not killed: this is reversible, survives the
# process forking, and is exactly what `systemctl set-property --runtime`
# exists for. It acts on the whole unit -- every process in that cgroup --
# which the caller is told up front (`unit_info` counts them), because
# throttling `session-3.scope` throttles someone's entire SSH session.
#
# CPUQuota is relative to ONE cpu in systemd (200% = two cores), so the
# presets are scaled by the core count to mean a share of the machine.
_THROTTLE_LEVELS = {
    "half": (0.50, "50"),        # half the machine's CPU, half the IO weight
    "quarter": (0.25, "10"),     # a quarter of the CPU, near-idle IO weight
    "release": (None, None),     # reset both to unlimited / default
}
_UNTHROTTLEABLE = {"init.scope", "dbus.service", "systemd-journald.service",
                   "systemd-logind.service", "systemd-udevd.service"}


def unit_info(pid: int) -> dict[str, object] | None:
    """The cgroup-v2 unit owning a PID and its current resource limits.

    Read straight from the cgroup files, not from systemctl, so it is cheap
    enough for the detail panel and works without the bus. None when no
    unit owns the process (cgroup v1, or a bare cgroup outside systemd).
    """
    path = linux.cgroup_path_of(pid)
    unit = linux.unit_from_cgroup(pid)
    if not path or not unit or linux.cgroup_version() != 2:
        return None
    segments = [s for s in path.strip("/").split("/") if s and s != ".."]
    try:
        depth = max(i for i, seg in enumerate(segments) if seg == unit)
    except ValueError:
        return None
    unit_dir = linux.CGROUP_ROOT.joinpath(*segments[:depth + 1])
    # Units run by a user's own manager sit under user@<uid>.service and are
    # addressed with `systemctl --user`; everything else (system services,
    # login session scopes, container scopes) belongs to the system manager.
    manager = "user" if any(seg.startswith("user@") and seg.endswith(".service")
                            for seg in segments[:depth]) else "system"
    procs = linux.read_text(unit_dir / "cgroup.procs")
    cores = os.cpu_count() or 1
    quota_pct = _cpu_quota_pct(linux.read_line(unit_dir / "cpu.max"))
    weight = linux.read_line(unit_dir / "io.weight")
    io_weight = None
    if weight:
        try:
            io_weight = int(weight.split()[-1])
        except ValueError:
            io_weight = None
    return {
        "name": unit,
        "manager": manager,
        "cgroup": "/" + "/".join(segments[:depth + 1]),
        "process_count": (len(procs.split()) if procs is not None else None),
        # Percent of the whole machine (systemd's own number is per-CPU).
        "cpu_quota_pct": (None if quota_pct is None
                          else round(quota_pct / cores, 1)),
        "io_weight": io_weight,
        "io_controller": (unit_dir / "io.weight").exists(),
        "throttled": quota_pct is not None or (io_weight is not None
                                               and io_weight != 100),
        "container": identify(path) is not None,
    }


def _cpu_quota_pct(cpu_max: str | None) -> float | None:
    """'50000 100000' -> 50.0 (of one CPU); 'max 100000' -> None."""
    if not cpu_max:
        return None
    parts = cpu_max.split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        return 100.0 * int(parts[0]) / int(parts[1])
    except (ValueError, ZeroDivisionError):
        return None


def throttle(pid: int, level: str) -> dict[str, object]:
    """Cap the CPU share and IO weight of the unit a process belongs to."""
    if level not in _THROTTLE_LEVELS:
        return {"ok": False,
                "reason": f"unknown throttle level {level!r}; expected one of "
                          f"{', '.join(_THROTTLE_LEVELS)}"}
    allowed, reason = can_act(pid, "throttle")
    if not allowed:
        return {"ok": False, "reason": reason}
    info = unit_info(pid)
    if info is None:
        return {"ok": False,
                "reason": "no systemd unit owns this process, so there is no "
                          "cgroup to cap (this needs cgroup v2 under systemd)"}
    unit = str(info["name"])
    own = linux.unit_from_cgroup(os.getpid())
    if unit in _UNTHROTTLEABLE or (own and unit == own):
        return {"ok": False,
                "reason": (f"{unit} is the unit running Culprit itself"
                           if own and unit == own else
                           f"{unit} is a critical system unit; capping it "
                           "would stall the machine")}
    share, io_weight = _THROTTLE_LEVELS[level]
    cores = os.cpu_count() or 1
    if share is None:
        props = ["CPUQuota=", "IOWeight="]
    else:
        props = [f"CPUQuota={int(share * 100 * cores)}%", f"IOWeight={io_weight}"]
    argv = ["systemctl"] + (["--user"] if info["manager"] == "user" else []) \
        + ["set-property", "--runtime", unit] + props
    try:
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": f"systemctl could not run: {exc}"}
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        if "authentication" in err.lower() or "access denied" in err.lower() \
                or "permission" in err.lower():
            return {"ok": False,
                    "reason": ("Permission denied: capping a system unit "
                               f"({unit}) needs root, or a polkit rule granting "
                               "org.freedesktop.systemd1.manage-units to the "
                               "agent's user.")}
        return {"ok": False, "reason": f"systemctl: {err[:300] or 'failed'}"}
    # systemd applies the cgroup change asynchronously after it replies; a
    # read in the same millisecond still shows the old quota.
    time.sleep(0.25)
    after = unit_info(pid) or info
    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        name = None
    note = None
    if share is not None and not after.get("io_controller"):
        note = ("CPU quota applied; the IO weight had no effect because the "
                "io controller is not enabled for this cgroup's parent.")
    return {
        "ok": True, "pid": pid, "name": name, "unit": unit, "level": level,
        "manager": info["manager"], "before": info, "after": after,
        "process_count": after.get("process_count"),
        "runtime_only": True,   # --runtime: cleared by a reboot or daemon-reload
        "note": note,
    }


# Freeing the space a deleted-but-open file still holds. A rotated log the
# daemon never closed keeps its blocks until the last descriptor goes, and
# `df` keeps counting them; the classic fix is `: > /proc/<pid>/fd/<n>`,
# which truncates the inode through the holder's own descriptor without
# touching the process. This does exactly that, and nothing else: the file
# must still be deleted (link count 0), regular, and the one the caller
# named -- a live file with a name is never truncated from here.
def truncate_deleted(pid: int, path: str) -> dict[str, object]:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 4096:
        return {"ok": False, "reason": "path must be the absolute path the holder shows"}
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except FileNotFoundError:
        return {"ok": False, "reason": "process no longer exists"}
    except PermissionError:
        return {"ok": False,
                "reason": ("Permission denied: another user's descriptors are not "
                           "readable; freeing this needs root (or CAP_SYS_PTRACE "
                           "and write access to the file).")}
    except OSError as exc:
        return {"ok": False, "reason": str(exc)}
    wanted = f"{path} (deleted)"
    fd_path = None
    live = False
    for fd in fds:
        try:
            target = os.readlink(f"{fd_dir}/{fd}")
        except OSError:
            continue
        if target == wanted:
            fd_path = f"{fd_dir}/{fd}"
            break
        if target == path:
            live = True
    if fd_path is None:
        if live:
            return {"ok": False,
                    "reason": (f"{path} still has a name on disk -- it is open, not "
                               "merely held; only deleted files are truncated from here")}
        return {"ok": False,
                "reason": ("that process no longer holds a deleted file at this "
                           "path -- it closed it, or the file has a name again")}
    try:
        before = os.stat(fd_path)
    except OSError as exc:
        return {"ok": False, "reason": f"could not stat the descriptor: {exc}"}
    if not stat.S_ISREG(before.st_mode):
        return {"ok": False, "reason": "not a regular file; only files are truncated"}
    if before.st_nlink != 0:
        return {"ok": False,
                "reason": ("the file still has a name on disk (link count "
                           f"{before.st_nlink}), so it is not merely held -- "
                           "refusing to truncate a live file")}
    try:
        os.truncate(fd_path, 0)
        after = os.stat(fd_path).st_size
    except PermissionError:
        return {"ok": False,
                "reason": ("Permission denied: truncating needs write access to "
                           "the file (its owner, or root).")}
    except OSError as exc:
        return {"ok": False, "reason": str(exc)}
    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        name = None
    return {
        "ok": True, "pid": pid, "name": name, "path": path,
        "freed_bytes": max(0, before.st_size - after), "size_after": after,
        "note": ("The holder still has the descriptor open: if it keeps appending, "
                 "the file grows again from zero. Restarting it (or a log rotation "
                 "it honours) closes the handle for good."),
    }


def _nice_label(value: object) -> str | None:
    if value is None:
        return None
    try:
        nice = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value)
    for label, target in _PRIORITIES.items():
        if nice == target:
            return label
    return f"nice {nice}"


# ---------------------------------------------------------------------- helpers
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
