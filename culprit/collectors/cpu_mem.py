"""CPU and memory sampling -- the 1Hz hot path.

Everything here is a plain /proc or /sys read; the whole sample costs about a
millisecond, where the Windows PDH version cost ~25ms. Field names are kept
compatible with the Windows payload wherever the semantics genuinely map
(commit charge <-> Committed_AS, hard faults <-> pgmajfault), so the frontend
keeps working; fields with no Linux meaning are None, which renders as an em
dash rather than a lying zero.

What Linux adds that Windows could not provide:

* **PSI** (/proc/pressure/*): the kernel's own measurement of time spent
  stalled on CPU, memory and IO -- the honest version of the pressure model.
* **iowait** and **steal** per-CPU: steal matters on VMs (this dev box is one).
* `procs_blocked`: how many tasks are in uninterruptible sleep right now.

Two counters honestly do not exist here: Windows' "% Processor Utility"
(frequency-normalised) and a system-wide syscall rate. `total` is time-based
utilisation and `system_calls` stays None rather than being faked.
"""

from __future__ import annotations

import os
import time

from .. import linux
from ..util import clamp, safe_div

_CLK_TCK = os.sysconf("SC_CLK_TCK")


class CpuMemoryCollector:
    def __init__(self) -> None:
        self._prev_stat = _read_proc_stat()
        self._prev_vmstat = _read_vmstat()
        self._prev_at = time.monotonic()
        self.psi_available = linux.psi_available()
        self.container = linux.in_container()
        # Thermal/power throttling counters exist only where the driver
        # exposes them (x86 with the intel/amd throttle drivers, bare metal);
        # a VM has none, and the payload says so instead of showing 0 events.
        self._throttle_paths = _throttle_counter_paths()
        self._prev_throttle: tuple[float, int] | None = None
        self._swap_devices: list[dict[str, object]] = []
        self._swap_checked = 0.0

    @property
    def degraded(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if not self.psi_available:
            out["psi"] = ("/proc/pressure/ does not exist -- kernel < 4.20, "
                          "CONFIG_PSI=n, or psi=1 missing from the kernel "
                          "command line. Pressure falls back to the derived "
                          "model.")
        if self.container:
            out["container"] = (
                f"running inside a {self.container} container: /proc/stat and "
                "/proc/meminfo show the HOST unless lxcfs is mounted"
            )
        return out

    def sample(self) -> dict[str, object]:
        now = time.monotonic()
        elapsed = max(1e-3, now - self._prev_at)
        stat = _read_proc_stat()
        vmstat = _read_vmstat()
        prev_stat, prev_vmstat = self._prev_stat, self._prev_vmstat
        self._prev_stat, self._prev_vmstat, self._prev_at = stat, vmstat, now

        cpu = self._cpu_section(stat, prev_stat, elapsed)
        memory = self._memory_section(vmstat, prev_vmstat, elapsed)
        psi = linux.system_psi()

        return {"cpu": cpu, "memory": memory, "psi": psi}

    # ------------------------------------------------------------------ CPU
    def _cpu_section(self, stat: dict, prev: dict, elapsed: float) -> dict:
        total_row = _cpu_percent(stat.get("cpu"), prev.get("cpu"))
        per_core: list[float] = []
        index = 0
        while f"cpu{index}" in stat:
            row = _cpu_percent(stat[f"cpu{index}"], prev.get(f"cpu{index}"))
            per_core.append(row["busy"])
            index += 1
        logical = max(1, len(per_core))

        loadavg = (linux.read_line("/proc/loadavg") or "").split()
        load1 = load5 = load15 = None
        thread_count = None
        try:
            load1, load5, load15 = (float(loadavg[0]), float(loadavg[1]),
                                    float(loadavg[2]))
            # Fourth field is "runnable/total scheduling entities" -- the total
            # is the system thread count, free of charge.
            thread_count = int(loadavg[3].split("/")[1])
        except (IndexError, ValueError):
            pass

        # procs_running counts *us* taking this sample; the queue the user
        # feels is everyone else. Same role as the Windows processor queue.
        running = stat.get("procs_running")
        queue = max(0, int(running) - 1) if running is not None else None

        ctxt = _rate_of(stat, prev, "ctxt", elapsed)

        return {
            # Time-based utilisation. Linux has no frequency-normalised
            # "utility" counter, so both fields carry the same number and the
            # UI's "time-based" annotation stays truthful.
            "total": total_row["busy"],
            "total_time_based": total_row["busy"],
            "per_core": [round(v, 1) for v in per_core],
            "user": total_row["user"],
            "privileged": total_row["system"],
            "interrupt": total_row["irq"],
            # No Windows equivalents -- new signals, both explain "slow but not
            # busy": iowait is CPU idle *waiting on disk*, steal is the
            # hypervisor giving this VM's time to someone else.
            "iowait": total_row["iowait"],
            "steal": total_row["steal"],
            "performance_pct": None,
            "frequency_mhz": _current_mhz(),
            "governor": linux.read_line(
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            "thermal": self._thermal(elapsed),
            "queue_length": queue,
            "queue_per_core": (None if queue is None
                               else round(queue / logical, 2)),
            "blocked": stat.get("procs_blocked"),
            "load_1": load1, "load_5": load5, "load_15": load15,
            "context_switches": None if ctxt is None else round(ctxt),
            "system_calls": None,  # no such system-wide counter on Linux
            "logical_cores": logical,
            "process_count": _count_pids(),
            "thread_count": thread_count,
        }

    def _thermal(self, elapsed: float) -> dict[str, object]:
        """Thermal / power-limit throttling: the CPU being slowed by its own
        cooling, which no process can be blamed for. The counters are
        cumulative throttle events per core; their rate is the signal. The
        clock ratio (current vs. maximum cpufreq) is the second view of the
        same thing, where cpufreq exists."""
        max_khz = linux.read_int("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        cur_khz = linux.read_int("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
        ratio = (round(cur_khz / max_khz, 3) if max_khz and cur_khz else None)
        if not self._throttle_paths:
            return {
                "available": False,
                "reason": ("no thermal_throttle counters in sysfs -- a virtual "
                           "machine, or a platform whose CPU driver does not "
                           "expose them; throttling cannot be observed here"),
                "throttle_events_sec": None, "throttle_count": None,
                "clock_ratio": ratio, "max_mhz": (max_khz or 0) / 1000 or None,
            }
        total = 0
        for path in self._throttle_paths:
            total += linux.read_int(path) or 0
        rate = None
        if self._prev_throttle is not None:
            rate = max(0.0, (total - self._prev_throttle[1]) / elapsed)
        self._prev_throttle = (time.monotonic(), total)
        return {
            "available": True, "reason": None,
            "throttle_events_sec": None if rate is None else round(rate, 2),
            "throttle_count": total,
            "clock_ratio": ratio, "max_mhz": (max_khz or 0) / 1000 or None,
        }

    # --------------------------------------------------------------- memory
    def _memory_section(self, vmstat: dict, prev: dict, elapsed: float) -> dict:
        info = linux.parse_kv_file("/proc/meminfo")
        total = linux.meminfo_kb(info, "MemTotal") or 0
        # MemAvailable, not MemFree: free ignores reclaimable page cache and
        # under-reports what is actually usable by a wide margin.
        available = linux.meminfo_kb(info, "MemAvailable")
        committed = linux.meminfo_kb(info, "Committed_AS")
        commit_limit = linux.meminfo_kb(info, "CommitLimit")
        cached = ((linux.meminfo_kb(info, "Cached") or 0)
                  + (linux.meminfo_kb(info, "SReclaimable") or 0))
        swap_total = linux.meminfo_kb(info, "SwapTotal") or 0
        swap_free = linux.meminfo_kb(info, "SwapFree") or 0
        swap_used = max(0, swap_total - swap_free)
        used = total - (available or 0)

        # Commit charge maps 1:1 to Windows *only* under strict overcommit
        # (vm.overcommit_memory=2). Under the default heuristic policy the
        # kernel does not enforce CommitLimit and Committed_AS routinely
        # exceeds it on a healthy machine -- treating that as "allocations
        # about to fail" would be confident nonsense, so the enforcement flag
        # travels with the numbers and the Lag Doctor gates on it.
        overcommit = linux.read_int("/proc/sys/vm/overcommit_memory")

        # pgmajfault is the honest "memory is being served from disk" rate --
        # the direct analogue of Windows' hard faults, and the number that
        # explains stutter.
        majflt = _rate_of(vmstat, prev, "pgmajfault", elapsed)
        minflt = _rate_of(vmstat, prev, "pgfault", elapsed)
        swap_in = _rate_of(vmstat, prev, "pswpin", elapsed)
        swap_out = _rate_of(vmstat, prev, "pswpout", elapsed)
        # Which devices back swap, and whether any is a spinning disk: paging
        # to rotational storage costs a seek per page, which is the case
        # where "swapping" is a hardware verdict rather than a process's fault.
        # /proc/swaps changes on swapon/swapoff only, so a minute is plenty.
        now = time.monotonic()
        if now - self._swap_checked > 60.0:
            self._swap_devices = _swap_devices()
            self._swap_checked = now
        rotational_flags = [d.get("rotational") for d in self._swap_devices]

        return {
            "total": total,
            "used": used,
            "available": available,
            "percent": round(clamp(safe_div(used, total) * 100), 2) if total else None,
            "available_mb": (None if available is None
                             else round(available / 1048576)),
            # Committed_AS / CommitLimit is a clean 1:1 with Windows commit
            # charge. Note the limit depends on vm.overcommit_* settings.
            "committed": committed,
            "commit_limit": commit_limit,
            "commit_percent": (
                round(clamp(safe_div(committed or 0, commit_limit or 0) * 100), 2)
                if committed and commit_limit else None
            ),
            "commit_enforced": overcommit == 2,
            "overcommit_policy": overcommit,
            "cached": cached or None,
            "hard_faults_sec": None if majflt is None else round(majflt, 1),
            "page_faults_sec": None if minflt is None else round(minflt),
            "swap_total": swap_total,
            "swap_used": swap_used,
            "swap_percent": (round(safe_div(swap_used, swap_total) * 100, 2)
                             if swap_total else 0.0),
            "swap_in_sec": None if swap_in is None else round(swap_in, 1),
            "swap_out_sec": None if swap_out is None else round(swap_out, 1),
            "swap_devices": self._swap_devices,
            # True if any swap device spins; None when there is no swap or the
            # device type could not be read (never a guessed False).
            "swap_rotational": (True if any(f is True for f in rotational_flags)
                                else False if rotational_flags
                                and all(f is False for f in rotational_flags)
                                else None),
            # Cumulative OOM kills since boot; the sampler diffs it for alerts.
            "oom_kills_total": vmstat.get("oom_kill"),
            "dirty": linux.meminfo_kb(info, "Dirty"),
            "writeback": linux.meminfo_kb(info, "Writeback"),
        }

    def close(self) -> None:  # symmetry with the sampler's lifecycle hooks
        pass


# ------------------------------------------------------------------- /proc/stat
def _read_proc_stat() -> dict[str, object]:
    """Per-CPU jiffy rows plus the scalar counters, one pass."""
    out: dict[str, object] = {}
    text = linux.read_text("/proc/stat") or ""
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        key = parts[0]
        if key.startswith("cpu"):
            try:
                out[key] = [int(v) for v in parts[1:]]
            except ValueError:
                pass
        elif key in ("ctxt", "procs_running", "procs_blocked", "btime"):
            try:
                out[key] = int(parts[1])
            except (ValueError, IndexError):
                pass
    return out


def _cpu_percent(row: list[int] | None, prev: list[int] | None) -> dict[str, float | None]:
    """Deltas of one jiffy row -> percentages of that CPU's time."""
    empty = {"busy": 0.0, "user": None, "system": None, "irq": None,
             "iowait": None, "steal": None}
    if not row or not prev or len(row) < 8 or len(prev) < 8:
        return empty
    delta = [max(0, a - b) for a, b in zip(row, prev)]
    total = sum(delta[:8])  # user nice system idle iowait irq softirq steal
    if total <= 0:
        return empty
    user, nice, system, idle, iowait, irq, softirq, steal = delta[:8]
    pct = lambda v: round(100.0 * v / total, 2)  # noqa: E731
    return {
        # iowait is idle-while-waiting, so it is not "busy" -- a machine at 5%
        # busy + 60% iowait is idle CPU-wise and drowning IO-wise, and the two
        # must not be conflated.
        "busy": pct(total - idle - iowait),
        "user": pct(user + nice),
        "system": pct(system),
        "irq": pct(irq + softirq),
        "iowait": pct(iowait),
        "steal": pct(steal),
    }


_VMSTAT_KEYS = frozenset(
    {"pgmajfault", "pgfault", "pswpin", "pswpout", "oom_kill"})


def _read_vmstat() -> dict[str, int]:
    out: dict[str, int] = {}
    text = linux.read_text("/proc/vmstat") or ""
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key in _VMSTAT_KEYS:
            try:
                out[key] = int(value)
            except ValueError:
                pass
    return out


def _rate_of(current: dict, prev: dict, key: str, elapsed: float) -> float | None:
    now_v, prev_v = current.get(key), (prev or {}).get(key)
    if now_v is None or prev_v is None:
        return None
    return max(0.0, (now_v - prev_v) / elapsed)


def _count_pids() -> int:
    try:
        return sum(1 for name in os.listdir("/proc") if name.isdigit())
    except OSError:
        return 0


def _throttle_counter_paths() -> list[str]:
    base = "/sys/devices/system/cpu"
    out: list[str] = []
    try:
        for entry in os.listdir(base):
            if not (entry.startswith("cpu") and entry[3:].isdigit()):
                continue
            for name in ("core_throttle_count", "package_throttle_count"):
                path = f"{base}/{entry}/thermal_throttle/{name}"
                if os.path.exists(path):
                    out.append(path)
    except OSError:
        pass
    return out


def _swap_devices() -> list[dict[str, object]]:
    """Every active swap area with the rotational flag of the disk under it.

    A swap *file* is resolved through the filesystem it lives on (st_dev), a
    partition through its device node (st_rdev); dm/md devices are followed
    down through /sys/dev/block/<maj:min>/slaves to a real disk. Anything
    that cannot be resolved reports rotational=None.
    """
    text = linux.read_text("/proc/swaps")
    out: list[dict[str, object]] = []
    if not text:
        return out
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        path, kind = parts[0], parts[1]
        try:
            size_kb = int(parts[2])
        except ValueError:
            size_kb = None
        rotational: bool | None = None
        try:
            st = os.stat(path)
            dev = st.st_rdev if kind == "partition" and st.st_rdev else st.st_dev
            rotational = _rotational_of(os.major(dev), os.minor(dev))
        except OSError:
            pass
        out.append({"path": path, "type": kind, "size_kb": size_kb,
                    "rotational": rotational})
    return out


def _rotational_of(major: int, minor: int, depth: int = 0) -> bool | None:
    """queue/rotational for a block device, following partitions up to their
    disk and layered (dm/md) devices down to their slaves."""
    if depth > 4:
        return None
    try:
        node = os.path.realpath(f"/sys/dev/block/{major}:{minor}")
    except OSError:
        return None
    if not os.path.isdir(node):
        return None
    # A partition directory has a `partition` file; its disk is the parent.
    if os.path.exists(f"{node}/partition"):
        node = os.path.dirname(node)
    try:
        slaves = os.listdir(f"{node}/slaves")
    except OSError:
        slaves = []
    if slaves:
        flags = []
        for slave in slaves:
            dev = linux.read_line(f"{node}/slaves/{slave}/dev")
            if dev and ":" in dev:
                maj, _, mino = dev.partition(":")
                try:
                    flags.append(_rotational_of(int(maj), int(mino), depth + 1))
                except ValueError:
                    pass
        if any(f is True for f in flags):
            return True
        if flags and all(f is False for f in flags):
            return False
        return None
    value = linux.read_int(f"{node}/queue/rotational")
    return None if value is None else bool(value)


def _current_mhz() -> float | None:
    """Average current frequency. cpufreq is authoritative; /proc/cpuinfo is
    the fallback (the only source inside this KVM dev box, where cpufreq does
    not exist at all)."""
    freqs: list[float] = []
    base = "/sys/devices/system/cpu"
    try:
        for entry in os.listdir(base):
            if not (entry.startswith("cpu") and entry[3:].isdigit()):
                continue
            khz = linux.read_int(f"{base}/{entry}/cpufreq/scaling_cur_freq")
            if khz:
                freqs.append(khz / 1000.0)
    except OSError:
        pass
    if not freqs:
        text = linux.read_text("/proc/cpuinfo") or ""
        for line in text.splitlines():
            if line.startswith("cpu MHz"):
                try:
                    freqs.append(float(line.split(":")[1]))
                except (IndexError, ValueError):
                    pass
    return round(sum(freqs) / len(freqs)) if freqs else None
