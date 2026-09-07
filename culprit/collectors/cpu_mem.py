"""CPU and memory sampling -- the 1Hz hot path.

Uses PDH in preference to psutil for anything PDH does better:

* `% Processor Utility` instead of `% Processor Time`. The classic counter is
  normalised to the base clock, so a CPU running at 60% of base clock while
  fully loaded reports ~60%. Utility accounts for frequency scaling and is what
  Task Manager shows.
* `\\System\\Processor Queue Length` -- threads that are runnable but waiting for
  a core. This, not raw CPU%, is what "the machine feels slow" actually means.
* `\\Memory\\Pages/sec` -- hard faults. Distinguishes "RAM is full" from "RAM is
  full and Windows is now paging to disk", which is the difference between a
  warning and an explanation.

The payload keeps the Linux agent's shape exactly, because the host and the
dashboard read that shape. Fields the Linux kernel has and Windows does not --
PSI, iowait, steal, the load average, uninterruptible tasks -- are `None`
(rendered as an em dash, never as a lying zero) and `degraded` names why.
Two Windows facts go the other way: the commit limit *is* enforced here
(`commit_enforced: True`, so the Lag Doctor's commit signal applies the way it
only does under strict overcommit on Linux), and the kernel pools have no
Linux counterpart (`pool_paged` / `pool_nonpaged` are Windows-only extras).
"""

from __future__ import annotations

import time

import psutil

from .. import windows
from ..util import clamp, safe_div

# key -> counter path. Every one of these is optional; a missing counter blanks
# one field rather than failing the tick.
_COUNTERS: tuple[tuple[str, str], ...] = (
    ("cpu_utility", r"\Processor Information(_Total)\% Processor Utility"),
    ("cpu_performance", r"\Processor Information(_Total)\% Processor Performance"),
    ("cpu_frequency", r"\Processor Information(_Total)\Processor Frequency"),
    ("cpu_privileged", r"\Processor Information(_Total)\% Privileged Time"),
    ("cpu_interrupt", r"\Processor Information(_Total)\% Interrupt Time"),
    ("cpu_dpc", r"\Processor Information(_Total)\% DPC Time"),
    ("cpu_user", r"\Processor Information(_Total)\% User Time"),
    ("queue_length", r"\System\Processor Queue Length"),
    ("context_switches", r"\System\Context Switches/sec"),
    ("system_calls", r"\System\System Calls/sec"),
    ("processes", r"\System\Processes"),
    ("threads", r"\System\Threads"),
    ("mem_available_mb", r"\Memory\Available MBytes"),
    ("mem_committed", r"\Memory\Committed Bytes"),
    ("mem_commit_limit", r"\Memory\Commit Limit"),
    ("hard_faults", r"\Memory\Pages/sec"),
    ("pages_in", r"\Memory\Pages Input/sec"),
    ("pages_out", r"\Memory\Pages Output/sec"),
    ("page_faults", r"\Memory\Page Faults/sec"),
    ("mem_cache", r"\Memory\Cache Bytes"),
    ("pool_nonpaged", r"\Memory\Pool Nonpaged Bytes"),
    ("pool_paged", r"\Memory\Pool Paged Bytes"),
    ("pagefile_usage", r"\Paging File(_Total)\% Usage"),
    ("dirty_pages", r"\Cache\Dirty Pages"),
)

# Per-core utility, as a wildcard array. Instance names are "0,0" / "0,1" on
# multi-group machines and plain "0" / "1" otherwise, plus a "_Total" to drop.
_PERCORE = (r"\Processor Information(*)\% Processor Utility", "percore_utility")

# Thermal zones exist on some machines only (the original dev laptop had
# none), and the counter reports Kelvin.
_THERMAL = (r"\Thermal Zone Information(*)\Temperature", "thermal_temp")
_THROTTLE = (r"\Thermal Zone Information(*)\% Passive Limit", "thermal_limit")


class CpuMemoryCollector:
    def __init__(self) -> None:
        self.query = windows.PdhQuery("cpu_mem")
        self.query.add_many(_COUNTERS)
        self.has_percore = self.query.add(_PERCORE[1], _PERCORE[0], array=True)
        self.has_thermal = self.query.add(_THERMAL[1], _THERMAL[0], array=True)
        self.query.add(_THROTTLE[1], _THROTTLE[0], array=True)
        # The Linux agent reports these; both are honestly absent here.
        self.psi_available = False
        self.container = None
        # Prime psutil's internal deltas so the first real sample is not 0.0.
        psutil.cpu_percent(percpu=True)
        psutil.cpu_percent()
        self.query.collect()
        self._swap_devices: list[dict[str, object]] = []
        self._swap_checked = 0.0

    @property
    def degraded(self) -> dict[str, str]:
        out = dict(self.query.unavailable)
        out["psi"] = windows.not_capable(
            "PSI (pressure stall information) is a Linux kernel interface; "
            "pressure comes from the derived model (utilisation, run queue, "
            "hard faults, disk latency).")
        out["load"] = windows.not_capable(
            "Windows keeps no load average or D-state count; the run queue "
            "depth (queue_per_core) is the equivalent signal.")
        return out

    def sample(self) -> dict[str, object]:
        query = self.query
        query.collect()

        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # Prefer PDH utility; fall back to psutil if the counter set is missing.
        utility = query.value("cpu_utility")
        psutil_total = psutil.cpu_percent()
        total = clamp(utility if utility is not None else psutil_total)

        per_core: list[float] = []
        if self.has_percore:
            array = query.array("percore_utility")
            # Two kinds of aggregate instance have to be dropped, not one: the
            # machine-wide "_Total" and -- on multi-processor-group machines --
            # a per-group "0,_Total". Filtering only the exact string "_Total"
            # left a 13th value on a 12-core box that was really the total.
            cores = [
                (_core_sort_key(name), clamp(value))
                for name, value in array.items()
                if "_total" not in name.lower()
            ]
            per_core = [value for _, value in sorted(cores, key=lambda item: item[0])]
        if not per_core:
            per_core = [clamp(v) for v in psutil.cpu_percent(percpu=True)]

        logical = psutil.cpu_count(logical=True) or 1
        queue = query.value("queue_length")
        committed = query.value("mem_committed")
        commit_limit = query.value("mem_commit_limit")
        times = psutil.cpu_times_percent()
        interrupt = query.value("cpu_interrupt")
        dpc = query.value("cpu_dpc")
        # DPC time is the Windows analogue of softirq time; both are "the
        # kernel servicing devices", so they are reported together the way
        # Linux reports irq + softirq under `interrupt`.
        interrupt_total = (None if interrupt is None and dpc is None
                           else (interrupt or 0.0) + (dpc or 0.0))

        now = time.monotonic()
        if now - self._swap_checked > 300:
            self._swap_devices = _pagefiles()
            self._swap_checked = now

        cpu = {
            "total": round(total, 2),
            "total_time_based": round(clamp(psutil_total), 2),
            "per_core": [round(v, 1) for v in per_core],
            "user": _round(query.value("cpu_user"), fallback=times.user),
            "privileged": _round(query.value("cpu_privileged"),
                                 fallback=times.system),
            "interrupt": _round(interrupt_total),
            "dpc": _round(dpc),
            # No Linux-only kernel counters on Windows -- None, never 0.
            "iowait": None,
            "steal": None,
            # >100% means turbo; do not clamp, it is real information.
            "performance_pct": _round(query.value("cpu_performance")),
            "frequency_mhz": _round(query.value("cpu_frequency"), digits=0),
            "governor": _power_plan(),
            "thermal": self._thermal(),
            "queue_length": _round(queue, digits=2),
            "queue_per_core": _round(safe_div(queue or 0.0, logical), digits=2),
            "blocked": None,
            "load_1": None, "load_5": None, "load_15": None,
            "context_switches": _round(query.value("context_switches"), digits=0),
            "system_calls": _round(query.value("system_calls"), digits=0),
            "logical_cores": logical,
            "process_count": _round(query.value("processes"), digits=0),
            "thread_count": _round(query.value("threads"), digits=0),
        }
        pages_in = query.value("pages_in")
        pages_out = query.value("pages_out")
        memory = {
            "total": virtual.total,
            "used": virtual.total - virtual.available,
            "available": virtual.available,
            "percent": round(virtual.percent, 2),
            "available_mb": _round(query.value("mem_available_mb"), digits=0)
                            or round(virtual.available / 1048576),
            "committed": _int(committed),
            "commit_limit": _int(commit_limit),
            "commit_percent": round(
                clamp(safe_div((committed or 0.0), (commit_limit or 0.0)) * 100), 2
            ),
            # Windows always enforces the commit limit: an allocation past it
            # fails outright, so commit% is a real ceiling here (on Linux it
            # only is under vm.overcommit_memory=2).
            "commit_enforced": True,
            "overcommit_policy": None,
            "cached": _int(query.value("mem_cache")),
            "pool_paged": _int(query.value("pool_paged")),
            "pool_nonpaged": _int(query.value("pool_nonpaged")),
            # Hard faults resolved from disk. The number that explains stutter.
            "hard_faults_sec": _round(query.value("hard_faults"), digits=1),
            "page_faults_sec": _round(query.value("page_faults"), digits=0),
            "swap_total": swap.total,
            "swap_used": swap.used,
            "swap_percent": round(swap.percent, 2),
            # Pages Input/Output are page-sized; Linux reports pages too.
            "swap_in_sec": _round(pages_in, digits=1),
            "swap_out_sec": _round(pages_out, digits=1),
            "swap_devices": self._swap_devices,
            "swap_rotational": next((d.get("rotational") for d in self._swap_devices
                                     if d.get("rotational") is not None), None),
            "pagefile_percent": _round(query.value("pagefile_usage"), digits=2),
            "oom_kills_total": None,
            "dirty": _pages_to_bytes(query.value("dirty_pages")),
            "writeback": None,
        }
        return {"cpu": cpu, "memory": memory, "psi": None}

    def _thermal(self) -> dict[str, object]:
        if not self.has_thermal:
            return {"available": False,
                    "reason": self.query.unavailable.get(
                        "thermal_temp", "no Thermal Zone Information counters on this machine"),
                    "throttle_events_sec": None, "throttle_count": None,
                    "clock_ratio": None, "max_mhz": None, "temperature_c": None}
        temps = [v for v in self.query.array("thermal_temp").values() if v > 0]
        limits = [v for v in self.query.array("thermal_limit").values()]
        performance = self.query.value("cpu_performance")
        return {
            "available": bool(temps),
            "reason": None if temps else "the Thermal Zone counters report no temperature",
            # Passive limit < 100 means the firmware is asking for less clock:
            # that is the throttle, reported as the ratio Linux would show.
            "throttle_events_sec": None,
            "throttle_count": None,
            "clock_ratio": (round(min(limits) / 100.0, 3) if limits
                            else (round(performance / 100.0, 3) if performance else None)),
            "max_mhz": None,
            "temperature_c": round(max(temps) - 273.15, 1) if temps else None,
        }

    def close(self) -> None:
        self.query.close()


def _pagefiles() -> list[dict[str, object]]:
    """The page files in the Linux `swap_devices` shape (path/type/size_kb/
    rotational). Rotational comes from the drive behind the file's letter
    when WMI can say; None when it cannot."""
    out: list[dict[str, object]] = []
    rows = windows.wmi_query(
        "SELECT Name, AllocatedBaseSize, CurrentUsage FROM Win32_PageFileUsage",
        ("Name", "AllocatedBaseSize", "CurrentUsage"))
    media = _media_by_letter() if rows else {}
    for row in rows:
        path = str(row.get("Name") or "")
        letter = path[:2].upper() if len(path) >= 2 and path[1] == ":" else None
        size_mb = row.get("AllocatedBaseSize")
        out.append({
            "path": path, "type": "file",
            "size_kb": int(size_mb) * 1024 if isinstance(size_mb, (int, float)) else None,
            "rotational": media.get(letter) if letter else None,
        })
    return out


def _media_by_letter() -> dict[str, bool | None]:
    """Drive letter -> rotational, via the Storage namespace (Windows 8+)."""
    out: dict[str, bool | None] = {}
    disks = windows.wmi_query(
        "SELECT DeviceId, MediaType FROM MSFT_PhysicalDisk",
        ("DeviceId", "MediaType"), namespace=r"winmgmts:\\.\root\Microsoft\Windows\Storage")
    if not disks:
        return out
    rotational_by_index = {str(d.get("DeviceId")): media_rotational(d.get("MediaType"))
                           for d in disks}
    # Letter -> disk index through the partition associations.
    for row in windows.wmi_query(
            "SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition",
            ("Antecedent", "Dependent")):
        antecedent = str(row.get("Antecedent") or "")
        dependent = str(row.get("Dependent") or "")
        # 'Win32_DiskPartition.DeviceID="Disk #0, Partition #2"' / '...DeviceID="C:"'
        index = antecedent.split("Disk #", 1)[-1].split(",", 1)[0].strip('" ')
        letter = dependent.rsplit("=", 1)[-1].strip('"').upper()
        if index.isdigit() and len(letter) == 2:
            out[letter] = rotational_by_index.get(index)
    return out


def media_rotational(media_type: object) -> bool | None:
    """MSFT_PhysicalDisk.MediaType: 0 unspecified, 3 HDD, 4 SSD, 5 SCM."""
    try:
        value = int(media_type)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return {3: True, 4: False, 5: False}.get(value)


_power_plan_cache: tuple[float, str | None] = (0.0, None)


def _power_plan() -> str | None:
    """The active power scheme, the Windows counterpart of the cpufreq
    governor: 'power saver' on battery explains a lot of reported slowness.
    Read from the registry every minute -- no powercfg spawn on the 1 Hz path."""
    global _power_plan_cache
    now = time.monotonic()
    if now - _power_plan_cache[0] < 60:
        return _power_plan_cache[1]
    name = None
    guid = windows.reg_value(
        windows.HKLM, r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
        "ActivePowerScheme")
    if guid:
        friendly = windows.reg_value(
            windows.HKLM,
            rf"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{guid}",
            "FriendlyName")
        # The built-in schemes store an indirect string ("@%SystemRoot%\...,-13")
        # rather than the name; map the well-known GUIDs instead.
        known = {
            "381b4222-f694-41f0-9685-ff5bb260df2e": "balanced",
            "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "high performance",
            "a1841308-3541-4fab-bc81-f71556f20b4a": "power saver",
            "e9a42b02-d5df-448d-aa00-03f14749eb61": "ultimate performance",
        }
        name = known.get(str(guid).lower()) or (
            str(friendly) if friendly and not str(friendly).startswith("@") else str(guid))
    _power_plan_cache = (now, name)
    return name


def _core_sort_key(name: str) -> tuple[int, int]:
    """'0,5' -> (0, 5); '5' -> (0, 5). Keeps cores in hardware order."""
    try:
        if "," in name:
            group, core = name.split(",", 1)
            return int(group), int(core)
        return 0, int(name)
    except ValueError:
        return 999, 999


def _round(value: float | None, digits: int = 2,
           fallback: float | None = None) -> float | None:
    if value is None:
        value = fallback
    if value is None:
        return None
    return round(float(value), digits) if digits else round(float(value))


def _int(value: float | None) -> int | None:
    return None if value is None else int(value)


def _pages_to_bytes(pages: float | None) -> int | None:
    return None if pages is None else int(pages) * 4096
