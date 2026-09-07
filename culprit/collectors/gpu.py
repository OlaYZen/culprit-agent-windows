"""GPU utilisation and VRAM, per adapter *and* per process.

Where the Linux agent has three backends (DRM fdinfo, NVML, amdgpu sysfs)
and names which one answered, Windows has one uniform source that covers
every vendor, so `backend` is always "pdh-gpu-engine". Engine keys are the
WDDM engine classes (3D, Copy, VideoDecode, ...) rather than the Linux
driver's names (render, video, ...); both sides label them for display.

There is no NVML here on purpose. `nvidia-smi` only exists on NVIDIA hardware
and gives nothing for the Intel/AMD integrated GPUs most corporate laptops
actually have (this machine: Intel Iris Xe). The `\\GPU Engine` performance
counters work on every WDDM 2.0+ adapter, need no elevation, and -- crucially --
are keyed by PID, so they give the same per-process GPU column Task Manager has.

Instance names look like:

    pid_23324_luid_0x00000004_0xAB370C9F_phys_0_eng_0_engtype_3D
    |         |                          |        |     `- engine class
    |         |                          |        `- engine index within class
    |         |                          `- physical adapter
    |         `- adapter LUID
    `- owning process

Turning ~600 of those into meaningful numbers needs care, because naively
summing everything produces utilisation well above 100%. A single instance's
value is a percentage *of one engine's* time, so the aggregation is:

    per engine (luid, phys, eng, engtype):  sum over PIDs      -> 0..100
    per engine class:                       max over engines   -> 0..100
    per adapter:                            max over classes   -> 0..100

That matches what Task Manager reports and stays bounded. One PDH collect plus
one array format costs 15-40ms in steady state, so the per-PID map is produced
as a by-product of the adapter totals rather than by a second query.
"""

from __future__ import annotations

from collections import defaultdict

from .. import windows as pdh
from ..util import clamp

# Engine classes worth showing separately. Anything else Windows reports is
# folded into "other" rather than dropped.
_KNOWN_ENGINES = (
    "3D", "Compute", "Copy", "VideoDecode", "VideoEncode", "VideoProcessing",
    "Security", "Overlay", "Sensor",
)

_ENGINE_LABELS = {
    "3D": "3D",
    "Compute": "Compute",
    "Copy": "Copy",
    "VideoDecode": "Video decode",
    "VideoEncode": "Video encode",
    "VideoProcessing": "Video processing",
    "Security": "Security",
    "Overlay": "Overlay",
    "Sensor": "Sensor",
}


class GpuCollector:
    def __init__(self, adapters: list[dict[str, object]] | None = None) -> None:
        self.adapters = adapters or []
        self.query = pdh.PdhQuery("gpu")
        # One full wildcard rather than one counter per engine class: fewer
        # counters to collect, and the engine class is in the instance name.
        self.has_engine = self.query.add(
            "engine", r"\GPU Engine(*)\Utilization Percentage", array=True
        )
        self.has_proc_mem = self.query.add(
            "proc_dedicated", r"\GPU Process Memory(*)\Dedicated Usage",
            fmt="large", array=True,
        )
        self.query.add(
            "proc_shared", r"\GPU Process Memory(*)\Shared Usage",
            fmt="large", array=True,
        )
        self.query.add(
            "adapter_dedicated", r"\GPU Adapter Memory(*)\Dedicated Usage",
            fmt="large", array=True,
        )
        self.query.add(
            "adapter_shared", r"\GPU Adapter Memory(*)\Shared Usage",
            fmt="large", array=True,
        )
        self.query.add(
            "adapter_committed", r"\GPU Adapter Memory(*)\Total Committed",
            fmt="large", array=True,
        )
        # First collect on a ~600-instance wildcard costs ~550ms while PDH
        # enumerates instances. Paid once, here, during startup warm-up.
        self.query.collect()
        # Latest per-PID view, consumed by the process collector on its own tick.
        self.per_pid: dict[int, dict[str, float]] = {}

    @property
    def available(self) -> bool:
        return self.has_engine

    @property
    def reason(self) -> str | None:
        if self.has_engine:
            return None
        return self.query.unavailable.get(
            "engine", "GPU performance counters are not present on this system"
        )

    def sample(self) -> dict[str, object]:
        if not self.has_engine:
            return {
                "available": False,
                "reason": self.reason,
                "backends_tried": {"pdh-gpu-engine": self.reason},
                "adapters": self.adapters,
                "total": None,
                "engines": [],
                "process_count": 0,
            }

        self.query.collect()
        engine_raw = self.query.array("engine")

        # (luid, phys, eng, engtype) -> summed utilisation across processes
        engines: dict[tuple[str, str, str, str], float] = defaultdict(float)
        # pid -> engtype -> summed utilisation
        by_pid: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))

        for instance, value in engine_raw.items():
            if value <= 0.0:
                continue
            parsed = pdh.parse_gpu_instance(instance)
            if not parsed:
                continue
            engtype = parsed.get("engtype") or "other"
            if engtype not in _KNOWN_ENGINES:
                engtype = "other"
            key = (
                parsed.get("luid") or "?",
                parsed.get("phys") or "0",
                parsed.get("eng") or "0",
                engtype,
            )
            engines[key] += value
            try:
                by_pid[int(parsed["pid"])][engtype] += value
            except (KeyError, TypeError, ValueError):
                pass

        # Engine class -> max across the physical engines of that class.
        class_util: dict[str, float] = defaultdict(float)
        # LUID -> max across all its engine classes, i.e. that adapter's load.
        adapter_util: dict[str, float] = defaultdict(float)
        for (luid, _phys, _eng, engtype), value in engines.items():
            bounded = clamp(value)
            class_util[engtype] = max(class_util[engtype], bounded)
            adapter_util[luid] = max(adapter_util[luid], bounded)

        self.per_pid = {
            pid: {
                "total": round(clamp(max(per_engine.values())), 2),
                "engines": {k: round(clamp(v), 2) for k, v in per_engine.items()},
            }
            for pid, per_engine in by_pid.items()
            if per_engine
        }

        memory = self._memory()
        overall = round(max(class_util.values()), 2) if class_util else 0.0

        engine_list = [
            {
                "key": key,
                "label": _ENGINE_LABELS.get(key, key.title()),
                "utilization": round(value, 2),
            }
            for key, value in sorted(class_util.items(), key=lambda kv: -kv[1])
            if value > 0.005
        ]

        adapters = []
        for index, adapter in enumerate(self.adapters or [{"name": "GPU"}]):
            entry = dict(adapter)
            # Adapter identity in WMI and in PDH instance names cannot be joined
            # reliably (no shared LUID field), so a single-GPU machine -- the
            # overwhelming majority -- gets the aggregate, and multi-GPU boxes
            # get per-LUID rows listed separately below.
            entry["utilization"] = overall if len(self.adapters) <= 1 else None
            entry.update(memory.get("adapter_totals", {}) if index == 0 else {})
            adapters.append(entry)

        return {
            "available": True,
            "reason": None,
            "backend": "pdh-gpu-engine",
            "total": overall,
            "engines": engine_list,
            "adapters": adapters,
            "per_luid": [
                {"luid": luid, "utilization": round(value, 2)}
                for luid, value in sorted(adapter_util.items(), key=lambda kv: -kv[1])
            ],
            "memory": memory,
            "process_count": len(self.per_pid),
        }

    # -------------------------------------------------------------- VRAM
    def _memory(self) -> dict[str, object]:
        dedicated = self.query.array("adapter_dedicated")
        shared = self.query.array("adapter_shared")
        committed = self.query.array("adapter_committed")

        def total(values: dict[str, float]) -> int | None:
            usable = [v for k, v in values.items() if k != "_Total"]
            return int(sum(usable)) if usable else None

        proc_dedicated = self.query.array("proc_dedicated")
        proc_shared = self.query.array("proc_shared")
        per_pid_mem: dict[int, dict[str, int]] = defaultdict(
            lambda: {"dedicated": 0, "shared": 0}
        )
        for source, field in ((proc_dedicated, "dedicated"), (proc_shared, "shared")):
            for instance, value in source.items():
                parsed = pdh.parse_gpu_instance(instance)
                if not parsed:
                    continue
                try:
                    per_pid_mem[int(parsed["pid"])][field] += int(value)
                except (KeyError, TypeError, ValueError):
                    pass

        # Fold VRAM into the per-PID view the process table reads.
        for pid, mem in per_pid_mem.items():
            slot = self.per_pid.setdefault(pid, {"total": 0.0, "engines": {}})
            slot["vram_dedicated"] = mem["dedicated"]
            slot["vram_shared"] = mem["shared"]

        return {
            "adapter_totals": {
                "vram_dedicated": total(dedicated),
                "vram_shared": total(shared),
                "vram_committed": total(committed),
                # Capacity is not a PDH counter; Win32_VideoController's
                # AdapterRAM wraps at 4 GB, so it is a hint, not a budget.
                "vram_total": _capacity(self.adapters),
            },
            "process_count": len(per_pid_mem),
        }

    def close(self) -> None:
        self.query.close()


def _capacity(adapters: list[dict[str, object]]) -> int | None:
    """Sum of the adapters' reported RAM when it is trustworthy (below the
    uint32 wrap), else None -- never a wrong number dressed as a total."""
    total = 0
    for adapter in adapters or []:
        ram = adapter.get("adapter_ram")
        if not isinstance(ram, int) or ram <= 0 or ram >= 4 * 1024 ** 3 - 1:
            return None
        total += ram
    return total or None
