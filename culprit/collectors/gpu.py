"""GPU utilisation and VRAM, per adapter and (where the driver allows) per PID.

Windows had one uniform per-process GPU API across all vendors; Linux does not,
so this is a `GpuBackend` chain with honest degradation. Backends are probed in
order of coverage and the first one that works wins; if none do, the payload
says exactly why for each.

1. **DRM fdinfo** (cross-vendor, kernel >= ~5.19): /proc/<pid>/fdinfo/<fd> for
   DRM fds exposes `drm-engine-<name>` busy-nanoseconds -- diffed over the
   interval for a percentage. This is what nvtop and modern intel_gpu_top use.
   Completeness varies by driver, and reading other users' fdinfo is
   permission-gated just like /proc/<pid>/io.
2. **NVML** (`pynvml`, optional dependency) for NVIDIA: adapter utilisation,
   VRAM, and per-process memory via the compute/graphics process lists.
3. **amdgpu sysfs**: /sys/class/drm/card*/device/gpu_busy_percent and the
   mem_info_vram_* files. Adapter-level only.

On the dev VM (QEMU virtual display, NVIDIA driver not loaded) all three
degrade, which exercised every unavailable path.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict

from .. import linux
from ..util import clamp

log = logging.getLogger("culprit.gpu")


class GpuCollector:
    def __init__(self, adapters: list[dict[str, object]] | None = None) -> None:
        self.adapters = adapters or []
        self.per_pid: dict[int, dict[str, float]] = {}
        self.backend: _Backend | None = None
        self.reasons: dict[str, str] = {}
        for candidate in (_FdinfoBackend(), _NvmlBackend(), _AmdSysfsBackend()):
            reason = candidate.probe()
            if reason is None:
                self.backend = candidate
                break
            self.reasons[candidate.name] = reason

    @property
    def available(self) -> bool:
        return self.backend is not None

    @property
    def reason(self) -> str | None:
        if self.backend is not None:
            return None
        if not self.reasons:
            return "no GPU backend probed"
        return "; ".join(f"{name}: {why}" for name, why in self.reasons.items())

    def sample(self) -> dict[str, object]:
        if self.backend is None:
            return {
                "available": False,
                "reason": self.reason,
                "backends_tried": dict(self.reasons),
                "adapters": self.adapters,
                "total": None,
                "engines": [],
                "process_count": 0,
            }
        try:
            payload = self.backend.sample()
        except Exception as exc:
            log.debug("gpu backend %s failed: %s", self.backend.name, exc)
            return {"available": False,
                    "reason": f"{self.backend.name} backend failed: {exc}",
                    "adapters": self.adapters, "total": None, "engines": []}
        self.per_pid = payload.pop("_per_pid", {})
        payload.setdefault("adapters", self.adapters)
        payload["available"] = True
        payload["reason"] = None
        payload["backend"] = self.backend.name
        payload["process_count"] = len(self.per_pid)
        return payload

    def close(self) -> None:
        if self.backend is not None:
            self.backend.close()


# ------------------------------------------------------------------- backends
class _Backend:
    name = "?"

    def probe(self) -> str | None:
        """None if usable, else the reason it is not."""
        raise NotImplementedError

    def sample(self) -> dict[str, object]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class _FdinfoBackend(_Backend):
    """Cross-vendor per-process engine time from DRM fdinfo."""

    name = "drm-fdinfo"

    def __init__(self) -> None:
        # (pid, client_id, engine) -> (monotonic, busy_ns)
        self._prev: dict[tuple[int, str, str], tuple[float, int]] = {}

    def probe(self) -> str | None:
        try:
            cards = [c for c in os.listdir("/sys/class/drm")
                     if c.startswith("card") and c[4:].isdigit()]
        except OSError:
            cards = []
        if not cards:
            return "no DRM devices under /sys/class/drm"
        # A device counts only if some readable fdinfo actually exposes
        # drm-engine counters; virtual displays (like this VM's) do not.
        found = self._collect_raw(limit_pids=400)
        if not found:
            return ("no process exposes drm-engine-* fdinfo counters (virtual "
                    "display, pre-5.19 kernel, or the driver does not "
                    "implement them)")
        return None

    def sample(self) -> dict[str, object]:
        now = time.monotonic()
        raw = self._collect_raw()
        by_pid: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        engine_util: dict[str, float] = defaultdict(float)
        vram_by_pid: dict[int, int] = defaultdict(int)

        for (pid, client, engine), (busy_ns, vram) in raw.items():
            key = (pid, client, engine)
            prev = self._prev.get(key)
            self._prev[key] = (now, busy_ns)
            if vram:
                vram_by_pid[pid] = max(vram_by_pid[pid], vram)
            if not prev or now <= prev[0]:
                continue
            pct = clamp(100.0 * (busy_ns - prev[1]) / ((now - prev[0]) * 1e9))
            by_pid[pid][engine] += pct
            engine_util[engine] += pct

        for key in set(self._prev) - set(raw):
            self._prev.pop(key, None)

        per_pid = {
            pid: {"total": round(clamp(max(engines.values())), 2),
                  "engines": {k: round(clamp(v), 2) for k, v in engines.items()},
                  "vram_dedicated": vram_by_pid.get(pid, 0)}
            for pid, engines in by_pid.items() if engines
        }
        total = round(max((clamp(v) for v in engine_util.values()), default=0.0), 2)
        return {
            "total": total,
            "engines": [
                {"key": key, "label": key.title(), "utilization": round(clamp(v), 2)}
                for key, v in sorted(engine_util.items(), key=lambda kv: -kv[1])
                if v > 0.005
            ],
            "memory": {"adapter_totals": {}},
            "_per_pid": per_pid,
        }

    def _collect_raw(self, limit_pids: int | None = None
                     ) -> dict[tuple[int, str, str], tuple[int, int]]:
        """Walk readable /proc/<pid>/fdinfo entries for DRM counters.

        Only fds pointing at /dev/dri/* are opened, found by readlink first --
        reading every fdinfo of every process would be an order of magnitude
        more file IO for nothing.
        """
        out: dict[tuple[int, str, str], tuple[int, int]] = {}
        count = 0
        try:
            pids = [int(n) for n in os.listdir("/proc") if n.isdigit()]
        except OSError:
            return out
        for pid in pids:
            if limit_pids is not None and count >= limit_pids:
                break
            count += 1
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue  # other user's process; counted by the process tier
            for fd in fds:
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if not target.startswith("/dev/dri/"):
                    continue
                info = linux.parse_kv_file(f"/proc/{pid}/fdinfo/{fd}")
                client = info.get("drm-client-id", fd)
                vram = 0
                mem = info.get("drm-memory-vram") or info.get("drm-total-vram")
                if mem and mem.split()[0].isdigit():
                    vram = int(mem.split()[0]) * 1024  # reported in KiB
                for key, value in info.items():
                    if not key.startswith("drm-engine-"):
                        continue
                    engine = key.removeprefix("drm-engine-")
                    try:
                        busy_ns = int(value.split()[0])
                    except (ValueError, IndexError):
                        continue
                    slot = (pid, client, engine)
                    # A process can hold several fds to one DRM client;
                    # keep the max, not the sum, or it double-counts.
                    if slot not in out or out[slot][0] < busy_ns:
                        out[slot] = (busy_ns, vram)
        return out


class _NvmlBackend(_Backend):
    name = "nvml"

    def __init__(self) -> None:
        self._nvml = None
        self._handles: list = []

    def probe(self) -> str | None:
        try:
            import pynvml  # optional, lazily imported
        except ImportError:
            return "pynvml is not installed (pip install nvidia-ml-py)"
        try:
            pynvml.nvmlInit()
        except Exception as exc:
            return f"NVML init failed: {exc} (NVIDIA driver not loaded?)"
        self._nvml = pynvml
        count = pynvml.nvmlDeviceGetCount()
        if count == 0:
            return "NVML reports no devices"
        self._handles = [pynvml.nvmlDeviceGetHandleByIndex(i) for i in range(count)]
        return None

    def sample(self) -> dict[str, object]:
        nvml = self._nvml
        adapters = []
        per_pid: dict[int, dict[str, float]] = {}
        total = 0.0
        vram_used = vram_total = 0
        for handle in self._handles:
            util = nvml.nvmlDeviceGetUtilizationRates(handle)
            mem = nvml.nvmlDeviceGetMemoryInfo(handle)
            name = nvml.nvmlDeviceGetName(handle)
            if isinstance(name, bytes):
                name = name.decode()
            total = max(total, float(util.gpu))
            vram_used += mem.used
            vram_total += mem.total
            adapters.append({"name": name, "utilization": float(util.gpu),
                             "vram_dedicated": mem.used, "vram_total": mem.total,
                             "integrated": False})
            for getter in (nvml.nvmlDeviceGetComputeRunningProcesses,
                           nvml.nvmlDeviceGetGraphicsRunningProcesses):
                try:
                    for proc in getter(handle):
                        slot = per_pid.setdefault(
                            proc.pid, {"total": 0.0, "engines": {},
                                       "vram_dedicated": 0})
                        used = getattr(proc, "usedGpuMemory", None)
                        if used:
                            slot["vram_dedicated"] += used
                except Exception:  # noqa: BLE001 -- per-proc list is best-effort
                    pass
        return {
            "total": round(total, 2),
            "engines": [{"key": "gpu", "label": "GPU",
                         "utilization": round(total, 2)}] if total else [],
            "adapters": adapters,
            "memory": {"adapter_totals": {"vram_dedicated": vram_used,
                                          "vram_total": vram_total}},
            "_per_pid": per_pid,
        }

    def close(self) -> None:
        if self._nvml is not None:
            try:
                self._nvml.nvmlShutdown()
            except Exception:
                pass


class _AmdSysfsBackend(_Backend):
    """amdgpu's sysfs files. Adapter totals only -- no per-PID view here."""

    name = "amdgpu-sysfs"

    def __init__(self) -> None:
        self._cards: list[str] = []

    def probe(self) -> str | None:
        try:
            for card in os.listdir("/sys/class/drm"):
                if not (card.startswith("card") and card[4:].isdigit()):
                    continue
                if os.path.exists(f"/sys/class/drm/{card}/device/gpu_busy_percent"):
                    self._cards.append(card)
        except OSError:
            pass
        if not self._cards:
            return "no /sys/class/drm/card*/device/gpu_busy_percent (not amdgpu)"
        return None

    def sample(self) -> dict[str, object]:
        adapters = []
        total = 0.0
        vram_used = vram_total = 0
        for card in self._cards:
            base = f"/sys/class/drm/{card}/device"
            busy = linux.read_int(f"{base}/gpu_busy_percent") or 0
            used = linux.read_int(f"{base}/mem_info_vram_used") or 0
            cap = linux.read_int(f"{base}/mem_info_vram_total") or 0
            total = max(total, float(busy))
            vram_used += used
            vram_total += cap
            adapters.append({"name": f"AMD GPU ({card})", "utilization": busy,
                             "vram_dedicated": used, "vram_total": cap,
                             "integrated": False})
        return {
            "total": round(total, 2),
            "engines": [{"key": "gpu", "label": "GPU",
                         "utilization": round(total, 2)}] if total else [],
            "adapters": adapters,
            "memory": {"adapter_totals": {"vram_dedicated": vram_used,
                                          "vram_total": vram_total}},
            "_per_pid": {},
        }
