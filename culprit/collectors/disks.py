"""Disk throughput, queue depth, latency and volume capacity.

Split across two cadences because the two questions are different:

* fast tick -- *is the disk the bottleneck right now?* Answered by queue depth
  and `Avg. Disk sec/Transfer` (latency), not by throughput. A disk saturated at
  100% busy with 2ms latency is fine; one at 40% busy with 80ms latency is why
  the UI is frozen.
* slow tick -- *am I running out of space?* Volume enumeration touches the
  filesystem and can block on a disconnected network drive, so it is kept off
  the hot path and network/removable drives are skipped.

The payload is the Linux agent's shape. What Windows cannot say is said as
such: there is no ext4-style root reserve (`reserved` is None), no
deleted-but-open file can exist (Windows refuses the delete, so
`held_deleted` is always empty and the truncate verb never applies), and
per-file write rates would cost `open_files()` on every process -- ~250 ms
each on Windows -- so writers are reported as gated with that reason rather
than attributed by guesswork. The fill forecast is pure arithmetic over
capacity samples and is ported from the Linux collector unchanged.
"""

from __future__ import annotations

import logging
import time
from collections import deque

import psutil

from .. import windows
from ..util import clamp
from .cpu_mem import media_rotational

log = logging.getLogger("culprit.disks")

_PHYSICAL_COUNTERS: tuple[tuple[str, str, str], ...] = (
    ("read_bytes", r"\PhysicalDisk(*)\Disk Read Bytes/sec", "double"),
    ("write_bytes", r"\PhysicalDisk(*)\Disk Write Bytes/sec", "double"),
    ("reads", r"\PhysicalDisk(*)\Disk Reads/sec", "double"),
    ("writes", r"\PhysicalDisk(*)\Disk Writes/sec", "double"),
    ("queue", r"\PhysicalDisk(*)\Current Disk Queue Length", "double"),
    ("idle", r"\PhysicalDisk(*)\% Idle Time", "double"),
    ("latency", r"\PhysicalDisk(*)\Avg. Disk sec/Transfer", "double"),
    ("read_latency", r"\PhysicalDisk(*)\Avg. Disk sec/Read", "double"),
    ("write_latency", r"\PhysicalDisk(*)\Avg. Disk sec/Write", "double"),
    ("split_io", r"\PhysicalDisk(*)\Split IO/Sec", "double"),
)


class DiskCollector:
    """Fast-tick physical disk activity."""

    def __init__(self) -> None:
        self.query = windows.PdhQuery("disk")
        for key, path, fmt in _PHYSICAL_COUNTERS:
            self.query.add(key, path, fmt=fmt, array=True)
        self.query.collect()
        self._rotational: dict[int, bool | None] = {}
        self._rotational_at = 0.0

    def sample(self) -> dict[str, object]:
        self.query.collect()
        arrays = {key: self.query.array(key) for key, _, _ in _PHYSICAL_COUNTERS}

        # PhysicalDisk instances are "0 C:" / "1 D: E:" / "_Total".
        names = sorted(
            {name for array in arrays.values() for name in array}
            - {"_Total"},
            key=_disk_sort_key,
        )
        if names and time.monotonic() - self._rotational_at > 300:
            self._rotational = _rotational_by_index()
            self._rotational_at = time.monotonic()

        disks = []
        for name in names:
            idle = arrays["idle"].get(name)
            busy = None if idle is None else clamp(100.0 - idle)
            latency = arrays["latency"].get(name)
            index = _disk_index(name)
            disks.append({
                "instance": name,
                "index": index,
                "letters": _disk_letters(name),
                "layered": False,
                "rotational": self._rotational.get(index) if index is not None else None,
                "read_bytes_sec": _num(arrays["read_bytes"].get(name)),
                "write_bytes_sec": _num(arrays["write_bytes"].get(name)),
                "reads_sec": _num(arrays["reads"].get(name), 1),
                "writes_sec": _num(arrays["writes"].get(name), 1),
                "queue_length": _num(arrays["queue"].get(name), 2),
                "busy_percent": None if busy is None else round(busy, 1),
                # PDH reports seconds; milliseconds is what people reason about.
                "latency_ms": None if latency is None else round(latency * 1000, 2),
                "read_latency_ms": _ms(arrays["read_latency"].get(name)),
                "write_latency_ms": _ms(arrays["write_latency"].get(name)),
                "split_io_sec": _num(arrays["split_io"].get(name), 1),
                # Linux counts block-layer merges; Windows counts the opposite
                # (split IO) and has no merge counter.
                "merged_io_sec": None,
            })

        totals_idle = arrays["idle"].get("_Total")
        total_latency = arrays["latency"].get("_Total")
        try:
            counters = psutil.disk_io_counters()
        except Exception:  # noqa: BLE001 -- no disks at all is a real case
            counters = None

        available = bool(names) or counters is not None
        return {
            "available": available,
            "reason": None if names else (self.query.unavailable.get("queue")
                                          or self.query.reason),
            "disks": disks,
            "total": {
                "read_bytes_sec": _num(arrays["read_bytes"].get("_Total")),
                "write_bytes_sec": _num(arrays["write_bytes"].get("_Total")),
                "reads_sec": _num(arrays["reads"].get("_Total"), 1),
                "writes_sec": _num(arrays["writes"].get("_Total"), 1),
                "queue_length": _num(arrays["queue"].get("_Total"), 2),
                "busy_percent": None if totals_idle is None
                                else round(clamp(100.0 - totals_idle), 1),
                "latency_ms": None if total_latency is None
                              else round(total_latency * 1000, 2),
                # Cumulative, for the "since boot" readout.
                "read_total": getattr(counters, "read_bytes", None),
                "write_total": getattr(counters, "write_bytes", None),
            },
        }

    def close(self) -> None:
        self.query.close()


class VolumeCollector:
    """Slow-tick volume capacity + physical drive media info."""

    def __init__(self) -> None:
        self._media: list[dict[str, object]] | None = None
        # mountpoint -> (epoch, used bytes) ring for the fill forecast.
        self._history: dict[str, deque[tuple[float, int]]] = {}

    def sample(self, processes: list[dict] | None = None) -> dict[str, object]:  # noqa: ARG002
        volumes = []
        skipped = []
        now = time.time()
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception as exc:  # noqa: BLE001
            partitions = []
            skipped.append({"device": "?", "reason": f"disk_partitions failed: {exc}"})
        for part in partitions:
            # 'cdrom' with no media, and mapped network drives that are offline,
            # both block for seconds inside disk_usage(). Filter first.
            opts = (part.opts or "").lower()
            if "cdrom" in opts or part.fstype == "":
                skipped.append({"device": part.device, "reason": "no media"})
                continue
            if _is_remote(part.device):
                skipped.append({"device": part.device,
                                "reason": "network drive -- not probed, it can hang the sampler"})
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except OSError as exc:
                skipped.append({"device": part.device, "reason": str(exc)})
                continue
            if usage.total == 0:
                continue
            volumes.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "opts": part.opts,
                "readonly": "ro" in opts.split(","),
                "label": _volume_label(part.mountpoint),
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                # NTFS keeps no root reserve; the whole free figure is usable.
                "reserved": None,
                "percent": round(usage.percent, 1),
            })
        volumes.sort(key=lambda v: v["mountpoint"])

        live = {v["mountpoint"] for v in volumes}
        for gone in [m for m in self._history if m not in live]:
            del self._history[gone]
        for volume in volumes:
            ring = self._history.setdefault(str(volume["mountpoint"]), deque())
            ring.append((now, int(volume["used"])))
            cutoff = now - _FORECAST_KEEP_SECONDS
            while ring and ring[0][0] < cutoff:
                ring.popleft()
            volume["forecast"] = _forecast(ring, int(volume["free"]),
                                           int(volume["total"]), now)
            volume["writers"] = []
            volume["held_deleted"] = []
            volume["files"] = []

        if self._media is None:
            self._media = _physical_media()

        writing = sum(1 for p in (processes or [])
                      if float(p.get("write_bytes_sec") or 0) > 0)
        return {
            "volumes": volumes,
            "skipped": skipped,
            "media": self._media or [],
            "writers_gated": writing,
            "writers_note": (
                f"{writing} writing process(es) are not attributed to a volume: "
                "naming a process's open files costs ~250 ms per process on "
                "Windows (NtQuerySystemInformation handle walk), which the slow "
                "tier cannot afford for every process. Their write rates are in "
                "the process table." if writing else None),
            "files_method": windows.not_capable(
                "per-file write rates come from /proc/<pid>/fdinfo offsets on "
                "Linux; Windows exposes no descriptor offsets to another process"),
        }


def _is_remote(device: str) -> bool:
    return device.startswith("\\\\") or device.startswith("//")


def _volume_label(mountpoint: str) -> str | None:
    if windows.win32api is None:
        return None
    try:
        # (name, serial, max_component, flags, fstype)
        return windows.win32api.GetVolumeInformation(mountpoint)[0] or None
    except Exception:
        return None


def _rotational_by_index() -> dict[int, bool | None]:
    out: dict[int, bool | None] = {}
    for row in windows.wmi_query(
            "SELECT DeviceId, MediaType FROM MSFT_PhysicalDisk",
            ("DeviceId", "MediaType"),
            namespace=r"winmgmts:\\.\root\Microsoft\Windows\Storage"):
        try:
            out[int(str(row.get("DeviceId")))] = media_rotational(row.get("MediaType"))
        except (TypeError, ValueError):
            continue
    return out


def _physical_media() -> list[dict[str, object]]:
    """Model / bus / media type per physical drive, plus the SMART flag.

    `Win32_DiskDrive.Status` and `PredictFailure` are the only failure signals a
    standard user can read; full SMART attributes need elevation and a vendor
    interface. A "Pred Fail" here is worth surfacing loudly, but its absence is
    not a clean bill of health -- `smart_reason` says so when it is unknown.
    """
    out: dict[str, dict[str, object]] = {}
    rotational = _rotational_by_index()
    for drive in windows.wmi_query(
        "SELECT DeviceID, Index, Model, InterfaceType, MediaType, Size, "
        "SerialNumber, Status, Partitions, FirmwareRevision FROM Win32_DiskDrive",
        ("DeviceID", "Index", "Model", "InterfaceType", "MediaType", "Size",
         "SerialNumber", "Status", "Partitions", "FirmwareRevision"),
    ):
        index = drive.get("Index")
        try:
            index_int = int(index)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            index_int = None
        media_type = drive.get("MediaType")
        rot = rotational.get(index_int) if index_int is not None else None
        if rot is True:
            media_type = "HDD"
        elif rot is False:
            media_type = "SSD"
        out[str(index)] = {
            "index": index_int,
            "name": str(drive.get("DeviceID") or f"PhysicalDrive{index}"),
            "model": str(drive.get("Model") or "").strip(),
            "interface": drive.get("InterfaceType"),
            "media_type": media_type,
            "size": _int(drive.get("Size")),
            "serial": str(drive.get("SerialNumber") or "").strip() or None,
            "status": drive.get("Status"),
            "partitions": drive.get("Partitions"),
            "firmware": str(drive.get("FirmwareRevision") or "").strip() or None,
            "predict_failure": None,
            "predict_reason": None,
            "smart_reason": None,
        }

    # MSStorageDriver_FailurePredictStatus lives in root\wmi and carries the
    # actual "this drive is dying" bit. Frequently access-denied unelevated, so
    # its absence means "unknown", never "healthy".
    rows = windows.wmi_query(
        "SELECT InstanceName, PredictFailure, Reason "
        "FROM MSStorageDriver_FailurePredictStatus",
        ("InstanceName", "PredictFailure", "Reason"),
        namespace=r"winmgmts:\\.\root\wmi",
    )
    matched: set[str] = set()
    for row in rows:
        instance = str(row.get("InstanceName") or "").lower()
        predict = bool(row.get("PredictFailure"))
        for key, entry in out.items():
            model = str(entry.get("model", ""))
            if model and model[:12].lower() in instance:
                entry["predict_failure"] = predict
                entry["predict_reason"] = row.get("Reason")
                matched.add(key)
    for key, entry in out.items():
        if key in matched:
            continue
        entry["smart_reason"] = (
            "the failure-prediction bit (MSStorageDriver_FailurePredictStatus) "
            "is not readable: run the agent elevated, or the drive does not report it"
            if not rows else "no failure-prediction record matched this drive's model")
    if not out:
        log.debug("Win32_DiskDrive returned nothing: %s", windows.wmi_reason())
    return list(out.values())


# -------------------------------------------------------------------- forecast
# Ported verbatim from the Linux collector: it is arithmetic over samples.
_FORECAST_KEEP_SECONDS = 6 * 3600
_FORECAST_WINDOW_SECONDS = 3600
_FORECAST_MIN_SECONDS = 600
_STABLE_BYTES_PER_DAY = 64 * 1024 ** 2


def _forecast(ring: deque[tuple[float, int]], free: int, total: int,  # noqa: ARG001
              now: float) -> dict[str, object]:
    """Least-squares slope of used bytes over the recent window."""
    window = [(t, u) for t, u in ring if t >= now - _FORECAST_WINDOW_SECONDS]
    span = (window[-1][0] - window[0][0]) if len(window) >= 2 else 0.0
    if span < _FORECAST_MIN_SECONDS or len(window) < 5:
        return {"available": False,
                "reason": f"forecasting after {_FORECAST_MIN_SECONDS // 60} min of "
                          f"samples ({span / 60:.0f} min so far)"}
    n = len(window)
    t0 = window[0][0]
    xs = [t - t0 for t, _ in window]
    ys = [float(u) for _, u in window]
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx <= 0:
        return {"available": False, "reason": "no time spread in the samples"}
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    slope = sxy / sxx                      # bytes per second
    syy = sum((y - mean_y) ** 2 for y in ys)
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 1.0
    per_day = slope * 86400.0
    if abs(per_day) < _STABLE_BYTES_PER_DAY:
        trend = "stable"
    else:
        trend = "growing" if slope > 0 else "shrinking"
    seconds_to_full = (free / slope) if slope > 0 and free > 0 else None
    return {
        "available": True,
        "trend": trend,
        "rate_bytes_sec": round(slope, 1),
        "bytes_per_day": round(per_day),
        "seconds_to_full": (round(seconds_to_full) if seconds_to_full is not None
                            else None),
        "window_seconds": round(span),
        "samples": n,
        # How straight the line is; a burst followed by a plateau scores low
        # and the UI says "erratic" instead of quoting an ETA to the minute.
        "r2": round(r2, 3),
        "delta_bytes": int(ys[-1] - ys[0]),
    }


def _disk_index(instance: str) -> int | None:
    head = instance.split(" ", 1)[0]
    try:
        return int(head)
    except ValueError:
        return None


def _disk_letters(instance: str) -> str:
    parts = instance.split(" ", 1)
    return parts[1] if len(parts) > 1 else ""


def _disk_sort_key(instance: str) -> tuple[int, str]:
    index = _disk_index(instance)
    return (index if index is not None else 999, instance)


def _num(value: float | None, digits: int = 0) -> float | None:
    if value is None:
        return None
    return round(float(value), digits) if digits else round(float(value))


def _ms(value: float | None) -> float | None:
    return None if value is None else round(float(value) * 1000, 2)


def _int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
