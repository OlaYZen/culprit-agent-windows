"""Disk throughput, queue depth, latency and volume capacity.

Split across two cadences because the two questions are different:

* fast tick -- *is the disk the bottleneck right now?* Answered from
  /proc/diskstats deltas: await-style latency and queue depth, not throughput.
  A disk saturated at 100% busy with 2ms latency is fine; one at 40% busy with
  80ms latency is why the UI is frozen.
* slow tick -- *am I running out of space?* Mount enumeration touches the
  filesystem, and network/auto mounts can block for seconds (the same failure
  as Windows' disconnected network drives), so they are filtered before any
  statvfs call.

The %util caveat, carried over and sharpened: on multi-queue NVMe both
`ms_doing_io` (busy%) and `ios_in_progress` (queue) are much weaker signals
than on single-queue devices, because independent hardware queues overlap.
Latency is the number to lead with; the UI says so.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque

from .. import linux
from ..util import clamp

log = logging.getLogger("culprit.disks")

_SECTOR = 512  # /proc/diskstats sector counts are always 512-byte units

# Filesystems that are memory, packaging or plumbing rather than storage.
_SKIP_FSTYPES = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "ramfs", "proc", "sysfs",
    "cgroup", "cgroup2", "devpts", "securityfs", "debugfs", "tracefs",
    "pstore", "bpf", "autofs", "mqueue", "hugetlbfs", "configfs", "fusectl",
    "binfmt_misc", "rpc_pipefs", "nsfs", "efivarfs", "fuse.snapfuse",
    "fuse.portal", "fuse.gvfsd-fuse",
}
# These can block for seconds when the far end is gone; statvfs on them is how
# a monitoring tool hangs its own sampler.
_NETWORK_FSTYPES = {"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs",
                    "9p", "ceph", "glusterfs", "afs"}


class DiskCollector:
    """Fast-tick physical disk activity from /proc/diskstats."""

    def __init__(self) -> None:
        self._devices = _whole_devices()
        self._prev: dict[str, tuple[float, dict[str, int]]] = {}
        self._prev_at = 0.0
        self.sample()  # prime the deltas

    def sample(self) -> dict[str, object]:
        now = time.monotonic()
        stats = _read_diskstats(self._devices)
        disks = []
        total = {"read_bytes_sec": 0.0, "write_bytes_sec": 0.0,
                 "reads_sec": 0.0, "writes_sec": 0.0, "queue_length": 0.0,
                 "busy_ms": 0.0, "io_ms": 0.0, "ios": 0.0,
                 "read_total": 0, "write_total": 0}

        physical_count = 0
        for name, row in stats.items():
            layered = bool(self._devices.get(name, {}).get("layered"))
            prev = self._prev.get(name)
            self._prev[name] = (now, row)
            if not layered:
                total["read_total"] += row["sectors_read"] * _SECTOR
                total["write_total"] += row["sectors_written"] * _SECTOR
            if not prev or now <= prev[0]:
                continue
            dt = now - prev[0]
            d = {key: max(0, row[key] - prev[1].get(key, 0)) for key in row}

            reads = d["reads"] / dt
            writes = d["writes"] / dt
            read_bytes = d["sectors_read"] * _SECTOR / dt
            write_bytes = d["sectors_written"] * _SECTOR / dt
            ios = d["reads"] + d["writes"]
            # await, exactly as iostat computes it: total time waited divided
            # by IOs completed. The most honest "how slow is storage" number.
            latency = ((d["ms_reading"] + d["ms_writing"]) / ios) if ios else 0.0
            read_latency = (d["ms_reading"] / d["reads"]) if d["reads"] else 0.0
            write_latency = (d["ms_writing"] / d["writes"]) if d["writes"] else 0.0
            busy = clamp(100.0 * d["ms_doing_io"] / (dt * 1000.0))
            merged = (d["reads_merged"] + d["writes_merged"]) / dt

            rotational = self._devices.get(name, {}).get("rotational")
            disks.append({
                "instance": name,
                "layered": layered,
                "index": None,          # Linux disks have names, not indexes
                "letters": name,        # what the per-disk rows display
                "rotational": rotational,
                "read_bytes_sec": round(read_bytes),
                "write_bytes_sec": round(write_bytes),
                "reads_sec": round(reads, 1),
                "writes_sec": round(writes, 1),
                "queue_length": row["ios_in_progress"],
                "busy_percent": round(busy, 1),
                "latency_ms": round(latency, 2),
                "read_latency_ms": round(read_latency, 2),
                "write_latency_ms": round(write_latency, 2),
                "merged_io_sec": round(merged, 1),
            })

            if layered:
                continue  # already counted through the underlying disk
            physical_count += 1
            total["read_bytes_sec"] += read_bytes
            total["write_bytes_sec"] += write_bytes
            total["reads_sec"] += reads
            total["writes_sec"] += writes
            total["queue_length"] += row["ios_in_progress"]
            total["busy_ms"] += d["ms_doing_io"]
            total["io_ms"] += d["ms_reading"] + d["ms_writing"]
            total["ios"] += ios

        elapsed = (now - self._prev_at) if self._prev_at else 0.0
        self._prev_at = now
        device_count = max(1, physical_count)

        return {
            "available": bool(stats),
            "reason": None if stats else "/proc/diskstats listed no whole block devices",
            "disks": sorted(disks, key=lambda d: d["instance"]),
            "total": {
                "read_bytes_sec": round(total["read_bytes_sec"]),
                "write_bytes_sec": round(total["write_bytes_sec"]),
                "reads_sec": round(total["reads_sec"], 1),
                "writes_sec": round(total["writes_sec"], 1),
                "queue_length": round(total["queue_length"], 2),
                # Busy% averaged across devices so one idle disk of two reads
                # as 50%, matching what the per-disk rows show.
                "busy_percent": (
                    round(clamp(100.0 * total["busy_ms"]
                                / (elapsed * 1000.0 * device_count)), 1)
                    if elapsed and disks else None
                ),
                "latency_ms": (round(total["io_ms"] / total["ios"], 2)
                               if total["ios"] else 0.0),
                "read_total": total["read_total"],
                "write_total": total["write_total"],
            },
        }

    def close(self) -> None:
        pass


class VolumeCollector:
    """Slow-tick mount capacity + block-device identity."""

    def __init__(self) -> None:
        self._media: list[dict[str, object]] | None = None
        # mountpoint -> (epoch, used bytes) ring for the fill forecast.
        self._history: dict[str, deque[tuple[float, int]]] = {}
        # (pid, fd, path) -> (epoch, file offset) from the previous tick, so
        # each open file's write rate is the offset it advanced per second.
        self._offsets: dict[tuple[int, str, str], tuple[float, int]] = {}
        self._started = time.time()

    def sample(self, processes: list[dict] | None = None) -> dict[str, object]:
        """`processes` (the latest process table) lets each mount name the
        processes writing to it and the deleted files still held open."""
        volumes = []
        skipped = []
        seen_devices: set[str] = set()
        # A second mount of a device already reported (a btrfs subvolume
        # such as /home or /var/log, a bind mount) is not a second volume,
        # but files under it still live on that volume: remember which one,
        # so a writer under /home is charged to / and not to nothing.
        first_mount: dict[str, str] = {}
        aliases: dict[str, str] = {}
        now = time.time()
        all_mounts = _mounts()
        for mount in all_mounts:
            fstype, mountpoint, source, options = (
                mount["fstype"], mount["mountpoint"], mount["source"],
                mount["options"])
            base_type = fstype.split(".")[0]
            if fstype in _SKIP_FSTYPES or base_type in _SKIP_FSTYPES:
                continue
            if fstype in _NETWORK_FSTYPES or base_type in _NETWORK_FSTYPES:
                # statvfs on a dead NFS/CIFS mount blocks for seconds inside
                # the kernel with no way to time it out from here.
                skipped.append({"device": source,
                                "reason": f"network filesystem ({fstype}) -- "
                                          "not probed, it can hang the sampler"})
                continue
            if source in seen_devices:
                aliases[mountpoint] = first_mount[source]
                continue  # bind mounts and btrfs subvolumes repeat the device
            seen_devices.add(source)
            first_mount[source] = mountpoint
            try:
                usage = os.statvfs(mountpoint)
            except OSError as exc:
                skipped.append({"device": source, "reason": str(exc)})
                continue
            frsize = usage.f_frsize or usage.f_bsize
            total = usage.f_blocks * frsize
            if total == 0:
                continue
            # f_bavail, not f_bfree: ext4 reserves ~5% for root, and reporting
            # root's number to a user overstates what they can actually write.
            free = usage.f_bavail * frsize
            reserved = max(0, (usage.f_bfree - usage.f_bavail)) * frsize
            used = total - usage.f_bfree * frsize
            usable = used + free
            volumes.append({
                "device": source,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "opts": options,
                "readonly": "ro" in options.split(","),
                "label": _label_for(source),
                "total": total,
                "used": used,
                "free": free,
                "reserved": reserved,
                "percent": round(100.0 * used / usable, 1) if usable else 0.0,
            })
        volumes.sort(key=lambda v: v["mountpoint"])

        # Fill forecast: a least-squares slope over the last hour of samples
        # (at least ten minutes), stated as a rate and a time to full. The
        # ring lives in the agent, so it starts empty after a restart and
        # says so rather than guessing from two points.
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

        reported = {str(v["mountpoint"]) for v in volumes}
        writers, held, gated, files = _writers(
            volumes, processes or [],
            every_mount=[str(m["mountpoint"]) for m in all_mounts],
            offsets=self._offsets, now=now,
            aliases={m: v for m, v in aliases.items() if v in reported})
        for volume in volumes:
            mount = str(volume["mountpoint"])
            volume["writers"] = writers.get(mount, [])
            volume["held_deleted"] = held.get(mount, [])
            volume["files"] = files.get(mount, [])

        if self._media is None:
            self._media = _block_media()

        return {
            "volumes": volumes,
            "skipped": skipped,
            "media": self._media or [],
            "writers_gated": gated,
            "writers_note": (
                f"{gated} writing process(es) could not be attributed to a mount: "
                "their open files are not readable at this privilege level "
                "(CAP_SYS_PTRACE or root for other users' descriptors)."
                if gated else None),
            # How a file's rate is measured, stated once so the UI can say it.
            "files_method": ("the offset of each writable descriptor, read from "
                             "/proc/<pid>/fdinfo between samples: sequential "
                             "writes exactly, mmap and pwrite not at all"),
        }


# -------------------------------------------------------------------- forecast
_FORECAST_KEEP_SECONDS = 6 * 3600
_FORECAST_WINDOW_SECONDS = 3600
_FORECAST_MIN_SECONDS = 600
_STABLE_BYTES_PER_DAY = 64 * 1024 ** 2


def _forecast(ring: deque[tuple[float, int]], free: int, total: int,
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


# --------------------------------------------------------------------- writers
_WRITERS_PER_MOUNT = 5
_HELD_PER_MOUNT = 5
_FILES_PER_MOUNT = 5
_PATHS_PER_WRITER = 3
# A process with thousands of descriptors (a database, a proxy) gets its
# first N looked at; the rest are not worth the syscalls on a slow tick.
_FDINFO_PER_PROCESS = 512
_O_ACCMODE, _O_WRONLY, _O_RDWR, _O_APPEND = 0o3, 0o1, 0o2, 0o2000


def _fd_offset(pid: int, fd: str) -> tuple[int, str] | None:
    """(offset, mode) of one descriptor from /proc/<pid>/fdinfo/<fd>, where
    mode is "w" / "rw" / "r" from the open flags. None when unreadable."""
    info = linux.read_text(f"/proc/{pid}/fdinfo/{fd}")
    if not info:
        return None
    pos = flags = None
    for line in info.split("\n"):
        if line.startswith("pos:"):
            pos = line[4:].strip()
        elif line.startswith("flags:"):
            flags = line[6:].strip()
        if pos is not None and flags is not None:
            break
    if pos is None or flags is None:
        return None
    try:
        offset = int(pos)
        access = int(flags, 8) & _O_ACCMODE
    except ValueError:
        return None
    mode = "w" if access == _O_WRONLY else "rw" if access == _O_RDWR else "r"
    return offset, mode


def _writers(volumes: list[dict], processes: list[dict],
             every_mount: list[str] | None = None,
             offsets: dict[tuple[int, str, str], tuple[float, int]] | None = None,
             now: float | None = None,
             aliases: dict[str, str] | None = None,
             ) -> tuple[dict[str, list[dict]], dict[str, list[dict]], int,
                        dict[str, list[dict]]]:
    """Which processes are writing to which mount, which *files* they are
    writing (and how fast), and which deleted files are still held open
    (the space a rotated log keeps until its holder closes it).

    All of it comes from /proc/<pid>/fd: readlink names the file, and the
    descriptor's offset in fdinfo, diffed against the previous tick, is the
    bytes it advanced per second. That is exact for a sequential writer (a
    log, a backup, a download) and blind to mmap and pwrite, which move no
    offset -- so a file with no rate is listed without one, never as 0. The
    directory is readable for the caller's own processes only unless it has
    CAP_SYS_PTRACE; the gated count keeps the answer honest. `offsets` is the
    caller's memory between ticks; without it no rates are computed.
    `aliases` maps a mount that is another view of a reported volume (a btrfs
    subvolume, a bind mount) to that volume, so its files count there.
    """
    reported = {str(v["mountpoint"]) for v in volumes}
    if not reported:
        return {}, {}, 0, {}
    now = time.time() if now is None else now
    seen_keys: set[tuple[int, str, str]] = set()
    # Longest-prefix match over *every* mount (devtmpfs, proc, tmpfs too),
    # so /dev/null or a tmpfs file is never charged to the root volume
    # merely because "/" is a prefix of everything.
    mounts = sorted(set(every_mount or []) | reported | set(aliases or {}), key=len, reverse=True)

    alias = aliases or {}

    def mount_of(path: str) -> str | None:
        for mount in mounts:
            if path == mount or path.startswith(mount.rstrip("/") + "/"):
                if mount in reported:
                    return mount
                return alias.get(mount)
        return None

    writers: dict[str, list[dict]] = {}
    held: dict[str, list[dict]] = {}
    files: dict[str, list[dict]] = {}
    gated = 0
    seen_deleted: set[tuple[int, str]] = set()
    for proc in processes:
        if proc.get("is_kthread"):
            continue
        try:
            pid = int(proc.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        rate = float(proc.get("write_bytes_sec") or 0.0)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            if rate > 0:
                gated += 1
            continue
        # mount -> path -> {deleted, rate, mode}; one entry per path even
        # when several descriptors point at it (dup'd stdout/stderr).
        paths: dict[str, dict[str, dict]] = {}
        looked = 0
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if not target.startswith("/") or target.startswith("/memfd:"):
                continue                # sockets, pipes, anon inodes, memfds
            deleted = target.endswith(" (deleted)")
            if deleted:
                target = target[:-len(" (deleted)")]
            mount = mount_of(target)
            if mount is None:
                continue
            if deleted:
                key = (pid, target)
                if key not in seen_deleted:
                    seen_deleted.add(key)
                    try:
                        size = os.stat(f"{fd_dir}/{fd}").st_size
                    except OSError:
                        size = None
                    if size and size >= 1024 ** 2:
                        held.setdefault(mount, []).append({
                            "pid": pid, "name": proc.get("name"),
                            "username": proc.get("username"), "unit": proc.get("unit"),
                            "container": proc.get("container"),
                            "path": target, "size": size, "fd": int(fd),
                        })
            if rate <= 0:
                continue
            entry = paths.setdefault(mount, {}).get(target)
            if entry is None:
                entry = paths[mount][target] = {"deleted": deleted, "rate": None, "mode": None}
            if offsets is None or looked >= _FDINFO_PER_PROCESS:
                continue
            looked += 1
            read = _fd_offset(pid, fd)
            if read is None:
                continue
            offset, mode = read
            if mode == "r":
                continue                # a reader: no write rate to claim
            okey = (pid, fd, target)
            seen_keys.add(okey)
            previous = offsets.get(okey)
            offsets[okey] = (now, offset)
            if entry["mode"] is None or mode == "w":
                entry["mode"] = mode
            if previous is None:
                continue                # first sight: a rate needs two points
            then, before = previous
            if offset < before or now - then <= 0:
                continue                # rewound (truncate / seek): not a write
            advanced = (offset - before) / (now - then)
            entry["rate"] = max(float(entry["rate"] or 0.0), advanced)
        if rate > 0:
            cwd_mount = None
            try:
                cwd_mount = mount_of(os.readlink(f"/proc/{pid}/cwd"))
            except OSError:
                pass
            targets = set(paths) | ({cwd_mount} if cwd_mount and not paths else set())
            for mount in targets:
                ranked = sorted(paths.get(mount, {}).items(),
                                key=lambda kv: -float(kv[1]["rate"] or 0.0))
                writers.setdefault(mount, []).append({
                    "pid": pid, "name": proc.get("name"),
                    "username": proc.get("username"), "unit": proc.get("unit"),
                    "container": proc.get("container"),
                    "write_bytes_sec": rate,
                    "paths": [{"path": p, "deleted": e["deleted"],
                               # The offset this file advanced per second;
                               # None on first sight or for mmap/pwrite IO.
                               "rate_bytes_sec": (round(e["rate"], 1)
                                                  if e["rate"] is not None else None),
                               "mode": e["mode"]}
                              for p, e in ranked[:_PATHS_PER_WRITER]],
                    # True when only the working directory pointed here (no
                    # open file did): a weaker attribution, said as such.
                    "by_cwd": mount not in paths,
                })
                for path, entry in ranked:
                    if entry["rate"]:
                        files.setdefault(mount, []).append({
                            "path": path, "deleted": entry["deleted"],
                            "rate_bytes_sec": round(entry["rate"], 1),
                            "mode": entry["mode"], "pid": pid,
                            "name": proc.get("name"), "unit": proc.get("unit"),
                            "container": proc.get("container"),
                        })
    if offsets is not None:
        # Forget descriptors that were not seen this tick (closed, or the
        # process stopped writing), so the map never outgrows the fd table.
        for key in [k for k in offsets if k not in seen_keys]:
            del offsets[key]
    for mount, entries in writers.items():
        entries.sort(key=lambda e: -float(e["write_bytes_sec"]))
        del entries[_WRITERS_PER_MOUNT:]
    for mount, entries in held.items():
        entries.sort(key=lambda e: -int(e["size"] or 0))
        del entries[_HELD_PER_MOUNT:]
    for mount, entries in files.items():
        entries.sort(key=lambda e: -float(e["rate_bytes_sec"]))
        del entries[_FILES_PER_MOUNT:]
    return writers, held, gated, files


# --------------------------------------------------------------------- helpers
def _whole_devices() -> dict[str, dict[str, object]]:
    """Whole block devices (not partitions), minus loop/ram noise.

    /sys/block only lists whole devices, which is exactly the split needed --
    partition rows in diskstats double-count everything.
    """
    out: dict[str, dict[str, object]] = {}
    try:
        names = os.listdir("/sys/block")
    except OSError:
        return out
    for name in names:
        if name.startswith(("loop", "ram", "zram", "sr", "fd")):
            continue
        rotational = linux.read_int(f"/sys/block/{name}/queue/rotational")
        # Layered devices (dm-*, md*) sit on top of real disks; counting both
        # double-counts every IO in the totals. They stay in the per-disk rows
        # (their queue depth is real information) but are flagged out of sums.
        layered = False
        try:
            layered = bool(os.listdir(f"/sys/block/{name}/slaves"))
        except OSError:
            pass
        out[name] = {
            "rotational": bool(rotational) if rotational is not None else None,
            "layered": layered,
        }
    return out


_DISKSTAT_FIELDS = (
    "reads", "reads_merged", "sectors_read", "ms_reading",
    "writes", "writes_merged", "sectors_written", "ms_writing",
    "ios_in_progress", "ms_doing_io", "weighted_ms_doing_io",
)


def _read_diskstats(devices: dict[str, dict]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    text = linux.read_text("/proc/diskstats") or ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if name not in devices:
            continue
        try:
            values = [int(v) for v in parts[3:3 + len(_DISKSTAT_FIELDS)]]
        except ValueError:
            continue
        out[name] = dict(zip(_DISKSTAT_FIELDS, values))
    return out


def _mounts() -> list[dict[str, str]]:
    """Parse /proc/self/mountinfo -- unlike /proc/mounts it survives odd mount
    namespaces and separates the optional fields unambiguously."""
    out = []
    text = linux.read_text("/proc/self/mountinfo") or ""
    for line in text.splitlines():
        # ... mountpoint options optional... - fstype source superopts
        left, _, right = line.partition(" - ")
        left_parts = left.split()
        right_parts = right.split()
        if len(left_parts) < 6 or len(right_parts) < 2:
            continue
        out.append({
            "mountpoint": _unescape(left_parts[4]),
            "options": left_parts[5],
            "fstype": right_parts[0],
            "source": right_parts[1],
        })
    return out


def _unescape(text: str) -> str:
    """mountinfo escapes space/tab/newline/backslash as octal."""
    if "\\" not in text:
        return text
    for code, char in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"),
                       ("\\134", "\\")):
        text = text.replace(code, char)
    return text


def _label_for(source: str) -> str | None:
    try:
        for label in os.listdir("/dev/disk/by-label"):
            target = os.path.realpath(f"/dev/disk/by-label/{label}")
            if target == os.path.realpath(source):
                return _unescape(label.replace("\\x20", " "))
    except OSError:
        pass
    return None


def _block_media() -> list[dict[str, object]]:
    """Identity per whole device from lsblk, plus honest health degradation.

    smartctl/nvme-cli give real SMART data but need CAP_SYS_RAWIO or root (and
    are frequently not installed); their absence is reported as *unknown*,
    never as healthy.
    """
    payload = linux.run_json([
        "lsblk", "--json", "-d", "-b",
        "-o", "NAME,TYPE,SIZE,ROTA,MODEL,SERIAL,TRAN,REV,VENDOR",
    ])
    out: list[dict[str, object]] = []
    devices = (payload or {}).get("blockdevices") if isinstance(payload, dict) else None
    smart_reason = _smart_unavailable_reason()
    for dev in devices or []:
        if dev.get("type") != "disk" or str(dev.get("name", "")).startswith(
                ("loop", "ram", "zram")):
            continue
        rota = dev.get("rota")
        out.append({
            "index": None,
            "name": dev.get("name"),
            "model": (str(dev.get("model") or "").strip()
                      or str(dev.get("vendor") or "").strip() or None),
            "interface": dev.get("tran"),
            "media_type": ("HDD (rotational)" if rota
                           else "SSD" if rota is False else None),
            "size": dev.get("size"),
            "serial": str(dev.get("serial") or "").strip() or None,
            "firmware": str(dev.get("rev") or "").strip() or None,
            "status": None,
            "smart_reason": smart_reason,
        })
    return out


def _smart_unavailable_reason() -> str | None:
    import shutil

    if not (shutil.which("smartctl") or shutil.which("nvme")):
        return ("smartctl / nvme-cli are not installed "
                "(sudo apt install smartmontools nvme-cli)")
    if os.geteuid() != 0 and "CAP_SYS_RAWIO" not in linux.capabilities():
        return "SMART queries need CAP_SYS_RAWIO or root"
    return None
