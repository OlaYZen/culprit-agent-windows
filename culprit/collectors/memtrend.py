"""The memory-fill forecast: who is going to run this machine out of memory,
and roughly when.

The disk forecast in `disks.py` fits used space over the last hour and names
the processes writing to the mount. Memory has the same shape and a worse
failure mode -- the OOM killer, not a failed write -- so this is its sibling:

* the machine: `MemAvailable` (the honest field: what can be handed out
  without swapping, page cache included) fitted by least squares over the
  last hour, at least ten minutes of it, stated as a rate and a time to
  exhaustion, with the fit quality so a burst then a plateau reads as
  "rough" instead of an ETA to the minute;
* the processes: each process's RSS over the same window, so the finding
  can say "`node` (pid 4410) grew 1.1 GB in the last 58 min, 96% of what
  the machine lost" -- the *grower*, which is not necessarily the largest
  process and not necessarily the one the OOM killer will take (that is the
  kernel's own `oom_score` ranking, carried separately);
* newcomers: a process younger than the window holding a real share of
  memory cannot be fitted yet, but it is where the memory went, and the
  change log already knows when it appeared.

Nothing here is a threshold. The ring lives in the agent, so it starts empty
after a restart and says so rather than guessing from two points. Cost: one
tuple per process every 30 s and one per machine every 10 s, and a fit over
a few hundred points on the proc tick -- well under a millisecond.

Why RSS and not PSS: PSS needs smaps_rollup per process every sample, which
is the one per-process read that costs real time on a big table. RSS
over-counts shared pages, but the *change* in a process's RSS over an hour
is dominated by its own anonymous memory, which is what a leak is.
"""

from __future__ import annotations

from collections import deque
from typing import Any

WINDOW_SECONDS = 3600.0
KEEP_SECONDS = 3600.0
MIN_SECONDS = 600.0            # ten minutes of samples before any rate is claimed
MIN_POINTS = 12
MACHINE_STEP = 10.0            # one machine point per 10 s
PROCESS_STEP = 30.0            # one point per process per 30 s
STABLE_BYTES_PER_HOUR = 64 * 1024 ** 2
GROWER_MIN_BYTES = 32 * 1024 ** 2      # a process must have grown this much to be named
GROWER_MIN_SHARE = 0.05                # ...and account for 5% of what the machine lost
NEWCOMER_MIN_SHARE = 0.02              # of total RAM, to be worth naming
MAX_GROWERS = 5
MAX_NEWCOMERS = 3
FORGET_AFTER = 120.0           # a pid unseen this long (exited) is dropped


def linear_fit(points: list[tuple[float, float]]) -> tuple[float, float] | None:
    """Least-squares (slope per second, r²) over (t, y) points; None when
    there is no time spread to fit over."""
    n = len(points)
    if n < 2:
        return None
    t0 = points[0][0]
    xs = [t - t0 for t, _ in points]
    ys = [float(y) for _, y in points]
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx <= 0:
        return None
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    syy = sum((y - mean_y) ** 2 for y in ys)
    slope = sxy / sxx
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 1.0
    return slope, r2


class MemoryTrend:
    def __init__(self) -> None:
        self._machine: deque[tuple[float, int]] = deque()
        self._machine_at = 0.0
        # (pid, create_time) -> ring of (epoch, rss); identity includes the
        # start time so a reused PID never inherits its predecessor's line.
        self._procs: dict[tuple[int, float], deque[tuple[float, int]]] = {}
        self._meta: dict[tuple[int, float], dict[str, Any]] = {}
        self._seen: dict[tuple[int, float], float] = {}
        self._procs_at = 0.0
        self._started: float | None = None

    # ---------------------------------------------------------------- observe
    def observe(self, now: float, memory: dict | None, processes: list[dict]) -> None:
        if self._started is None:
            self._started = now
        available = (memory or {}).get("available")
        if isinstance(available, (int, float)) and now - self._machine_at >= MACHINE_STEP:
            self._machine_at = now
            self._machine.append((now, int(available)))
            cutoff = now - KEEP_SECONDS
            while self._machine and self._machine[0][0] < cutoff:
                self._machine.popleft()
        if now - self._procs_at < PROCESS_STEP:
            return
        self._procs_at = now
        cutoff = now - KEEP_SECONDS
        for proc in processes:
            if proc.get("is_kthread"):
                continue
            rss = proc.get("working_set")
            pid = proc.get("pid")
            if not isinstance(rss, (int, float)) or not isinstance(pid, int):
                continue
            key = (pid, float(proc.get("create_time") or 0.0))
            ring = self._procs.get(key)
            if ring is None:
                ring = self._procs[key] = deque()
            ring.append((now, int(rss)))
            while ring and ring[0][0] < cutoff:
                ring.popleft()
            self._seen[key] = now
            self._meta[key] = {
                "pid": pid, "name": proc.get("name"), "unit": proc.get("unit"),
                "container": proc.get("container"), "username": proc.get("username"),
                "working_set": int(rss),
                "elapsed_seconds": proc.get("elapsed_seconds"),
            }
        for key in [k for k, at in self._seen.items() if now - at > FORGET_AFTER]:
            self._procs.pop(key, None)
            self._meta.pop(key, None)
            self._seen.pop(key, None)

    # --------------------------------------------------------------- forecast
    def forecast(self, now: float, total_ram: int | None = None) -> dict[str, Any]:
        window = [(t, a) for t, a in self._machine if t >= now - WINDOW_SECONDS]
        span = (window[-1][0] - window[0][0]) if len(window) >= 2 else 0.0
        base: dict[str, Any] = {"ts": now, "window_seconds": round(span), "samples": len(window)}
        if span < MIN_SECONDS or len(window) < MIN_POINTS:
            return {**base, "available": False,
                    "reason": (f"forecasting after {int(MIN_SECONDS // 60)} min of samples "
                               f"({span / 60:.0f} min so far)"
                               + (" -- the record restarts with the agent" if span < 60 else ""))}
        fit = linear_fit([(t, float(a)) for t, a in window])
        if fit is None:
            return {**base, "available": False, "reason": "no time spread in the samples"}
        slope, r2 = fit                       # bytes of MemAvailable per second
        available = window[-1][1]
        per_hour = slope * 3600.0
        if abs(per_hour) < STABLE_BYTES_PER_HOUR:
            trend = "stable"
        else:
            trend = "shrinking" if slope < 0 else "growing"
        seconds_to_exhaust = (available / -slope) if slope < 0 and available > 0 else None
        lost = float(window[0][1] - available)    # positive when available fell
        growers = self._growers(now, lost)
        return {
            **base,
            "available": True,
            "trend": trend,
            "available_bytes": available,
            "rate_bytes_sec": round(slope, 1),
            "bytes_per_hour": round(per_hour),
            "seconds_to_exhaust": (round(seconds_to_exhaust)
                                   if seconds_to_exhaust is not None else None),
            "r2": round(r2, 3),
            "delta_bytes": int(available - window[0][1]),
            "growers": growers,
            "newcomers": self._newcomers(total_ram),
        }

    def _growers(self, now: float, lost: float) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key, ring in self._procs.items():
            points = [(t, r) for t, r in ring if t >= now - WINDOW_SECONDS]
            if len(points) < 3:
                continue
            span = points[-1][0] - points[0][0]
            if span < MIN_SECONDS:
                continue
            growth = points[-1][1] - points[0][1]
            if growth < GROWER_MIN_BYTES:
                continue
            fit = linear_fit([(t, float(r)) for t, r in points])
            if fit is None or fit[0] <= 0:
                continue
            share = (growth / lost) if lost > 0 else None
            if share is not None and share < GROWER_MIN_SHARE:
                continue
            meta = self._meta.get(key) or {}
            out.append({
                **meta,
                "growth_bytes": int(growth),
                "rate_bytes_sec": round(fit[0], 1),
                "window_seconds": round(span),
                "r2": round(fit[1], 3),
                # Its growth against what the machine lost over the same
                # window; above 1.0 when other processes freed memory
                # meanwhile, which is said rather than clipped.
                "share_of_loss": (round(share, 3) if share is not None else None),
            })
        out.sort(key=lambda g: -float(g["rate_bytes_sec"]))
        return out[:MAX_GROWERS]

    def _newcomers(self, total_ram: int | None) -> list[dict[str, Any]]:
        if not total_ram:
            return []
        out = []
        for key, meta in self._meta.items():
            elapsed = meta.get("elapsed_seconds")
            rss = meta.get("working_set") or 0
            if not isinstance(elapsed, (int, float)) or elapsed >= WINDOW_SECONDS:
                continue
            if rss < total_ram * NEWCOMER_MIN_SHARE:
                continue
            ring = self._procs.get(key)
            span = (ring[-1][0] - ring[0][0]) if ring and len(ring) >= 2 else 0.0
            if span >= MIN_SECONDS:
                continue                # old enough to be fitted: a grower, or not
            out.append({**meta, "share_of_ram": round(rss / total_ram, 3)})
        out.sort(key=lambda n: -int(n.get("working_set") or 0))
        return out[:MAX_NEWCOMERS]
