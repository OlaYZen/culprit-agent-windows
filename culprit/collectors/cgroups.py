"""Pressure and limits per unit: the Lag Doctor's thesis, one level down.

The machine-wide PSI in /proc/pressure says whether *anything* is stalled.
cgroup v2 keeps the same three files in every unit's directory, so the
kernel also measures stall time *inside* `nginx.service` or one container --
which is how a box that is idle overall can still have one service crawling,
and how the reason turns out to be the unit's own limit:

- `cpu.stat` counts scheduling periods in which the unit hit its CPUQuota
  (`nr_throttled` / `nr_periods`). A unit throttled in most periods is slow
  because of a cap somebody set -- possibly Culprit's own Throttle, which
  leaves a `50-CPUQuota.conf` runtime drop-in that this collector looks for.
- `memory.events` counts how often usage hit `memory.max` / `memory.high`,
  and OOM kills confined to the unit. A container thrashing against its own
  limit looks healthy from /proc/meminfo.
- `*.pressure` inside the unit says its tasks are stalled even when the
  machine's aggregate is quiet.

Runs on the proc tier (2s): every unit directory under /sys/fs/cgroup, the
three pressure files each tick and the counters only where a limit exists;
the limits themselves (cpu.max, memory.max, ...) change rarely and are
re-read every tenth tick. ~10ms for ~50 units on the target. Only units with
something to say (a limit, a stall, a throttle, a memory event) are emitted,
so the payload stays a few KB. Container scopes are included and named through
the same resolver the process table uses.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .. import linux
from .containers import identify

_UNIT_SUFFIXES = (".service", ".scope")
_MAX_DIRS = 2500
_MAX_DEPTH = 8
_EMIT_CAP = 80

# Where `systemctl set-property --runtime` leaves its drop-ins. A cap that
# lives here is gone after a reboot -- and is exactly what Culprit's Throttle
# creates, so a finding can say so instead of blaming a mystery limit.
_RUNTIME_DIRS_SYSTEM = ("/run/systemd/system.control", "/run/systemd/transient")


class CgroupCollector:
    def __init__(self) -> None:
        # cgroup path -> (monotonic, nr_periods, nr_throttled, throttled_usec,
        #                 mem_max_events, mem_high_events, oom_kill)
        self._prev: dict[str, tuple[float, int, int, int, int, int, int]] = {}
        # cgroup path -> the rarely-changing limits, refreshed every tenth
        # tick (a new unit is read on its first appearance).
        self._limits: dict[str, dict[str, object]] = {}
        self._tick = 0
        self.available = linux.cgroup_version() == 2
        self.reason = (None if self.available else
                       "per-unit pressure and limits need the cgroup v2 "
                       "unified hierarchy (systemd.unified_cgroup_hierarchy=1)")

    def sample(self, containers: object = None) -> dict[str, object]:
        """`containers` is the process collector's ContainerResolver (or None)
        so container scopes carry the same name/image the process table shows."""
        started = time.perf_counter()
        if not self.available:
            return {"available": False, "reason": self.reason, "units": [],
                    "total_units": 0, "sample_ms": 0.0}
        now = time.monotonic()
        units: list[dict[str, object]] = []
        total = 0
        seen: set[str] = set()
        refresh = self._tick % 10 == 0
        self._tick += 1
        for path, rel in _walk(linux.CGROUP_ROOT):
            total += 1
            seen.add(rel)
            if refresh or rel not in self._limits:
                self._limits[rel] = _read_limits(path, path.name, rel)
            entry = self._read_unit(path, rel, now, containers, self._limits[rel])
            if entry is not None:
                units.append(entry)
        # Forget counters of units that vanished, so a reused path (a
        # restarted transient unit) never gets a negative delta.
        for gone in [k for k in self._prev if k not in seen]:
            del self._prev[gone]
        for gone in [k for k in self._limits if k not in seen]:
            del self._limits[gone]
        units.sort(key=lambda u: (-float(u.get("worst_stall") or 0.0),
                                  -float(u.get("throttled_pct") or 0.0),
                                  str(u["unit"])))
        return {
            "available": True,
            "reason": None,
            "units": units[:_EMIT_CAP],
            "total_units": total,
            "emitted": min(len(units), _EMIT_CAP),
            "sample_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    # ------------------------------------------------------------------ unit
    def _read_unit(self, path: Path, rel: str, now: float,
                   containers: object,
                   limits: dict[str, object]) -> dict[str, object] | None:
        name = path.name
        container_ident = identify("/" + rel)
        quota_pct = limits.get("cpu_quota_pct")
        memory_max = limits.get("memory_max")
        memory_high = limits.get("memory_high")
        pids_max = limits.get("pids_max")
        # Counters are only worth reading where a limit can be hit; a unit
        # without a quota never throttles and its memory.events stay zero.
        cpu_stat = (linux.parse_kv_file(path / "cpu.stat", sep=" ")
                    if quota_pct is not None else {})
        mem_events = (linux.parse_kv_file(path / "memory.events", sep=" ")
                      if memory_max is not None or memory_high is not None
                      or container_ident else {})
        periods = _int(cpu_stat.get("nr_periods"))
        throttled = _int(cpu_stat.get("nr_throttled"))
        throttled_usec = _int(cpu_stat.get("throttled_usec"))
        ev_max = _int(mem_events.get("max"))
        ev_high = _int(mem_events.get("high"))
        oom_kill = _int(mem_events.get("oom_kill"))

        prev = self._prev.get(rel)
        self._prev[rel] = (now, periods, throttled, throttled_usec, ev_max,
                           ev_high, oom_kill)
        throttled_pct: float | None = None
        throttled_ms_sec: float | None = None
        limit_hits_sec = 0.0
        high_hits_sec = 0.0
        oom_new = 0
        if prev and now > prev[0]:
            dt = now - prev[0]
            d_periods = periods - prev[1]
            if d_periods > 0:
                throttled_pct = round(100.0 * max(0, throttled - prev[2]) / d_periods, 1)
                throttled_ms_sec = round(max(0, throttled_usec - prev[3]) / 1000.0 / dt, 1)
            limit_hits_sec = max(0, ev_max - prev[4]) / dt
            high_hits_sec = max(0, ev_high - prev[5]) / dt
            oom_new = max(0, oom_kill - prev[6])

        psi: dict[str, float | None] = {}
        worst_stall = 0.0
        for resource in ("cpu", "memory", "io"):
            block = linux.read_psi(path / f"{resource}.pressure")
            for kind in ("some", "full"):
                value = None
                if block and kind in block:
                    raw = block[kind].get("avg10")
                    value = float(raw) if isinstance(raw, (int, float)) else None
                psi[f"{resource}_{kind}"] = value
                if value is not None and (kind == "full" or resource == "cpu"):
                    worst_stall = max(worst_stall, value)

        memory_bytes = (linux.read_int(path / "memory.current")
                        if memory_max is not None or memory_high is not None
                        or worst_stall > 0 else None)
        pids = linux.read_int(path / "pids.current") if pids_max is not None else None

        # systemd gives every service a TasksMax, so pids.max alone says
        # nothing; it counts once the unit is actually near it.
        pids_near = (pids is not None and pids_max is not None
                     and pids_max > 0 and pids / pids_max >= 0.8)
        notable = (
            worst_stall > 0.0 or quota_pct is not None or memory_max is not None
            or memory_high is not None or pids_near
            or (throttled_pct or 0) > 0 or limit_hits_sec > 0 or high_hits_sec > 0
            or oom_new > 0 or oom_kill > 0
        )
        if not notable:
            return None

        manager = "user" if "user@" in rel else "system"
        entry: dict[str, object] = {
            "unit": name,
            "cgroup": "/" + rel,
            "manager": manager,
            "kind": ("container" if container_ident else
                     "scope" if name.endswith(".scope") else "service"),
            "container": None,
            "psi": psi,
            "worst_stall": round(worst_stall, 2),
            # CPU quota as systemd states it (percent of ONE core) and as a
            # share of this machine, which is what people mean by "half".
            "cpu_quota_pct": quota_pct,
            "cpu_quota_machine_pct": (None if quota_pct is None else
                                      round(quota_pct / (os.cpu_count() or 1), 1)),
            "throttled_pct": throttled_pct,
            "throttled_ms_sec": throttled_ms_sec,
            "runtime_cap": bool(limits.get("runtime_cap")),
            "memory_bytes": memory_bytes,
            "memory_max": memory_max,
            "memory_high": memory_high,
            "memory_limit_pct": (round(100.0 * memory_bytes / memory_max, 1)
                                 if memory_bytes is not None and memory_max
                                 else None),
            "limit_hits_sec": round(limit_hits_sec, 2),
            "high_hits_sec": round(high_hits_sec, 2),
            "oom_kills": oom_kill,
            "oom_kills_new": oom_new,
            "pids": pids,
            "pids_max": pids_max,
        }
        if container_ident and containers is not None:
            try:
                entry["container"] = containers.entry(*container_ident)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 -- a resolver hiccup is not a reason to drop the unit
                entry["container"] = {"runtime": container_ident[0],
                                      "id": container_ident[1], "name": None}
        elif container_ident:
            entry["container"] = {"runtime": container_ident[0],
                                  "id": container_ident[1], "name": None}
        return entry


# ------------------------------------------------------------------ helpers
def _read_limits(path: Path, name: str, rel: str) -> dict[str, object]:
    """The rarely-changing part of a unit: quota, memory ceilings, pids cap,
    and whether the quota is a runtime drop-in."""
    manager = "user" if "user@" in rel else "system"
    quota_pct = _quota_pct(linux.read_line(path / "cpu.max"))
    return {
        "cpu_quota_pct": quota_pct,
        "memory_max": _limit(linux.read_line(path / "memory.max")),
        "memory_high": _limit(linux.read_line(path / "memory.high")),
        "pids_max": _limit(linux.read_line(path / "pids.max")),
        "runtime_cap": (quota_pct is not None
                        and _runtime_cap(name, manager, rel)),
    }


def _walk(root: Path):
    """Every unit directory (service, scope, container) under the cgroup
    root, depth- and count-limited. Slices are descended, not reported."""
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]
    count = 0
    while stack:
        base, rel, depth = stack.pop()
        try:
            entries = list(os.scandir(base))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            count += 1
            if count > _MAX_DIRS:
                return
            child_rel = f"{rel}/{entry.name}" if rel else entry.name
            path = Path(entry.path)
            is_unit = entry.name.endswith(_UNIT_SUFFIXES) or identify("/" + child_rel) is not None
            if is_unit:
                yield path, child_rel
            if depth + 1 < _MAX_DEPTH:
                stack.append((path, child_rel, depth + 1))


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _limit(value: str | None) -> int | None:
    """'max' -> None (no limit); a number -> the number."""
    if not value or value.strip() == "max":
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _quota_pct(cpu_max: str | None) -> float | None:
    """'50000 100000' -> 50.0 (of one CPU); 'max 100000' / None -> None."""
    if not cpu_max:
        return None
    parts = cpu_max.split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        return round(100.0 * int(parts[0]) / int(parts[1]), 1)
    except (ValueError, ZeroDivisionError):
        return None


def _runtime_cap(unit: str, manager: str, rel: str) -> bool:
    """True when the unit's CPU quota comes from a `set-property --runtime`
    drop-in (Culprit's Throttle, or an admin's `systemctl set-property`),
    which does not survive a reboot."""
    if manager == "user":
        uid = _uid_from_path(rel)
        bases = ([f"/run/user/{uid}/systemd/user.control",
                  f"/run/user/{uid}/systemd/transient"] if uid is not None else [])
    else:
        bases = list(_RUNTIME_DIRS_SYSTEM)
    for base in bases:
        if os.path.exists(f"{base}/{unit}.d/50-CPUQuota.conf"):
            return True
    return False


def _uid_from_path(rel: str) -> int | None:
    for segment in rel.split("/"):
        if segment.startswith("user@") and segment.endswith(".service"):
            try:
                return int(segment[5:-8])
            except ValueError:
                return None
    return None
