"""The flight recorder: the last ten minutes, kept on disk, for the Coroner.

Every other collector answers "what is happening now". History on the host
is rolled up per minute, which is exactly the resolution that hides how a
machine died: the memory that drained over ninety seconds, the process that
climbed for four minutes, the PSI that went to 100% twenty seconds before the
journal stopped. So the agent keeps its own black box -- a compact ring of
the last ten minutes at the sampler's own cadence (fast tier every second,
process table every proc tick) -- and writes it to disk every few seconds.

After a crash, a hang, a power cut or a kill, the file on disk is the last
few seconds before the end, and the agent finds it at its next start. The
kernel's boot id says whether the *machine* went down or only the agent; a
clean stop (SIGTERM handled) marks the file so a routine restart is never
mistaken for a death. What the file holds is then handed to the host with
the previous boot's journal (collectors/forensics.py), and the host's Coroner
delivers the verdict.

Cost: a fast frame is two dozen numbers; a proc frame is the top dozen
processes. Ten minutes is roughly 600 fast + 300 proc frames -- about 350 KB
of JSON, 40 KB gzipped, rewritten atomically every five seconds. The write
is the whole price, and it is one small file on a local disk.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any

from .. import linux

log = logging.getLogger("culprit.recorder")

WINDOW_SECONDS = 600.0
FLUSH_SECONDS = 5.0
FORMAT_VERSION = 1
# How many processes a proc frame keeps: the heaviest by lag score, then the
# biggest by memory (a leak is the classic cause of death), then any stuck.
_TOP_BY_LAG = 10
_TOP_BY_RSS = 6
_TOP_CAP = 16
_FINDINGS_CAP = 8

# The fast frame's columns, in order. Names are short on purpose: they are
# repeated per frame on disk (columnar, so once per column in the file) and
# the Coroner view maps them back to words.
FAST_COLUMNS: tuple[str, ...] = (
    "ts", "cpu", "iowait", "steal", "queue", "load", "blocked",
    "mem_pct", "mem_avail_mb", "swap_pct", "faults",
    "psi_cpu_some", "psi_mem_some", "psi_mem_full", "psi_io_some", "psi_io_full",
    "disk_busy", "disk_lat", "disk_queue", "net_rx", "net_tx", "gpu",
    "p_cpu", "p_mem", "p_disk", "throttle",
)


def boot_id() -> str | None:
    """The kernel's boot id: new on every boot, the one fact that separates
    'the machine rebooted' from 'the agent restarted'."""
    return linux.read_line("/proc/sys/kernel/random/boot_id")


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return round(float(value), 3) if value == value else None
    return None


def _psi(psi: Any, resource: str, kind: str) -> float | None:
    try:
        return _num(psi[resource][kind]["avg10"])
    except (KeyError, TypeError):
        return None


class FlightRecorder:
    def __init__(self, path: Path, window_seconds: float = WINDOW_SECONDS) -> None:
        self.path = Path(path)
        self.window = float(window_seconds)
        self.boot_id = boot_id()
        self.started_at = time.time()
        self._fast: deque[tuple] = deque()
        self._proc: deque[dict[str, Any]] = deque()
        self._last_flush = 0.0
        self.last_error: str | None = None
        self.flushes = 0

    # ------------------------------------------------------------- observe
    def observe_fast(self, sample: dict[str, Any]) -> None:
        cpu = sample.get("cpu") or {}
        mem = sample.get("memory") or {}
        psi = sample.get("psi")
        disk = (sample.get("disk") or {}).get("total") or {}
        net = (sample.get("network") or {}).get("total") or {}
        gpu = sample.get("gpu") or {}
        pressures = sample.get("pressures") or {}
        thermal = cpu.get("thermal") or {}
        ts = float(sample.get("ts") or time.time())
        frame = (
            round(ts, 3), _num(cpu.get("total")), _num(cpu.get("iowait")),
            _num(cpu.get("steal")), _num(cpu.get("queue_per_core")),
            _num(cpu.get("load_1")), _num(cpu.get("blocked")),
            _num(mem.get("percent")), _num(mem.get("available_mb")),
            _num(mem.get("swap_percent")), _num(mem.get("hard_faults_sec")),
            _psi(psi, "cpu", "some"), _psi(psi, "memory", "some"),
            _psi(psi, "memory", "full"), _psi(psi, "io", "some"),
            _psi(psi, "io", "full"),
            _num(disk.get("busy_percent")), _num(disk.get("latency_ms")),
            _num(disk.get("queue_length")),
            _num(net.get("recv_bytes_sec")), _num(net.get("sent_bytes_sec")),
            None if gpu.get("available") is False else _num(gpu.get("total")),
            _num(pressures.get("cpu")), _num(pressures.get("memory")),
            _num(pressures.get("disk")),
            _num(thermal.get("throttle_events_sec")) if thermal.get("available") else None,
        )
        self._fast.append(frame)
        self._trim(ts)

    def observe_proc(self, processes: list[dict[str, Any]],
                     diagnosis: dict[str, Any] | None) -> None:
        ts = time.time()
        chosen: dict[int, dict[str, Any]] = {}
        real = [p for p in processes if not p.get("is_kthread")]
        for proc in sorted(real, key=lambda p: -float(p.get("lag_score") or 0))[:_TOP_BY_LAG]:
            chosen[int(proc["pid"])] = proc
        for proc in sorted(real, key=lambda p: -float(p.get("working_set") or 0))[:_TOP_BY_RSS]:
            chosen.setdefault(int(proc["pid"]), proc)
        for proc in real:
            if proc.get("stuck"):
                chosen.setdefault(int(proc["pid"]), proc)
        rows = [
            [int(p["pid"]), str(p.get("name") or "?"), _num(p.get("cpu")),
             int(p.get("working_set") or 0), _num(p.get("io_bytes_sec")),
             _num(p.get("lag_score")), str(p.get("state") or "?"),
             p.get("unit") or None, bool(p.get("stuck"))]
            for p in list(chosen.values())[:_TOP_CAP]
        ]
        findings = []
        if isinstance(diagnosis, dict):
            for finding in (diagnosis.get("findings") or [])[:_FINDINGS_CAP]:
                if isinstance(finding, dict):
                    findings.append([str(finding.get("key")), str(finding.get("severity")),
                                     str(finding.get("title") or "")[:120]])
        self._proc.append({
            "ts": round(ts, 3),
            "sev": str((diagnosis or {}).get("severity") or "ok"),
            "findings": findings,
            "top": rows,
        })
        self._trim(ts)

    def _trim(self, now: float) -> None:
        cutoff = now - self.window
        while self._fast and self._fast[0][0] < cutoff:
            self._fast.popleft()
        while self._proc and float(self._proc[0]["ts"]) < cutoff:
            self._proc.popleft()

    # -------------------------------------------------------------- persist
    def maybe_flush(self, now: float | None = None) -> None:
        now = now or time.time()
        if now - self._last_flush < FLUSH_SECONDS:
            return
        self._last_flush = now
        self.flush(clean_stop=False)

    def flush(self, clean_stop: bool = False) -> bool:
        payload = {
            "version": FORMAT_VERSION,
            "boot_id": self.boot_id,
            "agent_pid": os.getpid(),
            "started_at": self.started_at,
            "written_at": time.time(),
            "clean_stop": clean_stop,
            "window_seconds": self.window,
            "fast": {"columns": list(FAST_COLUMNS),
                     "rows": [list(frame) for frame in self._fast]},
            "proc": list(self._proc),
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=3) as handle:
                json.dump(payload, handle, separators=(",", ":"))
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self.last_error = None
            self.flushes += 1
            return True
        except OSError as exc:
            # One failed write is not fatal; the next flush retries. It is
            # reported so the agent's status can say the recorder is off.
            if self.last_error != str(exc):
                log.warning("flight recorder cannot write %s: %s", self.path, exc)
            self.last_error = str(exc)
            return False

    def mark_clean_stop(self) -> None:
        """Called on SIGTERM: a routine stop is not a death."""
        self.flush(clean_stop=True)

    def status(self) -> dict[str, Any]:
        return {
            "path": str(self.path), "frames_fast": len(self._fast),
            "frames_proc": len(self._proc), "flushes": self.flushes,
            "error": self.last_error, "window_seconds": self.window,
        }


# ----------------------------------------------------------------- recovery
def read_recording(path: Path) -> dict[str, Any] | None:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, EOFError) as exc:
        if Path(path).exists():
            log.warning("flight recorder file unreadable (%s): %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def detect_death(path: Path, current_boot: str | None,
                 now: float | None = None) -> dict[str, Any] | None:
    """What the previous run left behind, if it ended badly.

    Returns None when there is no recording, when the previous run stopped
    cleanly, or when the recording is too old to say anything (the agent was
    off for a week: that is not a death, that is a machine that was off).
    """
    now = now or time.time()
    data = read_recording(path)
    if not data:
        return None
    if data.get("clean_stop"):
        return None
    written = data.get("written_at")
    if not isinstance(written, (int, float)) or written <= 0:
        return None
    prev_boot = data.get("boot_id")
    kind = "machine" if (prev_boot and current_boot and prev_boot != current_boot) else "agent"
    fast = data.get("fast") if isinstance(data.get("fast"), dict) else {}
    rows = fast.get("rows") if isinstance(fast.get("rows"), list) else []
    last_ts = float(rows[-1][0]) if rows and isinstance(rows[-1], list) and rows[-1] else float(written)
    return {
        "kind": kind,
        # The last frame is at most FLUSH_SECONDS older than the last write;
        # the death happened somewhere between the two and the next start.
        "died_at": max(last_ts, float(written)),
        "last_frame_at": last_ts,
        "written_at": float(written),
        "detected_at": now,
        "gap_seconds": round(now - float(written), 1),
        "prev_boot_id": prev_boot,
        "boot_id": current_boot,
        "agent_pid": data.get("agent_pid"),
        "recorder": {
            "version": data.get("version"),
            "window_seconds": data.get("window_seconds"),
            "started_at": data.get("started_at"),
            "written_at": float(written),
            "fast": {"columns": fast.get("columns") or list(FAST_COLUMNS), "rows": rows},
            "proc": data.get("proc") if isinstance(data.get("proc"), list) else [],
        },
    }


def summarise_frames(recording: dict[str, Any]) -> dict[str, Any]:
    """The last minute against the whole window, for the verdict: was the
    machine healthy when the record stops, or was it thrashing, stalled or
    throttled? Returns numbers; the Coroner turns them into words."""
    fast = recording.get("fast") or {}
    columns = list(fast.get("columns") or FAST_COLUMNS)
    rows = [r for r in (fast.get("rows") or []) if isinstance(r, list) and len(r) == len(columns)]
    index = {name: i for i, name in enumerate(columns)}

    def column(name: str, subset: list[list]) -> list[float]:
        i = index.get(name)
        if i is None:
            return []
        return [float(r[i]) for r in subset if isinstance(r[i], (int, float))]

    def stat(name: str, subset: list[list], fn) -> float | None:  # type: ignore[no-untyped-def]
        values = column(name, subset)
        return round(fn(values), 2) if values else None

    if not rows:
        return {"frames": 0}
    end = float(rows[-1][0])
    last_minute = [r for r in rows if float(r[0]) >= end - 60]
    first_minute = rows[: max(1, len(last_minute))]
    out: dict[str, Any] = {
        "frames": len(rows),
        "span_seconds": round(end - float(rows[0][0]), 1),
        "last_frame_at": end,
    }
    for name in ("cpu", "mem_pct", "mem_avail_mb", "swap_pct", "faults",
                 "psi_cpu_some", "psi_mem_full", "psi_mem_some", "psi_io_full",
                 "psi_io_some", "disk_lat", "load", "blocked", "throttle", "steal"):
        out[f"{name}_last"] = stat(name, last_minute, lambda v: sum(v) / len(v))
        out[f"{name}_peak"] = stat(name, rows, max)
        out[f"{name}_start"] = stat(name, first_minute, lambda v: sum(v) / len(v))
    out["mem_avail_mb_min"] = stat("mem_avail_mb", last_minute, min)
    # The process that grew the most over the window, from the proc frames:
    # the classic memory-death signature, named rather than implied.
    growth = _growth(recording.get("proc") or [])
    if growth:
        out["grew_most"] = growth
    last_proc = next((f for f in reversed(recording.get("proc") or [])
                      if isinstance(f, dict) and f.get("top")), None)
    if last_proc:
        top = sorted((r for r in last_proc["top"] if isinstance(r, list) and len(r) >= 6),
                     key=lambda r: -float(r[3] or 0))
        out["biggest_at_end"] = [{"pid": r[0], "name": r[1], "rss": r[3], "cpu": r[2]}
                                 for r in top[:3]]
        out["findings_at_end"] = last_proc.get("findings") or []
        out["severity_at_end"] = last_proc.get("sev")
    return out


def _growth(frames: list[dict[str, Any]]) -> dict[str, Any] | None:
    first: dict[int, tuple[float, int, str]] = {}
    last: dict[int, tuple[float, int, str]] = {}
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        ts = float(frame.get("ts") or 0)
        for row in frame.get("top") or []:
            if not isinstance(row, list) or len(row) < 4:
                continue
            try:
                pid, name, rss = int(row[0]), str(row[1]), int(row[3] or 0)
            except (TypeError, ValueError):
                continue
            first.setdefault(pid, (ts, rss, name))
            last[pid] = (ts, rss, name)
    best: dict[str, Any] | None = None
    for pid, (t0, rss0, name) in first.items():
        t1, rss1, _ = last[pid]
        if t1 - t0 < 60 or rss1 <= rss0:
            continue
        delta = rss1 - rss0
        if best is None or delta > best["delta"]:
            best = {"pid": pid, "name": name, "delta": delta, "from": rss0, "to": rss1,
                    "seconds": round(t1 - t0), "rate_mb_min": round(delta / 1024 ** 2 / ((t1 - t0) / 60), 1)}
    return best
