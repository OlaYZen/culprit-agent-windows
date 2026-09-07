"""Small shared helpers: rate maths, ring buffers, privilege check."""

from __future__ import annotations

import functools
import os
import time
from collections import deque
from typing import Any, Deque, Iterable


def now() -> float:
    return time.time()


def monotonic() -> float:
    return time.monotonic()


def rate(current: float | None, previous: float | None, dt: float) -> float:
    """Per-second rate from two cumulative counter readings.

    Returns 0.0 rather than a negative or absurd number when the counter has
    been reset (process restarted, adapter re-enumerated) or dt is degenerate.
    """
    if current is None or previous is None or dt <= 0:
        return 0.0
    delta = current - previous
    if delta < 0:
        return 0.0
    return delta / dt


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return low if value < low else high if value > high else value


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    return numerator / denominator if denominator else default


class Ring:
    """Fixed-duration ring buffer of (timestamp, payload) samples.

    Backs the live sparklines. Trimming is by age rather than count so the
    window stays honest when the sampling interval is changed at runtime.
    """

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._items: Deque[tuple[float, Any]] = deque()

    def push(self, timestamp: float, payload: Any) -> None:
        self._items.append((timestamp, payload))
        self.trim(timestamp)

    def trim(self, reference: float | None = None) -> None:
        cutoff = (reference if reference is not None else now()) - self.window
        items = self._items
        while items and items[0][0] < cutoff:
            items.popleft()

    def set_window(self, window_seconds: float) -> None:
        self.window = window_seconds
        self.trim()

    def since(self, timestamp: float) -> list[tuple[float, Any]]:
        return [item for item in self._items if item[0] > timestamp]

    def series(self, key: str) -> tuple[list[float], list[float | None]]:
        """Extract one metric as parallel (timestamps, values) lists for uPlot."""
        times: list[float] = []
        values: list[float | None] = []
        for timestamp, payload in self._items:
            times.append(timestamp)
            value = payload.get(key) if isinstance(payload, dict) else None
            values.append(None if value is None else float(value))
        return times, values

    def latest(self) -> Any | None:
        return self._items[-1][1] if self._items else None

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterable[tuple[float, Any]]:
        return iter(self._items)


class Sustain:
    """Counts how many consecutive ticks a condition has held.

    Used so a 100% CPU blip from opening a context menu never becomes an alert:
    a pressure state is only reported once it has survived `sustain_ticks`.
    """

    def __init__(self) -> None:
        self._streaks: dict[str, int] = {}
        self._since: dict[str, float] = {}

    def feed(self, key: str, active: bool, now: float | None = None) -> int:
        streak = self._streaks.get(key, 0)
        streak = streak + 1 if active else 0
        self._streaks[key] = streak
        if streak == 1 and now is not None:
            self._since[key] = now      # the moment the condition began
        elif streak == 0:
            self._since.pop(key, None)
        return streak

    def streak(self, key: str) -> int:
        return self._streaks.get(key, 0)

    def since(self, key: str) -> float | None:
        """Wall time the current streak started (None when not active)."""
        return self._since.get(key)

    def prune(self, prefix: str, keep: set[str]) -> None:
        """Drop keys with `prefix` that are not in `keep` -- per-unit keys
        would otherwise accumulate for every transient unit that ever ran."""
        for key in [k for k in self._streaks if k.startswith(prefix) and k not in keep]:
            del self._streaks[key]
            self._since.pop(key, None)


@functools.lru_cache(maxsize=1)
def is_elevated() -> bool:
    """True when running as root.

    Linux privilege is granular (groups, capabilities), so most gating is done
    per-source with a named group or capability -- see `linux.capabilities()`
    and `linux.journal_access()`. This coarse check only covers the few things
    that genuinely need root: DMI serials, btmp, SMART.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def human_bytes(value: float) -> str:
    """Only used for log lines; the UI formats client-side."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"
