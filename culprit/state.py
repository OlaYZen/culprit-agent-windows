"""Shared snapshot store and the SSE fan-out.

The store is the seam between the sampler and the HTTP layer. Collectors write
whole payloads into it; request handlers and the SSE stream only ever read what
is already there. That is what keeps `/api/snapshot` a sub-millisecond dict
serialisation instead of a burst of syscalls per request -- an open dashboard and
ten open dashboards cost the machine exactly the same.

Fan-out is Server-Sent Events rather than WebSockets: the traffic is entirely
one-directional (server -> browser), SSE reconnects on its own, and it needs no
protocol handshake or ping/pong bookkeeping. Commands go over ordinary POST
endpoints.

Each subscriber gets a bounded queue. A browser tab that has been throttled by
the OS (backgrounded, laptop asleep) stops draining its queue; dropping the
oldest frame for that subscriber is correct, because a monitoring client wants
the *newest* state, never a backlog of stale ones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from .util import Ring

log = logging.getLogger("culprit.state")

# Frames a slow subscriber may fall behind before the oldest are discarded.
_QUEUE_DEPTH = 8


class Store:
    """Latest payload per section, plus the live ring buffer."""

    def __init__(self, live_window_seconds: float = 900.0) -> None:
        self._sections: dict[str, Any] = {}
        self.ring = Ring(live_window_seconds)
        self.started_at = time.time()
        # Set once the first fast and proc ticks have both landed, so the UI can
        # tell "still warming up" from "genuinely nothing to show".
        self.warm = False
        self.warmup_stage = "starting"
        self.errors: dict[str, str] = {}
        self.timings: dict[str, float] = {}

    # ------------------------------------------------------------------ write
    def put(self, section: str, payload: Any) -> None:
        self._sections[section] = payload

    def merge(self, payload: dict[str, Any]) -> None:
        self._sections.update(payload)

    def push_live(self, timestamp: float, sample: dict[str, Any]) -> None:
        self.ring.push(timestamp, sample)

    def set_error(self, section: str, message: str | None) -> None:
        if message:
            self.errors[section] = message
        else:
            self.errors.pop(section, None)

    def set_timing(self, section: str, milliseconds: float) -> None:
        self.timings[section] = round(milliseconds, 1)

    # ------------------------------------------------------------------- read
    def get(self, section: str, default: Any = None) -> Any:
        return self._sections.get(section, default)

    def snapshot(self) -> dict[str, Any]:
        """Everything the dashboard needs for a cold start, in one payload."""
        return {
            "warm": self.warm,
            "warmup_stage": self.warmup_stage,
            "server_started_at": self.started_at,
            "now": time.time(),
            "errors": dict(self.errors),
            "timings": dict(self.timings),
            **self._sections,
        }

    def live_series(self, keys: tuple[str, ...] = ()) -> dict[str, Any]:
        """The in-memory ring as parallel arrays, for the live sparklines."""
        timestamps: list[float] = []
        columns: dict[str, list[float | None]] = {key: [] for key in keys}
        for timestamp, sample in self.ring:
            timestamps.append(round(timestamp, 3))
            for key in keys:
                columns[key].append(_dig(sample, key))
        return {"ts": timestamps, "series": columns,
                "window_seconds": self.ring.window}


class Broker:
    """SSE subscriber registry."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self.dropped = 0

    @property
    def count(self) -> int:
        return len(self._subscribers)

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_QUEUE_DEPTH)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: str, data: Any) -> None:
        """Serialise once, hand the same string to every subscriber."""
        if not self._subscribers:
            return
        try:
            body = json.dumps(data, default=_fallback, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            log.warning("could not serialise %s frame: %s", event, exc)
            return
        frame = f"event: {event}\ndata: {body}\n\n"
        for queue in list(self._subscribers):
            while True:
                try:
                    queue.put_nowait(frame)
                    break
                except asyncio.QueueFull:
                    # Drop this subscriber's oldest frame and retry. A stalled
                    # tab must never slow down the sampler or other clients.
                    try:
                        queue.get_nowait()
                        self.dropped += 1
                    except asyncio.QueueEmpty:
                        break


def _dig(sample: Any, path: str) -> float | None:
    """'cpu.total' -> sample['cpu']['total'], or None if absent."""
    node = sample
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return float(node) if isinstance(node, (int, float)) else None


def _fallback(value: Any) -> Any:
    """Last-resort JSON encoder so one odd value cannot kill a whole frame."""
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)
