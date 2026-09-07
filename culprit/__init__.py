"""culprit -- live Linux health, process and event monitoring.

Layout:

    config.py            defaults + config.json overrides + validation
    linux.py             /proc, /sys, cgroup, journal and systemctl helpers
    util.py              rate maths, ring buffer, sustain counters
    state.py             shared snapshot store + SSE fan-out
    db.py                SQLite history (rollups, events, findings)
    sampler.py           the four sampling loops
    main.py              FastAPI routes
    collectors/          one module per data domain
"""

import json as _json
from pathlib import Path as _Path


def _read_version() -> str:
    """The version is a plain string in version.json at the repo root, next
    to this package, so it can be bumped without touching Python."""
    try:
        with open(_Path(__file__).resolve().parent.parent / "version.json",
                  encoding="utf-8") as fh:
            return str(_json.load(fh)["version"])
    except (OSError, ValueError, KeyError):
        return "unknown"


__version__ = _read_version()
