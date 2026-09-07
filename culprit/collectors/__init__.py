"""Data collectors.

Each module owns one domain and exposes a small class with a `collect()` (or
`sample()`) method. Collectors are stateful on purpose: rate metrics need the
previous reading, and psutil's `Process.cpu_percent()` is only meaningful when
called repeatedly on a *retained* Process object.

All of them are written to degrade rather than raise. A collector that cannot
read its source returns a payload with `available: False` and a `reason`, which
the UI renders as an explicit unavailable state.
"""
