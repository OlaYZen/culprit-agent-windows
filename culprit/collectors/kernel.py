"""The kernel's own state -- not capable in Windows.

The Linux collector reads /proc/mdstat (software RAID rebuilds), per-core
interrupt and softirq rates (an IRQ-bound core named after its device) and
explains kernel threads (kswapd, kworker, jbd2). Windows exposes none of
that to an unelevated process: Storage Spaces repair state needs the
Storage management WMI namespace and elevation, and per-core DPC/ISR time
exists only as an aggregate (`% DPC Time`, `% Interrupt Time`, which
cpu_mem already reports as `cpu.interrupt`). There are no kernel threads in
the process table either -- the closest things, `System` (pid 4) and
`Memory Compression`, are pseudo-processes the process collector flags as
`is_system`.

Returned in the Linux collector's unavailable shape so the dashboard says
so in one line. `explain()` keeps its Linux signature for the process
collector and always answers None: nothing on Windows is a kernel thread.
"""

from __future__ import annotations

from .. import windows

REASON = windows.not_capable(
    "mdstat, per-core IRQ/softirq rates and kernel-thread roles are Linux "
    "kernel interfaces; Windows reports only the aggregate interrupt and DPC "
    "time, which the CPU panel shows as `interrupt`.")


class KernelCollector:
    def __init__(self) -> None:
        self.available = False
        self.reason = REASON

    def sample(self) -> dict[str, object]:
        return {
            "available": False, "reason": self.reason,
            "mdstat": {"available": False, "reason": self.reason, "arrays": [],
                       "syncing": []},
            "irq": {"available": False, "reason": self.reason, "cores": [], "top": []},
            "sample_ms": 0.0,
        }


def explain(name: str) -> dict[str, object] | None:  # noqa: ARG001
    """Linux names kernel threads' roles; Windows has none to name."""
    return None
