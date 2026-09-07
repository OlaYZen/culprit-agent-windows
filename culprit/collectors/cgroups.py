"""Per-unit pressure and limits -- not capable in Windows.

On Linux every systemd unit is a cgroup, and the kernel keeps per-cgroup
PSI, CPU quota, memory limit and pid counts for each one, which is how the
Lag Doctor names *which service* is making a machine slow. Windows has no
equivalent: services are processes in the SCM's care, Job Objects exist but
services are not placed in them, and the kernel keeps no per-service stall
accounting. So this section is honestly unavailable rather than faked from
per-process numbers -- the process table already carries `services` (what
each svchost hosts) for the attribution Windows *can* do.

The shape is the Linux collector's unavailable shape exactly, so the host
and the dashboard treat it the way they treat a Linux kernel without
cgroup v2: a one-line reason, never an empty panel.
"""

from __future__ import annotations

from .. import windows

REASON = windows.not_capable(
    "per-service pressure and limits come from Linux cgroups (PSI, cpu.max, "
    "memory.max); Windows keeps no per-service stall or limit accounting. "
    "The process table's `services` column says what each svchost hosts.")


class CgroupCollector:
    def __init__(self) -> None:
        self.available = False
        self.reason = REASON

    def sample(self, containers=None) -> dict[str, object]:  # noqa: ANN001
        return {"available": False, "reason": self.reason, "units": [],
                "total_units": 0, "sample_ms": 0.0}
