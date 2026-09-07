"""Container identity -- not capable in Windows (for now).

On Linux a process's cgroup path says which Docker/Podman/containerd/CRI-O
container it belongs to, and the runtime's socket names it. Windows
process containers (Docker with Windows containers, Hyper-V isolation)
leave no such mark on the process: a container's processes appear in the
host's table only for process-isolated containers, and identifying them
needs the Host Compute Service API, which is admin-only and out of scope
for a first port. Docker Desktop's Linux containers live inside a WSL2 VM
and are not in this machine's process table at all.

The resolver keeps the Linux interface (the sampler and the cgroups stub
call it) and answers "no container" for everything, with `note()` naming
why, so a `container` column is null rather than wrong.
"""

from __future__ import annotations

from .. import windows

REASON = windows.not_capable(
    "container membership is read from Linux cgroup paths; Windows containers "
    "are not identified in this port (Docker Desktop's Linux containers run "
    "inside a WSL2 VM and are not in this machine's process table).")


def identify(cgroup_path: str | None) -> tuple[str, str] | None:  # noqa: ARG001
    return None


class ContainerResolver:
    """Same surface as the Linux resolver; every answer is 'no container'."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.unresolved = 0

    def begin_tick(self) -> None:
        return None

    def resolve(self, cgroup_path: str | None) -> dict[str, object] | None:  # noqa: ARG002
        return None

    def entry(self, runtime: str, cid: str) -> dict[str, object]:
        return {"runtime": runtime, "id": cid, "name": None, "image": None,
                "service": None, "project": None}

    def forget_except(self, live_ids: set[str]) -> None:  # noqa: ARG002
        return None

    def note(self) -> str | None:
        return REASON
