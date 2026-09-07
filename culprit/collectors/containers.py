"""Name the container, not the shim.

A runaway process inside a Docker or Podman container shows up in /proc as an
opaque PID whose parent is `containerd-shim`, and a dashboard that ranks it
first has named nothing useful. The container's identity is already in the
kernel: every container is a cgroup, and the cgroup path carries the runtime
and the container id (`docker-<id>.scope` under the systemd driver, `/docker/
<id>` under cgroupfs, `libpod-<id>.scope` for Podman, `cri-containerd-<id>`
for Kubernetes). That much costs one /proc read per process lifetime and is
free of any privilege.

The *name* (and image, and compose service) lives with the runtime, behind
its socket. Reading it is a single HTTP GET over the unix socket, cached for
the container's lifetime, and gated honestly: without access to the socket the
process is still labelled with its runtime and short id, and the payload says
which group unlocks the name -- a dash-with-a-reason, never a missing label.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import socket
import time

log = logging.getLogger("culprit.containers")

# One pattern per runtime layout. The id is 64 hex chars on every runtime,
# but some layouts (LXC-style names, truncated k8s ids) are shorter; 12 is
# the floor Docker itself prints.
_PATTERNS = (
    (re.compile(r"(?:^|/)docker-([0-9a-f]{12,64})\.scope"), "docker"),
    (re.compile(r"(?:^|/)docker/([0-9a-f]{12,64})(?:/|$)"), "docker"),
    (re.compile(r"(?:^|/)libpod-([0-9a-f]{12,64})\.scope"), "podman"),
    (re.compile(r"(?:^|/)libpod-([0-9a-f]{12,64})(?:/|$)"), "podman"),
    (re.compile(r"(?:^|/)cri-containerd-([0-9a-f]{12,64})\.scope"), "containerd"),
    (re.compile(r"(?:^|/)crio-([0-9a-f]{12,64})\.scope"), "cri-o"),
    (re.compile(r"(?:^|/)kubepods[^/]*/.*?([0-9a-f]{64})(?:/|$)"), "kubernetes"),
)

# Where each runtime's API socket lives. Podman's rootless socket is per
# user; the root one is under /run.
_SOCKETS = {
    "docker": ("/var/run/docker.sock", "/run/docker.sock"),
    "podman": ("/run/podman/podman.sock",
               f"/run/user/{os.getuid()}/podman/podman.sock"),
}
_UNLOCK = {
    "docker": "read access to /var/run/docker.sock (the `docker` group, or "
              "mount the socket into the agent container)",
    "podman": "the Podman API socket (systemctl --user enable --now podman.socket)",
}

_RETRY_S = 300.0        # how long a failed lookup stays failed
_TIMEOUT_S = 1.5        # the socket call runs on the proc tick; keep it short


def identify(cgroup_path: str | None) -> tuple[str, str] | None:
    """(runtime, container id) from a cgroup path, or None outside a container."""
    if not cgroup_path:
        return None
    for pattern, runtime in _PATTERNS:
        match = pattern.search(cgroup_path)
        if match:
            return runtime, match.group(1)
    return None


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:  # noqa: D401 -- http.client hook
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


class ContainerResolver:
    """cgroup path -> {runtime, id, name, image, service, project}, cached."""

    def __init__(self) -> None:
        self._cache: dict[str, dict[str, object]] = {}
        self._failed: dict[str, tuple[float, str]] = {}     # id -> (when, why)
        # runtime -> (probed at, socket path or None, why not)
        self._socket_state: dict[str, tuple[float, str | None, str | None]] = {}
        self.unresolved = 0        # containers seen without a name this tick
        self.seen: set[str] = set()

    # ---------------------------------------------------------------- public
    def begin_tick(self) -> None:
        self.unresolved = 0
        self.seen = set()

    def resolve(self, cgroup_path: str | None) -> dict[str, object] | None:
        ident = identify(cgroup_path)
        return self.entry(*ident) if ident else None

    def entry(self, runtime: str, cid: str) -> dict[str, object]:
        """The cached record for one container. A nameless record is retried
        (cheaply: the socket and failure states are themselves cached) so a
        name that becomes readable later shows up without a restart."""
        self.seen.add(cid)
        entry = self._cache.get(cid)
        if entry is None or entry.get("name") is None:
            entry = self._lookup(runtime, cid)
            self._cache[cid] = entry
        if entry.get("name") is None:
            self.unresolved += 1
        return dict(entry)

    def forget_except(self, live_ids: set[str]) -> None:
        """Drop cache entries for containers no process belongs to any more,
        so a host that churns containers cannot grow this without bound."""
        for cid in list(self._cache):
            if cid not in live_ids:
                self._cache.pop(cid, None)
                self._failed.pop(cid, None)

    def note(self) -> str | None:
        """Why some containers carry only an id -- names the exact unlock."""
        if not self.unresolved:
            return None
        reasons = sorted({why for _, _, why in self._socket_state.values() if why})
        if not reasons:
            reasons = sorted({why for _, why in self._failed.values()})
        return (f"{self.unresolved} container process(es) shown by id only; "
                f"naming them needs {'; '.join(reasons) or 'the runtime API socket'}")

    # --------------------------------------------------------------- lookup
    def _lookup(self, runtime: str, cid: str) -> dict[str, object]:
        base: dict[str, object] = {
            "runtime": runtime, "id": cid[:12], "name": None, "image": None,
            "service": None, "project": None,
        }
        failed = self._failed.get(cid)
        if failed and time.monotonic() - failed[0] < _RETRY_S:
            return base
        path = self._socket_for(runtime)
        if path is None:
            return base
        try:
            info = self._inspect(path, cid)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self._failed[cid] = (time.monotonic(), f"{runtime} API: {exc}")
            log.debug("container %s lookup failed: %s", cid[:12], exc)
            return base
        if not info:
            self._failed[cid] = (time.monotonic(), f"{runtime} API returned nothing")
            return base
        config = info.get("Config") if isinstance(info.get("Config"), dict) else {}
        labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
        name = info.get("Name")
        base.update({
            "name": str(name).lstrip("/")[:128] if isinstance(name, str) and name else None,
            "image": str(config.get("Image"))[:128] if config.get("Image") else None,
            "service": _label(labels, "com.docker.compose.service",
                              "io.podman.compose.service"),
            "project": _label(labels, "com.docker.compose.project",
                              "io.podman.compose.project"),
        })
        return base

    def _socket_for(self, runtime: str) -> str | None:
        """The runtime's API socket path, or None (with the reason recorded
        for note()). Re-probed every few minutes so granting access to the
        socket takes effect without an agent restart."""
        state = self._socket_state.get(runtime)
        if state and time.monotonic() - state[0] < _RETRY_S:
            return state[1]
        candidates = _SOCKETS.get(runtime, ())
        for path in candidates:
            if os.path.exists(path) and os.access(path, os.R_OK | os.W_OK):
                self._socket_state[runtime] = (time.monotonic(), path, None)
                return path
        why = (_UNLOCK.get(runtime, f"the {runtime} API socket")
               if any(os.path.exists(p) for p in candidates)
               else f"the {runtime} API socket, which is not present "
                    f"({', '.join(candidates)})")
        self._socket_state[runtime] = (time.monotonic(), None, why)
        return None

    @staticmethod
    def _inspect(path: str, cid: str) -> dict | None:
        conn = _UnixHTTPConnection(path, _TIMEOUT_S)
        try:
            conn.request("GET", f"/containers/{cid}/json",
                         headers={"Host": "localhost"})
            response = conn.getresponse()
            body = response.read(256 * 1024)
            if response.status != 200:
                raise http.client.HTTPException(f"HTTP {response.status}")
            data = json.loads(body)
            return data if isinstance(data, dict) else None
        finally:
            conn.close()


def _label(labels: dict, *keys: str) -> str | None:
    for key in keys:
        value = labels.get(key)
        if isinstance(value, str) and value:
            return value[:128]
    return None
