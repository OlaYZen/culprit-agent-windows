"""File-sync health -- the generalisation of the Windows OneDrive collector.

There is no single sync client to special-case on Linux, so this is a small
plugin chain: each adapter implements `detect()` and `sample()`, and only
detected clients appear in the payload. Most Linux sync clients run as systemd
*user* units, so unit state plus that unit's journal is the common backbone;
client-specific adapters add real queue/error counters where an API exists.

The honesty rules carried over from the OneDrive collector:

* readings that come from a file or cache carry their age;
* an opaque status value is corroboration, never the verdict -- verdicts are
  derived from unambiguous counters;
* "no client detected" is an explicit state naming what was looked for.

Plus one Linux-only panel with no Windows analogue: **inotify watch
exhaustion**. Sync clients and editors silently stop noticing file changes
when fs.inotify.max_user_watches runs out, which looks exactly like "sync is
broken" while every status light stays green.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from .. import linux

log = logging.getLogger("culprit.sync")

HOME = Path.home()


class SyncCollector:
    def __init__(self) -> None:
        self._plugins = [Syncthing(), RcloneRC(), OneDriveAbraunegg(),
                         NextcloudDesktop(), Dropbox()]
        self._detected: list | None = None

    def sample(self) -> dict[str, object]:
        if self._detected is None:
            self._detected = [p for p in self._plugins if _safe_detect(p)]

        clients = []
        problems: list[dict[str, object]] = []
        for plugin in self._detected:
            try:
                payload = plugin.sample()
            except Exception as exc:  # noqa: BLE001 -- one client must not kill the tier
                payload = {"name": plugin.name, "status": "unknown",
                           "detail": f"adapter failed: {exc}", "source": "error"}
            clients.append(payload)
            problems.extend(payload.get("problems") or [])

        status = "not_configured"
        if clients:
            ranking = ["error", "warning", "syncing", "up_to_date", "unknown"]
            statuses = [str(c.get("status")) for c in clients]
            status = next((s for s in ranking if s in statuses), "unknown")

        return {
            "available": bool(clients),
            "reason": None if clients else (
                "no known sync client detected -- looked for "
                + ", ".join(p.name for p in self._plugins)),
            "status": status,
            "clients": clients,
            "problems": problems,
            "inotify": _inotify_state(),
        }


def _safe_detect(plugin) -> bool:  # noqa: ANN001
    try:
        return bool(plugin.detect())
    except Exception as exc:  # noqa: BLE001
        log.debug("%s detect failed: %s", plugin.name, exc)
        return False


# ------------------------------------------------------------------- plugins
class Syncthing:
    """The best integration target: a proper local REST API on :8384.

    The API key is read from the user's own config file, which is exactly as
    readable as the data it protects -- no secret is being circumvented.
    """

    name = "Syncthing"

    def __init__(self) -> None:
        self.api_key: str | None = None
        self.address = "127.0.0.1:8384"

    def detect(self) -> bool:
        for candidate in (HOME / ".local/state/syncthing/config.xml",
                          HOME / ".config/syncthing/config.xml"):
            if candidate.exists():
                try:
                    root = ET.parse(candidate).getroot()
                    gui = root.find("gui")
                    if gui is not None:
                        key = gui.findtext("apikey")
                        address = gui.findtext("address")
                        self.api_key = key
                        if address:
                            self.address = address
                    return True
                except ET.ParseError:
                    return True
        return _unit_exists("syncthing.service", user=True)

    def sample(self) -> dict[str, object]:
        base = {"name": self.name, "source": "REST API + user unit",
                "unit": _unit_state("syncthing.service", user=True)}
        if not self.api_key:
            return {**base, "status": "unknown",
                    "detail": "config.xml found but no API key readable; only "
                              "unit state is available", "problems": []}
        try:
            errors = self._get("/rest/system/error")
            completion = self._get("/rest/db/completion")
        except OSError as exc:
            running = (base["unit"] or {}).get("active") == "active"
            return {**base,
                    "status": "error" if running else "not_configured",
                    "detail": f"API not reachable ({exc})", "problems": ([{
                        "severity": "warn", "title": "Syncthing API unreachable",
                        "detail": "The unit reports running but the REST API "
                                  "did not answer.", "client": self.name,
                    }] if running else [])}
        error_list = (errors or {}).get("errors") or []
        pct = (completion or {}).get("completion")
        need_bytes = (completion or {}).get("needBytes") or 0
        problems = [{
            "severity": "warn", "title": "Syncthing reports errors",
            "detail": str(error_list[-1].get("message"))[:200],
            "client": self.name,
        }] if error_list else []
        status = ("error" if error_list
                  else "syncing" if need_bytes else "up_to_date")
        return {**base, "status": status,
                "detail": f"{pct:.0f}% complete, {need_bytes} bytes needed"
                if pct is not None else "connected",
                "metrics": {"completion_pct": pct, "need_bytes": need_bytes,
                            "errors": len(error_list)},
                "problems": problems}

    def _get(self, path: str) -> dict | None:
        request = urllib.request.Request(
            f"http://{self.address}{path}",
            headers={"X-API-Key": self.api_key or ""})
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read())


class RcloneRC:
    name = "rclone"

    def detect(self) -> bool:
        # Only meaningful when the rc server is enabled; a bare binary on PATH
        # syncs nothing by itself.
        return _port_open(5572) and _which("rclone")

    def sample(self) -> dict[str, object]:
        stats = linux.run_json(["rclone", "rc", "core/stats"], timeout=5)
        if not isinstance(stats, dict):
            return {"name": self.name, "status": "unknown", "source": "rclone rc",
                    "detail": "rc server did not answer core/stats", "problems": []}
        errors = stats.get("errors") or 0
        transferring = stats.get("transferring") or []
        status = ("error" if errors else
                  "syncing" if transferring else "up_to_date")
        return {
            "name": self.name, "source": "rclone rc", "status": status,
            "detail": f"{len(transferring)} transferring, {errors} errors",
            "metrics": {"errors": errors, "transferring": len(transferring),
                        "bytes": stats.get("bytes"),
                        "last_error": stats.get("lastError")},
            "problems": [{"severity": "warn", "title": "rclone errors",
                          "detail": str(stats.get("lastError"))[:200],
                          "client": self.name}] if errors else [],
        }


class OneDriveAbraunegg:
    """The community OneDrive client -- runs as a systemd user unit."""

    name = "onedrive (abraunegg)"

    def detect(self) -> bool:
        return (HOME / ".config/onedrive").is_dir() or _unit_exists(
            "onedrive.service", user=True)

    def sample(self) -> dict[str, object]:
        unit = _unit_state("onedrive.service", user=True)
        running = (unit or {}).get("active") == "active"
        # The client's journal carries its sync errors; grab the recent ones.
        entries = linux.journalctl_json(
            ["--user", "-u", "onedrive.service", "--since", "-1d",
             "-p", "0..4"], timeout=10, max_entries=20)
        problems = [{
            "severity": "warn", "title": "onedrive logged errors",
            "detail": str(entry.get("MESSAGE"))[:200], "client": self.name,
        } for entry in entries[-3:]]
        return {
            "name": self.name, "source": "user unit + journal",
            "unit": unit,
            "status": ("error" if problems else
                       "up_to_date" if running else "not_configured"),
            "detail": ("service running" if running
                       else "configured but service not running"),
            "problems": problems,
        }


class NextcloudDesktop:
    name = "Nextcloud"

    def detect(self) -> bool:
        return (HOME / ".local/share/Nextcloud/socket").exists()

    def sample(self) -> dict[str, object]:
        # The socket protocol is line-based (RETRIEVE_FOLDER_STATUS etc.); a
        # full client is out of scope, but the socket existing while the
        # process runs is a meaningful liveness check.
        import psutil

        running = any("nextcloud" in (p.info.get("name") or "").lower()
                      for p in psutil.process_iter(["name"]))
        return {
            "name": self.name, "source": "socket + process",
            "status": "unknown" if running else "not_configured",
            "detail": ("client running; per-folder status not queried "
                       "(socket API adapter not implemented)" if running
                       else "socket present but the client is not running"),
            "problems": [],
        }


class Dropbox:
    name = "Dropbox"

    def detect(self) -> bool:
        return (HOME / ".dropbox").is_dir() and _which("dropbox")

    def sample(self) -> dict[str, object]:
        text = (linux.run(["dropbox", "status"], timeout=5) or "").strip()
        lowered = text.lower()
        status = ("up_to_date" if "up to date" in lowered
                  else "syncing" if ("syncing" in lowered or "indexing" in lowered)
                  else "error" if "isn't running" not in lowered and text else
                  "not_configured")
        return {"name": self.name, "source": "dropbox status", "status": status,
                "detail": text.split("\n")[0] if text else "no status output",
                "problems": []}


# ----------------------------------------------------------------- inotify
def _inotify_state() -> dict[str, object]:
    limit = linux.read_int("/proc/sys/fs/inotify/max_user_watches")
    instances_limit = linux.read_int("/proc/sys/fs/inotify/max_user_instances")
    used = 0
    instances = 0
    unreadable = 0
    # Counting real watches means walking fdinfo, which is permission-gated
    # per process (same as /proc/<pid>/io); the unreadable count keeps the
    # number honest.
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            fd_dir = f"/proc/{name}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                unreadable += 1
                continue
            for fd in fds:
                try:
                    if os.readlink(f"{fd_dir}/{fd}") != "anon_inode:inotify":
                        continue
                except OSError:
                    continue
                instances += 1
                info = linux.read_text(f"/proc/{name}/fdinfo/{fd}") or ""
                used += info.count("inotify wd:")
    except OSError:
        pass
    pct = (100.0 * used / limit) if limit else None
    return {
        "max_watches": limit,
        "max_instances": instances_limit,
        "used_watches": used,
        "instances": instances,
        "unreadable_processes": unreadable,
        "percent": None if pct is None else round(pct, 1),
        "note": ("counts cover only processes readable at this privilege "
                 f"level ({unreadable} not readable); the true usage is at "
                 "least this" if unreadable else None),
        "warning": ("inotify watches nearly exhausted -- sync clients and "
                    "editors silently stop seeing file changes when this "
                    "runs out. Raise fs.inotify.max_user_watches."
                    if pct is not None and pct >= 80 else None),
    }


# ------------------------------------------------------------------- helpers
def _which(binary: str) -> bool:
    import shutil

    return shutil.which(binary) is not None


def _port_open(port: int) -> bool:
    import socket

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def _unit_exists(unit: str, user: bool = False) -> bool:
    flag = ["--user"] if user else []
    text = linux.run(["systemctl", *flag, "list-unit-files", unit,
                      "--no-legend", "--no-pager"], timeout=5)
    return bool(text and text.strip())


def _unit_state(unit: str, user: bool = False) -> dict[str, object] | None:
    flag = ["--user"] if user else []
    text = linux.run(["systemctl", *flag, "show", unit,
                      "-p", "ActiveState,SubState,Result,NRestarts"], timeout=5)
    if not text:
        return None
    fields = dict(line.partition("=")[::2] for line in text.splitlines())
    return {"active": fields.get("ActiveState"),
            "sub": fields.get("SubState"),
            "result": fields.get("Result"),
            "restarts": fields.get("NRestarts")}
