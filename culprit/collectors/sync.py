"""File-sync health: OneDrive, in the shape the dashboard reads for the
Linux agent's sync clients.

There is no supported API for "is OneDrive actually synced". The shell exposes
an overlay icon, `StorageProviderState` is awkward to reach from Python, and the
`.odl` logs are a proprietary binary format. What *is* readable, plain text, and
genuinely informative is OneDrive's own diagnostic dump:

    %LOCALAPPDATA%\\Microsoft\\OneDrive\\logs\\<Account>\\SyncDiagnostics.log

It is a UTF-8 `key = value` file that OneDrive rewrites periodically, carrying
the counters that matter: pending uploads and downloads, failed transfers,
conflicts, and two explicit stall flags (`syncStallDetected`,
`scanStateStallDetected`).

Two deliberate choices about how it is interpreted:

* **The file is not live.** OneDrive rewrites it on its own schedule, so a
  reading can be an hour old. Every payload therefore carries `age_seconds` and
  the UI shows the staleness rather than presenting an old snapshot as current.
* **`syncProgressState` is not trusted as the verdict.** It is an undocumented
  bitfield; 16777216 is reliably "up to date" but the rest of the space is
  community guesswork. So status is derived from the *unambiguous* counters --
  failures, conflicts, stall flags, pending queues -- and the raw state value is
  reported alongside as a hint, never as the sole basis for a verdict.

The Linux agent generalised this into a plugin chain (Syncthing, rclone,
Nextcloud, ...) and one Linux-only panel, inotify watch exhaustion. Here each
OneDrive account is one `client`; the inotify panel is honestly unavailable
(ReadDirectoryChangesW has no watch quota); and the OneDrive-only facts --
Known Folder Move health, the sync processes -- ride under `onedrive`.

One caveat that is Windows-specific: the registry accounts live under HKCU,
so an agent running as SYSTEM (the scheduled task) sees no user's OneDrive.
The payload says so instead of reporting "not configured".
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path

import psutil

from .. import windows

log = logging.getLogger("culprit.sync")

_ACCOUNTS_KEY = r"Software\Microsoft\OneDrive\Accounts"

# The one value in this bitfield with a reliable community-confirmed meaning.
_STATE_UP_TO_DATE = 16_777_216

_PROCESS_NAMES = {
    "onedrive.exe": "sync engine",
    "onedrive.sync.service.exe": "sync service",
    "filecoauth.exe": "Office co-authoring",
    "filesyncconfig.exe": "sync config",
    "microsoft.sharepoint.exe": "SharePoint sync",
}

# Known Folder Move: which shell folders have been redirected into OneDrive.
# Redirection breaking is a common and confusing failure -- files appear to
# vanish from the Desktop -- so it is worth reporting explicitly.
_SHELL_FOLDERS = {
    "Desktop": "Desktop",
    "Personal": "Documents",
    "My Pictures": "Pictures",
}

_INOTIFY = {
    "available": False,
    "reason": windows.not_capable("inotify watch limits are a Linux kernel quota; "
                                  "ReadDirectoryChangesW has none"),
    "max_watches": None, "used_watches": None, "instances": None,
    "max_instances": None, "percent": None, "note": None, "warning": None,
}


class SyncCollector:
    def __init__(self) -> None:
        self._accounts: list[dict[str, object]] | None = None
        self._accounts_at = 0.0

    def sample(self) -> dict[str, object]:
        now = time.monotonic()
        # Account configuration only changes on sign-in/sign-out.
        if self._accounts is None or now - self._accounts_at > 300:
            self._accounts = _registry_accounts()
            self._accounts_at = now

        processes = _processes()
        installed = bool(self._accounts) or bool(processes)

        if not installed:
            system_account = windows.IS_WINDOWS and _running_as_system()
            return {
                "available": False,
                "reason": ("the agent runs as SYSTEM, whose registry hive holds no OneDrive "
                           "account; run it as the signed-in user to see their sync state"
                           if system_account else
                           "no OneDrive account is configured for this user (looked in "
                           "HKCU\\Software\\Microsoft\\OneDrive\\Accounts) and no "
                           "OneDrive process is running"),
                "status": "not_configured", "clients": [], "problems": [],
                "inotify": _INOTIFY,
                "onedrive": {"accounts": [], "processes": processes, "kfm": _known_folders()},
            }

        clients: list[dict[str, object]] = []
        problems: list[dict[str, object]] = []

        for account in self._accounts or []:
            diagnostics = _read_diagnostics(str(account.get("key") or ""))
            verdict = _verdict(diagnostics, processes, account)
            label = str(account.get("label") or "OneDrive")
            name = f"OneDrive ({label})"
            for problem in verdict.get("problems", []):  # type: ignore[union-attr]
                problems.append({**problem, "client": name})
            clients.append({
                "name": name,
                "source": "SyncDiagnostics.log" if diagnostics.get("available")
                          else "registry (no diagnostics yet)",
                "status": verdict["status"],
                "detail": verdict["status_detail"],
                "unit": None,
                "metrics": diagnostics.get("metrics") or {},
                "problems": list(verdict.get("problems") or []),
                "pending": verdict.get("pending"),
                "stale": verdict.get("stale"),
                "age_seconds": diagnostics.get("age_seconds"),
                "account": {k: account.get(k) for k in
                            ("key", "label", "business", "email", "folder", "folder_exists")},
                "raw_state": diagnostics.get("raw_state"),
            })

        if not any(p["kind"] == "sync engine" for p in processes):
            problems.append({
                "severity": "critical",
                "title": "OneDrive is not running",
                "detail": "The sync engine process (OneDrive.exe) is not present, "
                          "so nothing is syncing. Files changed locally are not "
                          "being uploaded.",
                "client": "OneDrive",
            })

        kfm = _known_folders()
        for folder in kfm.get("folders", []):  # type: ignore[union-attr]
            if folder.get("redirected") and not folder.get("exists"):
                problems.append({
                    "severity": "critical",
                    "title": f"{folder['label']} redirection is broken",
                    "detail": f"{folder['label']} points at {folder['path']}, "
                              "which does not exist. This is why files look like "
                              "they have disappeared.",
                    "client": "OneDrive",
                })

        status = _worst_status(clients, problems)
        return {
            "available": True,
            "reason": None,
            "status": status,
            "clients": clients,
            "problems": sorted(problems,
                               key=lambda p: 0 if p["severity"] == "critical" else 1),
            "inotify": _INOTIFY,
            "onedrive": {"accounts": self._accounts, "processes": processes, "kfm": kfm},
        }


def _running_as_system() -> bool:
    return (os.environ.get("USERNAME") or "").upper().endswith("$") or \
        (os.environ.get("USERPROFILE") or "").lower().endswith("systemprofile")


# ------------------------------------------------------------------- registry
def _registry_accounts() -> list[dict[str, object]]:
    winreg = windows.winreg
    out: list[dict[str, object]] = []
    if winreg is None:
        return out
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _ACCOUNTS_KEY) as root:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, name) as key:
                        values = _all_values(key)
                except OSError:
                    continue
                folder = values.get("UserFolder")
                # An account key with no UserFolder was never fully set up.
                if not folder:
                    continue
                is_business = bool(values.get("Business")) or name.startswith("Business")
                out.append({
                    "key": name,
                    "label": str(values.get("DisplayName") or
                                 ("Personal" if not is_business else name)),
                    "business": is_business,
                    "email": values.get("UserEmail"),
                    "folder": folder,
                    "folder_exists": os.path.isdir(str(folder)),
                    "tenant_url": values.get("SPOResourceId"),
                    "cid": values.get("cid"),
                })
    except FileNotFoundError:
        return []
    except OSError as exc:
        log.debug("OneDrive registry read failed: %s", exc)
        return []
    out.sort(key=lambda a: (not a["business"], str(a["label"])))
    return out


def _all_values(key: object) -> dict[str, object]:
    winreg = windows.winreg

    values: dict[str, object] = {}
    index = 0
    while True:
        try:
            name, value, _ = winreg.EnumValue(key, index)  # type: ignore[arg-type]
        except OSError:
            break
        index += 1
        values[name] = value
    return values


def _known_folders() -> dict[str, object]:
    """Which of Desktop/Documents/Pictures are redirected into OneDrive."""
    winreg = windows.winreg
    folders: list[dict[str, object]] = []
    if winreg is None:
        return {"folders": [], "redirected_count": 0}
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ) as key:
            for value_name, label in _SHELL_FOLDERS.items():
                try:
                    raw = str(winreg.QueryValueEx(key, value_name)[0])
                except OSError:
                    continue
                expanded = os.path.expandvars(raw)
                folders.append({
                    "label": label,
                    "path": expanded,
                    "redirected": "onedrive" in expanded.lower(),
                    "exists": os.path.isdir(expanded),
                })
    except OSError as exc:
        log.debug("known folder read failed: %s", exc)
    return {
        "folders": folders,
        "redirected_count": sum(1 for f in folders if f["redirected"]),
    }


# ---------------------------------------------------------------- diagnostics
def _diagnostics_path(account_key: str) -> Path | None:
    """The diagnostics log for one specific account, or None.

    Deliberately does *not* fall back to another account's log. An earlier
    version did, and the result was that a Personal account with no log of its
    own reported the Business account's numbers as if they were its own -- 766
    files synced, same client version, identical status. Reporting "no data" is
    correct; reporting someone else's data is worse than useless.
    """
    if not account_key:
        return None
    base = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "OneDrive" / "logs"
    candidate = base / account_key / "SyncDiagnostics.log"
    return candidate if candidate.is_file() else None


_KV = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _read_diagnostics(account_key: str) -> dict[str, object]:
    path = _diagnostics_path(account_key)
    if path is None:
        return {"available": False,
                "reason": "SyncDiagnostics.log has not been written yet."}
    try:
        stat = path.stat()
        # utf-8-sig strips the BOM OneDrive writes; some builds use UTF-16.
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-16", errors="replace")
    except OSError as exc:
        return {"available": False, "reason": f"could not read the log: {exc}"}

    values: dict[str, object] = {}
    for line in text.splitlines():
        match = _KV.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2)
        values[key] = _coerce(raw)

    # SyncProgressState appears twice with different casing across versions.
    state = values.get("syncProgressState", values.get("SyncProgressState"))

    return {
        "available": True,
        "reason": None,
        "path": str(path),
        "written_at": stat.st_mtime,
        "age_seconds": max(0.0, time.time() - stat.st_mtime),
        "raw_state": state,
        "state_is_up_to_date": state == _STATE_UP_TO_DATE,
        "values": values,
        "metrics": _metrics(values),
    }


def _pick(values: dict[str, object], *names: str) -> object:
    """First present key, since casing drifts between OneDrive versions."""
    for name in names:
        if name in values:
            return values[name]
    return None


def _metrics(values: dict[str, object]) -> dict[str, object]:
    """The subset worth putting on a dashboard."""
    return {
        "files": _pick(values, "files"),
        "folders": _pick(values, "folders"),
        "files_to_upload": _pick(values, "FilesToUpload", "filesToUpload"),
        "files_to_download": _pick(values, "FilesToDownload", "filesToDownload"),
        "bytes_to_upload": _pick(values, "BytesToUpload", "bytesToUpload"),
        "bytes_to_download": _pick(values, "BytesToDownload", "bytesToDownload"),
        "upload_speed": _pick(values, "UploadSpeedBytesPerSec"),
        "download_speed": _pick(values, "DownloadSpeedBytesPerSec"),
        "changes_to_process": _pick(values, "ChangesToProcess"),
        "changes_to_send": _pick(values, "ChangesToSend"),
        "eta_seconds": _pick(values, "EstTimeRemainingInSec"),
        "failed_uploads": _pick(values, "numFileFailedUploads"),
        "failed_downloads": _pick(values, "numFileFailedDownloads"),
        "files_in_warning": _pick(values, "numFileInWarning"),
        "upload_errors": _pick(values, "numUploadErrorsReported"),
        "download_errors": _pick(values, "numDownloadErrorsReported"),
        "hash_mismatches": _pick(values, "numHashMismatchErrorsReported"),
        "conflicts_failed": _pick(values, "conflictsFailed"),
        "conflicts_handled": _pick(values, "conflictsHandled"),
        "sync_stalled": _pick(values, "syncStallDetected"),
        "scan_stalled": _pick(values, "scanStateStallDetected"),
        "resyncs": _pick(values, "numResyncs"),
        "db_was_reset": _pick(values, "wasFileDBReset"),
        "drives_connected": _pick(values, "drivesConnected"),
        "drives_awaiting_initial_sync": _pick(values, "drivesWaitingForInitialSync"),
        "client_version": _pick(values, "clientVersion"),
        "uptime_seconds": _pick(values, "uptimeSecs"),
        "placeholders_enabled": _pick(values, "placeholdersEnabled"),
        "vault_state": _pick(values, "vaultState"),
        "disk_free": _pick(values, "bytesAvailableOnDiskDrive"),
        "disk_total": _pick(values, "totalSizeOfDiskDrive"),
        "symlink_count": _pick(values, "SymLinkCount"),
        "reported_at": _pick(values, "timeUtc", "UtcNow"),
    }


def _verdict(diagnostics: dict[str, object], processes: list[dict],
             account: dict[str, object]) -> dict[str, object]:
    """Derive a status from the counters, not from the opaque state bitfield."""
    problems: list[dict[str, object]] = []

    if not account.get("folder_exists"):
        problems.append({
            "severity": "critical",
            "title": "Sync folder is missing",
            "detail": f"{account.get('folder')} does not exist. OneDrive cannot "
                      "sync a folder that is not there.",
        })

    if not diagnostics.get("available"):
        return {
            "status": "unknown",
            "status_detail": str(diagnostics.get("reason") or
                                 "No diagnostic data available."),
            "problems": problems,
            "pending": 0,
        }

    metrics = diagnostics.get("metrics") or {}
    number = lambda key: _as_int(metrics.get(key))  # noqa: E731

    failed = (number("failed_uploads") + number("failed_downloads")
              + number("upload_errors") + number("download_errors"))
    conflicts = number("conflicts_failed")
    warnings = number("files_in_warning")
    hash_mismatch = number("hash_mismatches")
    stalled = bool(number("sync_stalled")) or bool(number("scan_stalled"))
    pending = number("files_to_upload") + number("files_to_download")
    awaiting = number("drives_awaiting_initial_sync")

    if stalled:
        problems.append({
            "severity": "critical",
            "title": "Sync is stalled",
            "detail": "OneDrive has flagged its own sync loop as stalled. It will "
                      "not recover on its own -- restart the sync engine.",
        })
    if failed:
        problems.append({
            "severity": "critical",
            "title": f"{failed} transfer{'s' if failed != 1 else ''} failed",
            "detail": f"{number('failed_uploads')} upload(s) and "
                      f"{number('failed_downloads')} download(s) failed. Usually "
                      "an unsupported character in a filename, a path over the "
                      "length limit, a locked file, or exhausted quota.",
        })
    if conflicts:
        problems.append({
            "severity": "warn",
            "title": f"{conflicts} unresolved conflict{'s' if conflicts != 1 else ''}",
            "detail": "The same file was changed in two places and OneDrive could "
                      "not merge it. Both copies are kept until you pick one.",
        })
    if hash_mismatch:
        problems.append({
            "severity": "warn",
            "title": f"{hash_mismatch} checksum mismatch(es)",
            "detail": "A file's content did not match what the server expected. "
                      "Worth checking the file is not corrupt.",
        })
    if warnings:
        problems.append({
            "severity": "warn",
            "title": f"{warnings} file{'s' if warnings != 1 else ''} in a warning state",
            "detail": "These are skipped rather than synced.",
        })
    if number("db_was_reset"):
        problems.append({
            "severity": "warn",
            "title": "Sync database was reset",
            "detail": "OneDrive rebuilt its local database, which triggers a full "
                      "rescan and a burst of disk and network activity.",
        })
    if awaiting:
        problems.append({
            "severity": "info",
            "title": f"{awaiting} drive(s) awaiting initial sync",
            "detail": "First-time sync has not completed yet.",
        })

    age = float(diagnostics.get("age_seconds") or 0)
    if problems:
        status = ("error" if any(p["severity"] == "critical" for p in problems)
                  else "warning")
        detail = str(problems[0]["title"])
    elif pending or number("changes_to_process"):
        status = "syncing"
        detail = f"{pending} file(s) queued."
    elif diagnostics.get("state_is_up_to_date"):
        status = "up_to_date"
        detail = "Everything is synced."
    else:
        # No pending work, no failures, but the state value is not the known
        # up-to-date constant. Say so rather than guessing.
        status = "unknown"
        detail = (f"No pending transfers or errors reported, but OneDrive's state "
                  f"value ({diagnostics.get('raw_state')}) is not a recognised "
                  "'up to date' value.")

    return {
        "status": status,
        "status_detail": detail,
        "problems": problems,
        "pending": pending,
        "stale": age > 3600,
    }


def _processes() -> list[dict[str, object]]:
    """Which OneDrive processes are running.

    Only `name` is requested in the iteration. Asking `process_iter` for
    `create_time` as well cost 3.8 seconds here, because on Windows psutil pays
    ~9ms *per process* for it across all ~445 processes -- to answer a question
    about three of them. The expensive fields are read only for the handful that
    match.
    """
    out: list[dict[str, object]] = []
    for proc in psutil.process_iter(["name"]):
        name = str(proc.info.get("name") or "").lower()
        if name not in _PROCESS_NAMES:
            continue
        entry: dict[str, object] = {
            "pid": proc.pid,
            "name": proc.info["name"],
            "kind": _PROCESS_NAMES[name],
        }
        try:
            with proc.oneshot():
                entry["started"] = proc.create_time()
                entry["working_set"] = proc.memory_info().rss
                entry["threads"] = proc.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        out.append(entry)
    return out


def _worst_status(accounts: list[dict], problems: list[dict]) -> str:
    """Overall badge. Answers "is anything wrong", not "is everything known".

    `up_to_date` deliberately outranks `unknown`: a second account that is
    configured but has never written a diagnostics log (a Personal account
    alongside a Business one is the common case) should not drag the headline
    into an ambiguous state while the account that matters is demonstrably fine.
    The per-account card still shows its own honest `unknown`.
    """
    if any(p["severity"] == "critical" for p in problems):
        return "error"
    if any(p["severity"] == "warn" for p in problems):
        return "warning"
    statuses = {str(a.get("status")) for a in accounts}
    for candidate in ("error", "warning", "syncing", "up_to_date", "unknown"):
        if candidate in statuses:
            return candidate
    return "unknown"


def _coerce(raw: str) -> object:
    """Numbers as numbers, so the UI can format and compare them."""
    if raw == "":
        return None
    if re.fullmatch(r"-?\d+", raw):
        try:
            return int(raw)
        except ValueError:
            return raw
    if re.fullmatch(r"-?\d+\.\d+", raw):
        try:
            return float(raw)
        except ValueError:
            return raw
    return raw


def _as_int(value: object) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    # OneDrive uses -1 for "not measured"; treat that as zero, not as a count.
    return max(0, number)
