"""Windows services -- the Service Control Manager's database, in the shape
the dashboard reads for systemd units.

`psutil.win_service_iter()` reads the SCM database, which a standard user can
enumerate (306 services readable, 1 denied on the original dev machine).

The useful signal is not the list itself but the *anomalies*: services set to
start automatically that are not running. Those are surfaced separately so
the dashboard can lead with them instead of a 300-row table nobody reads.

**Why the benign-stopped allowlist exists here and not on Linux.** systemd
tells you when a unit is *supposed* to be inactive (Type=oneshot without
RemainAfterExit), so the Linux collector derives "enabled but not running"
from properties. The SCM has no such property: Windows ships a dozen
auto-start services that legitimately stop themselves once their work is
done (Software Protection, Windows Update between scans, Delivery
Optimization...), and without the list every machine shows a dozen false
"failed to start" alarms. A hand-curated list is the honest fallback, and it
is kept short and commented.

What the SCM can say that fills the systemd-era fields: `Win32ExitCode` /
`ServiceSpecificExitCode` from QueryServiceStatusEx stand in for `result` /
`exit_status` (a non-zero code on a stopped service is the failure reason),
and the recovery actions (SERVICE_CONFIG_FAILURE_ACTIONS) say whether it
restarts on failure. Scheduled tasks play the role of systemd timers. What
it cannot say is per-service CPU, memory and stall time -- that needs cgroups
-- so `cgroup_attribution` is False and the per-unit section says why.
"""

from __future__ import annotations

import csv
import io
import logging
import time
from datetime import datetime

import psutil

from .. import windows
from . import events as events_mod

log = logging.getLogger("culprit.services")

# Auto-start services that legitimately stop themselves once their work is done.
# Flagging these as "failed to start" would be noise on every single machine.
_BENIGN_STOPPED = {
    "sppsvc",            # Software Protection -- exits after licence checks
    "gpsvc",             # Group Policy -- demand-start in practice
    "wuauserv",          # Windows Update -- stops between scans
    "bits",              # Background Intelligent Transfer
    "dosvc",             # Delivery Optimization
    "trustedinstaller",  # Windows Modules Installer
    "clipsvc",           # Client Licence Service
    "wbiosrvc",          # Windows Biometric
    "tokenbroker",
    "wpnservice",
    "cdpsvc",
    "mapsbroker",
    "dps",
    "wsearch",           # can be idle-stopped by the indexer itself
    "webthreatdefsvc",
    "installservice",
    "smphost",
    "svsvc",
    "sgrmbroker",
    "camsvc",
    "wlidsvc",
    "edgeupdate",        # the updaters run on a schedule and exit
    "gupdate",
    "brave",
    "mozillamaintenance",
}

_TASKS_REFRESH_S = 300.0
# How far back the Operational log is read for task runs, and how many events
# that is allowed to cost. One read every _TASKS_REFRESH_S, not per tick.
_TASK_RUN_LOOKBACK_DAYS = 14
_TASK_RUN_EVENTS = 400
# Task Scheduler result codes that mean "did not fail".
_TASK_OK = {0, 0x41301, 0x41302, 0x41303, 0x41304, 0x41306, 0x41325, 0x41326, 0x420, 0x800710E0}


class ServiceCollector:
    def __init__(self) -> None:
        self._tasks: list[dict[str, object]] = []
        self._tasks_at = 0.0
        self._tasks_reason: str | None = None

    def sample(self) -> dict[str, object]:
        try:
            iterator = list(psutil.win_service_iter())
        except Exception as exc:  # noqa: BLE001
            reason = (str(exc) if windows.IS_WINDOWS
                      else "the Service Control Manager only exists on Windows")
            return {"available": False, "reason": reason, "services": [],
                    "summary": {"total": 0, "denied": 0, "user_units": 0},
                    "problems": [], "by_pid": {}, "timers": [],
                    "cgroup_attribution": False, "user_bus": False,
                    "user_bus_reason": None}

        services: list[dict[str, object]] = []
        denied = 0
        for service in iterator:
            try:
                info = service.as_dict()
            except psutil.AccessDenied:
                denied += 1
                continue
            except (psutil.NoSuchProcess, OSError):
                continue

            name = str(info.get("name") or "")
            status = str(info.get("status") or "unknown")
            start_type = str(info.get("start_type") or "unknown")
            pid = info.get("pid")
            exit_codes = _exit_codes(name) if status in ("stopped", "paused") else None

            services.append({
                "name": name,
                "scope": "system",
                "display_name": info.get("display_name"),
                "status": status,
                "active_state": "active" if status == "running" else status,
                "sub_state": status,
                "load_state": "loaded",
                "start_type": start_type,
                "pid": pid if pid else None,
                "username": info.get("username"),
                "binpath": info.get("binpath"),
                "description": info.get("description"),
                # The SCM's exit codes are the nearest thing to systemd's
                # Result: non-zero on a stopped service is why it stopped.
                "result": _result_of(exit_codes),
                "restarts": None,
                "exit_status": (exit_codes or {}).get("exit_code"),
                "type": "service",
                "remain_after_exit": False,
                "condition_result": None,
                "since": None,
                "inactive_since": None,
                "started_at": None,
                "exited_at": None,
                "wanted_by": [],
            })

        summary: dict[str, int] = {"total": len(services), "denied": denied,
                                   "user_units": 0}
        for service in services:
            key = f"status_{service['status']}"
            summary[key] = summary.get(key, 0) + 1
            key = f"start_{service['start_type']}"
            summary[key] = summary.get(key, 0) + 1

        problems = []
        for service in services:
            if service["start_type"] != "automatic":
                continue
            if service["status"] not in ("stopped", "paused"):
                continue
            if str(service["name"]).lower() in _BENIGN_STOPPED:
                continue
            code = service.get("exit_status")
            crashed = isinstance(code, int) and code not in (0, 1077)
            problems.append({
                "name": service["name"],
                "display_name": service["display_name"],
                "status": service["status"],
                "start_type": service["start_type"],
                "scope": "system",
                "severity": "critical" if crashed else "warn",
                "result": service.get("result"),
                "restarts": None,
                "detail": (f"Set to start automatically but stopped with exit code {code}."
                           if crashed else "Set to start automatically but is not running."),
            })
        problems.sort(key=lambda item: (0 if item["severity"] == "critical" else 1,
                                        str(item["display_name"] or item["name"])))

        services.sort(key=lambda s: (
            0 if s["status"] == "running" else 1,
            str(s["display_name"] or s["name"]).lower(),
        ))

        # PID -> service names, so the process table can label svchost.exe rows
        # with what they are actually hosting.
        by_pid: dict[str, list[str]] = {}
        for service in services:
            if service["pid"]:
                by_pid.setdefault(str(service["pid"]), []).append(
                    str(service["display_name"] or service["name"])
                )

        now = time.monotonic()
        if now - self._tasks_at > _TASKS_REFRESH_S:
            self._tasks, self._tasks_reason = _scheduled_tasks()
            self._tasks_at = now

        return {
            "available": True,
            "reason": None,
            "services": services,
            "summary": summary,
            "problems": problems,
            "by_pid": by_pid,
            "timers": self._tasks,
            "timers_reason": self._tasks_reason,
            "cgroup_attribution": False,
            "cgroup_reason": windows.not_capable(
                "per-service CPU, memory and stall time come from Linux cgroups; "
                "the SCM keeps none. The process table shows each host process "
                "with the services it hosts."),
            "user_bus": False,
            "user_bus_reason": "Windows has no per-user service manager; per-user "
                               "background work runs as scheduled tasks (listed under timers)",
        }


def _exit_codes(name: str) -> dict[str, object] | None:
    status = windows.service_status(name)
    if not status:
        return None
    code = int(status.get("exit_code") or 0)
    specific = int(status.get("service_exit_code") or 0)
    # ERROR_SERVICE_SPECIFIC_ERROR (1066): the real code is the specific one.
    if code == 1066:
        return {"exit_code": specific, "specific": True}
    return {"exit_code": code, "specific": False}


def _result_of(codes: dict[str, object] | None) -> str | None:
    if not codes:
        return None
    code = int(codes.get("exit_code") or 0)
    if code == 0:
        return "success"
    if code == 1077:
        return "never-started"     # ERROR_SERVICE_NEVER_STARTED: stopped since boot
    return f"exit-code {code}" + (" (service-specific)" if codes.get("specific") else "")


def _scheduled_tasks() -> tuple[list[dict[str, object]], str | None]:
    """Scheduled tasks in the systemd-timer shape (unit / activates / next /
    last), plus each task's last result, so a job that failed on its last run
    is a real signal. `schtasks /query /v /fo csv` costs ~0.5-1 s on a
    machine with a few hundred tasks, so it runs every five minutes, not
    every slow tick; Microsoft's own maintenance tasks (\\Microsoft\\Windows\\...)
    are folded away unless they failed, or the list is 200 rows of noise."""
    text = windows.run(["schtasks", "/query", "/v", "/fo", "csv"], timeout=20)
    if text is None:
        return [], ("schtasks is not available" if windows.IS_WINDOWS
                    else "Task Scheduler only exists on Windows")
    out: list[dict[str, object]] = []
    try:
        rows = list(csv.DictReader(io.StringIO(text)))
    except csv.Error as exc:
        return [], f"schtasks output could not be parsed: {exc}"
    for row in rows:
        name = row.get("TaskName") or ""
        if not name or name == "TaskName":
            continue      # schtasks repeats the header per folder
        try:
            result = int(str(row.get("Last Result") or "0"), 0)
        except ValueError:
            result = None
        failed = result is not None and result not in _TASK_OK
        if name.startswith("\\Microsoft\\") and not failed:
            continue
        out.append({
            "unit": name,
            "activates": (row.get("Task To Run") or "")[:160] or None,
            "next": _task_time(row.get("Next Run Time")),
            "last": _task_time(row.get("Last Run Time")),
            "last_result": result,
            "failed": failed,
            "status": row.get("Status"),
            "run_as": row.get("Run As User"),
        })
    out.sort(key=lambda t: (not t["failed"], str(t["unit"]).lower()))
    out = out[:120]
    runs, run_reason = _task_runs({str(t["unit"]) for t in out})
    for task in out:
        run = runs.get(str(task["unit"]))
        reason = run_reason
        last = task.get("last")
        if run is not None and isinstance(last, (int, float)) \
                and float(last) > float(run["started"]) + 60:
            # The instance the log paired is older than the run the scheduler
            # says was the last one: the completion event is missing (the log
            # rolled, or the machine went down mid-task). Not the last run,
            # so not reported as one.
            run, reason = None, ("the Task Scheduler log holds no completed run for "
                                 "the last time this task ran")
        if run is not None and not run["running"] and task.get("last_result") is not None:
            # The scheduler's own result code is the reliable one, and it
            # describes the run that *finished*; the Operational log supplies
            # the timing the code has no room for. A run still in flight gets
            # neither -- its result does not exist yet.
            run["status"] = task["last_result"]
            run["result"] = ("success" if task["last_result"] in _TASK_OK
                             else f"result {task['last_result']}")
        task["run"] = run
        task["run_reason"] = None if run is not None else reason
    return out, None


def _task_runs(names: set[str]) -> tuple[dict[str, dict[str, object]], str | None]:
    """The last run of each task, timed from the Task Scheduler's own log.

    `schtasks` says when a task last ran and how it ended. It does not say how
    **long** it took, and that is the number that catches a backup which
    "succeeded" in four seconds. The Operational channel does: event 100 opens
    an instance and 102 closes the same one, so a start paired with its end is
    a duration measured by Windows itself rather than inferred.

    That channel is not readable by a standard user, so this degrades the way
    every gated source here does: `run: null` with the exact unlock named,
    never a guessed duration.
    """
    if not names:
        return {}, None
    spec = events_mod.EventSpec(
        key="task_run", label="Scheduled task run",
        channel="Microsoft-Windows-TaskScheduler/Operational",
        ids=(100, 102), kind="task", severity="info",
        providers=("Microsoft-Windows-TaskScheduler",),
        requires_admin=True, limit=_TASK_RUN_EVENTS,
    )
    try:
        entries = events_mod.query_channel(spec, _TASK_RUN_LOOKBACK_DAYS, _TASK_RUN_EVENTS)
    except PermissionError:
        return {}, ("Not capable in Windows: the Task Scheduler Operational log needs "
                    "an Administrator task, so how long each task ran is unknown "
                    "(its result is not)")
    except Exception as exc:  # noqa: BLE001 -- one optional source, never the tier
        log.debug("task run log unreadable: %s", exc)
        return {}, f"the Task Scheduler Operational log could not be read ({_brief(exc)})"
    if not entries:
        return {}, ("the Task Scheduler Operational log is empty or disabled "
                    "(wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true)")

    # Newest first. An instance is one run: 102 closes what 100 opened.
    ends: dict[str, float] = {}
    out: dict[str, dict[str, object]] = {}
    for entry in entries:
        data = entry.get("data") or {}
        name = str(data.get("TaskName") or "")
        instance = str(data.get("InstanceId") or "")
        stamp = entry.get("timestamp")
        if name not in names or not isinstance(stamp, (int, float)):
            continue
        key = instance or name
        if entry.get("id") == 102:
            ends.setdefault(key, float(stamp))
            continue
        if entry.get("id") != 100 or name in out:
            continue                       # 100 without a 102 yet: still running
        ended = ends.pop(key, None)
        out[name] = {
            "started": float(stamp),
            "ended": ended,
            "duration_s": round(ended - float(stamp), 3) if ended and ended >= stamp else None,
            "elapsed_s": round(time.time() - float(stamp), 1) if ended is None else None,
            "status": None,
            "result": None,
            "running": ended is None,
        }
    return out, None


def _brief(exc: Exception, limit: int = 120) -> str:
    return str(exc)[:limit] or exc.__class__.__name__


def _task_time(value: str | None) -> float | None:
    """schtasks prints local time in the console locale's format; the two
    common shapes are tried and 'N/A' / 'Disabled' are None."""
    if not value or value.strip().upper() in ("N/A", "DISABLED", "NEVER"):
        return None
    text = value.strip()
    for fmt in ("%d.%m.%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    return None
