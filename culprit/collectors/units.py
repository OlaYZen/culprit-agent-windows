"""Service actions: the Outage Doctor's verbs, on Windows services.

The Lag Doctor's findings come with End task, priority and Throttle; the
Outage Doctor's items come with the things a person types after reading one
of its cards -- on Linux `systemctl restart / start / reload-or-restart /
reset-failed`, here the SCM's start and restart -- run on the agent with the
same guards the process actions have: never the services Windows cannot run
without (RPC, the event log, Plug and Play, WMI, the session manager, LSA),
never the task running this agent, and nothing that is not a service name.
`stop` is deliberately not offered: nothing the Outage Doctor reports is
fixed by stopping something.

Verb mapping: `restart` and `start` are what they say; `reload-or-restart`
becomes a restart (Windows services have a pause/continue control but no
reload); `reset-failed` has nothing to reset -- the SCM keeps no failed
state past the exit code -- and is refused with that reason. The service's
state is read before and after from QueryServiceStatusEx, so the result says
what happened ("stopped -> running, pid 4410") rather than that a call
returned. Whether the fix *held* is the host's verdict watch, which follows
the node's next outage samples, not this module.

Controlling a service needs the SERVICE_START right, which a standard user
does not have for most services: the agent reports exactly that when it
lacks it, the same way Throttle does.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from .. import windows

log = logging.getLogger("culprit.units")

VERBS = ("restart", "start", "reload-or-restart", "reset-failed")
MANAGERS = ("system",)
# What the Outage Doctor offers per item kind (the agent decides, so the
# dashboard renders data rather than choosing verbs on the host's behalf).
OFFERED = {
    "unit_failed": ("restart",),
    "unit_looping": ("restart",),
    "unit_stopped": ("start",),
    "not_listening": ("reload-or-restart",),
}
# Services the machine (or every session on it) goes down with.
PROTECTED = frozenset({
    "rpcss", "dcomlaunch", "rpceptmapper", "eventlog", "plugplay", "winmgmt",
    "lsm", "samss", "schedule", "power", "brokerinfrastructure",
    "coremessagingregistrar", "systemeventsbroker", "profsvc", "usermanager",
    "termservice", "lanmanserver", "lanmanworkstation", "dhcp", "dnscache",
    "nsi", "cryptsvc", "keyiso", "vaultsvc", "wdiservicehost", "windefend",
    "sens", "themes", "shellhwdetection", "seclogon",
})
_NAME = re.compile(r"^[A-Za-z0-9_.$@ -]{1,256}$")
TIMEOUT_S = 45.0


def refuse(unit: str, verb: str, manager: str) -> str | None:
    """Why this action is not allowed, or None when it is."""
    if verb not in VERBS:
        return f"unknown verb {verb!r}; expected one of {', '.join(VERBS)}"
    if manager not in MANAGERS:
        return f"unknown manager {manager!r}; Windows services have one manager (system)"
    if not isinstance(unit, str) or not _NAME.match(unit) or unit != unit.strip():
        return "not a service name"
    if verb == "reset-failed":
        return windows.not_capable("the Service Control Manager keeps no failed state "
                                   "to reset; restart the service instead")
    if unit.lower() in PROTECTED:
        return f"{unit} is a service Windows cannot run without; restarting it takes the machine or its sessions down"
    own = windows.own_service_name()
    if own and unit.lower() == own.lower():
        return f"{unit} is the task running Culprit itself"
    return None


def state(unit: str, manager: str = "system") -> dict[str, Any] | None:  # noqa: ARG001
    status = windows.service_status(unit)
    if status is None:
        return None
    return {
        "active": "active" if status["state"] == "running" else status["state"],
        "sub": status["state"],
        "result": (f"exit-code {status['exit_code']}" if status.get("exit_code")
                   and status["exit_code"] not in (0, 1077) else None),
        "restarts": None,
        "pid": status.get("pid"),
        "exit_status": status.get("exit_code"),
    }


def act(unit: str, verb: str, manager: str = "system") -> dict[str, Any]:
    """Run one verb on a service and report its state before and after."""
    reason = refuse(unit, verb, manager)
    if reason:
        return {"ok": False, "reason": reason}
    util = windows.win32serviceutil
    if util is None:
        return {"ok": False, "reason": windows.missing("win32serviceutil")}
    before = state(unit, manager)
    if before is None:
        return {"ok": False, "reason": f"no such service: {unit}"}
    started = time.perf_counter()
    try:
        if verb == "start":
            if before.get("sub") == "running":
                return {"ok": True, "unit": unit, "verb": verb, "manager": manager,
                        "before": before, "after": before, "elapsed_ms": 0,
                        "note": "The service was already running; nothing was done."}
            util.StartService(unit)
            util.WaitForServiceStatus(unit, windows.win32service.SERVICE_RUNNING,  # type: ignore[union-attr]
                                      int(TIMEOUT_S))
        else:
            # restart and reload-or-restart both: stop (if running), then start.
            if before.get("sub") != "stopped":
                util.StopService(unit)
                util.WaitForServiceStatus(unit, windows.win32service.SERVICE_STOPPED,  # type: ignore[union-attr]
                                          int(TIMEOUT_S))
            util.StartService(unit)
            util.WaitForServiceStatus(unit, windows.win32service.SERVICE_RUNNING,  # type: ignore[union-attr]
                                      int(TIMEOUT_S))
    except Exception as exc:  # noqa: BLE001 -- pywintypes.error and timeouts
        text = windows.short_error(exc)
        lowered = text.lower()
        if "access is denied" in lowered or "denied" in lowered:
            return {"ok": False,
                    "reason": (f"Permission denied: {verb} on {unit} needs the agent "
                               "elevated (the SYSTEM task agent.ps1 sets up has it).")}
        if "does not exist" in lowered or "not exist" in lowered:
            return {"ok": False, "reason": f"no such service: {unit}"}
        return {"ok": False, "reason": f"SCM: {text[:300] or 'failed'}",
                "before": before, "after": state(unit, manager)}
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    time.sleep(0.3)
    after = state(unit, manager)
    note = None
    if verb == "reload-or-restart":
        note = "Windows services have no reload; the service was restarted."
    if after and after.get("sub") != "running":
        note = ((note + " ") if note else "") + (
            f"The SCM reported success but the service is {after.get('sub')}; it "
            "may have exited straight away -- the System event log has its last words.")
    return {
        "ok": True, "unit": unit, "verb": verb, "manager": manager,
        "before": before, "after": after, "elapsed_ms": elapsed_ms, "note": note,
    }


def offered(kind: str, unit: str | None, root: str | None, manager: str) -> list[dict[str, Any]]:
    """The action buttons an Outage item carries: verb, service, and a label
    that says what will be acted on. A failed service with a different root
    offers the root first (fixing the dependency is the fix), then itself."""
    verbs = OFFERED.get(kind) or ()
    if not verbs or not unit:
        return []
    out: list[dict[str, Any]] = []
    for verb in verbs:
        targets = [root, unit] if root and root != unit else [unit]
        for target in targets:
            if refuse(target, verb, manager):
                continue
            out.append({
                "verb": verb, "unit": target, "manager": manager,
                "label": (f"{_VERB_WORD[verb]} {target}"
                          + (" (the root)" if target == root and root != unit else "")),
            })
    return out


_VERB_WORD = {"restart": "Restart", "start": "Start",
              "reload-or-restart": "Restart", "reset-failed": "Reset failed state"}
