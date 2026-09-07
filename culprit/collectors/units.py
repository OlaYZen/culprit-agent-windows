"""Unit actions: the Outage Doctor's verbs.

The Lag Doctor's findings come with End task, renice and Throttle; until now
the Outage Doctor's items came with a command to copy. This closes that gap
with the four things a person types after reading one of its cards --
`systemctl restart`, `start`, `reload-or-restart`, `reset-failed` -- run on
the agent with the same guards the process actions have: never the init
scope, never journald / logind / udevd / dbus (the machine goes with them),
never the unit running this agent, and nothing that is not a unit name.
`stop` is deliberately not offered: nothing the Outage Doctor reports is
fixed by stopping something.

The unit's state is read before and after from `systemctl show`, so the
result says what happened ("failed -> active, main pid 4410") rather than
that a command returned zero. Whether the fix *held* is the host's verdict
watch, which follows the node's next outage samples, not this module.

A system unit needs root or a polkit rule for
org.freedesktop.systemd1.manage-units; the agent reports exactly that when
it lacks it, the same way Throttle does.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from typing import Any

from .. import linux

log = logging.getLogger("culprit.units")

VERBS = ("restart", "start", "reload-or-restart", "reset-failed")
MANAGERS = ("system", "user")
# What the Outage Doctor offers per item kind (the agent decides, so the
# dashboard renders data rather than choosing verbs on the host's behalf).
OFFERED = {
    "unit_failed": ("restart",),
    "unit_looping": ("restart",),
    "unit_stopped": ("start",),
    "not_listening": ("reload-or-restart",),
}
PROTECTED = frozenset({
    "init.scope", "dbus.service", "dbus-broker.service",
    "systemd-journald.service", "systemd-logind.service",
    "systemd-udevd.service", "user.slice", "system.slice", "-.slice",
})
_NAME = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,255}\.(service|socket|timer|mount|path|target)$")
_PROPS = ("ActiveState,SubState,Result,NRestarts,MainPID,ExecMainStatus,"
          "ExecMainStartTimestampMonotonic,InactiveEnterTimestamp,Id")
TIMEOUT_S = 45.0


def _argv(manager: str, *rest: str) -> list[str]:
    return ["systemctl"] + (["--user"] if manager == "user" else []) + list(rest)


def state(unit: str, manager: str = "system") -> dict[str, Any] | None:
    """The unit's current state from `systemctl show`, or None when it
    cannot be read (no systemd, no bus, no such unit)."""
    text = linux.run(_argv(manager, "show", unit, "-p", _PROPS), timeout=10)
    if not text:
        return None
    props: dict[str, str] = {}
    for line in text.split("\n"):
        key, sep, value = line.partition("=")
        if sep:
            props[key.strip()] = value.strip()
    if not props.get("Id"):
        return None
    main_pid = props.get("MainPID")
    restarts = props.get("NRestarts")
    return {
        "active": props.get("ActiveState") or None,
        "sub": props.get("SubState") or None,
        "result": props.get("Result") or None,
        "main_pid": int(main_pid) if main_pid and main_pid.isdigit() and main_pid != "0" else None,
        "restarts": int(restarts) if restarts and restarts.isdigit() else None,
        "exit_status": props.get("ExecMainStatus") or None,
    }


def refuse(unit: str, verb: str, manager: str) -> str | None:
    """Why this action is not allowed, or None when it is."""
    if verb not in VERBS:
        return f"unknown verb {verb!r}; expected one of {', '.join(VERBS)}"
    if manager not in MANAGERS:
        return f"unknown manager {manager!r}; expected system or user"
    if not isinstance(unit, str) or not _NAME.match(unit):
        return "not a unit name (a .service, .socket, .timer, .mount, .path or .target)"
    if unit in PROTECTED or unit.startswith("user@"):
        return f"{unit} is a critical system unit; restarting it takes the machine or its sessions down"
    own = linux.unit_from_cgroup(os.getpid())
    if own and unit == own:
        return f"{unit} is the unit running Culprit itself"
    return None


def act(unit: str, verb: str, manager: str = "system") -> dict[str, Any]:
    """Run one systemctl verb on a unit and report its state before and after."""
    reason = refuse(unit, verb, manager)
    if reason:
        return {"ok": False, "reason": reason}
    before = state(unit, manager)
    started = time.perf_counter()
    try:
        completed = subprocess.run(_argv(manager, verb, unit), capture_output=True,
                                   text=True, timeout=TIMEOUT_S)
    except FileNotFoundError:
        return {"ok": False, "reason": "systemctl is not available on this machine"}
    except subprocess.TimeoutExpired:
        return {"ok": False,
                "reason": (f"systemctl {verb} {unit} did not return within {TIMEOUT_S:.0f}s "
                           "-- the unit is probably still stopping (TimeoutStopSec); "
                           "its state will show in the next samples")}
    except OSError as exc:
        return {"ok": False, "reason": f"systemctl could not run: {exc}"}
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        lowered = err.lower()
        if "authentication" in lowered or "access denied" in lowered or "permission" in lowered \
                or "interactive authentication required" in lowered:
            return {"ok": False,
                    "reason": (f"Permission denied: {verb} on a {manager} unit needs root, "
                               "or a polkit rule granting org.freedesktop.systemd1."
                               "manage-units to the agent's user.")}
        if "not found" in lowered or "not loaded" in lowered:
            return {"ok": False, "reason": f"systemctl: {err[:300] or 'no such unit'}"}
        return {"ok": False, "reason": f"systemctl: {err[:300] or 'failed'}",
                "before": before, "after": state(unit, manager)}
    # systemd reports the job done when the start job finishes; a Type=simple
    # unit is "active" the moment its process is forked, so a crash a second
    # later is only visible to the verdict watch, which is the point of it.
    time.sleep(0.3)
    after = state(unit, manager)
    note = None
    if verb == "reset-failed":
        note = "Only the failed state was cleared; nothing was started."
    elif after and after.get("active") not in ("active", "activating", "reloading"):
        note = (f"systemctl returned success but the unit is {after.get('active')} "
                f"({after.get('sub')}); it may have exited straight away -- the "
                "journal has its last words.")
    return {
        "ok": True, "unit": unit, "verb": verb, "manager": manager,
        "before": before, "after": after, "elapsed_ms": elapsed_ms, "note": note,
    }


def offered(kind: str, unit: str | None, root: str | None, manager: str) -> list[dict[str, Any]]:
    """The action buttons an Outage item carries: verb, unit, and a label
    that says what will be acted on. A failed unit with a different root
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
              "reload-or-restart": "Reload or restart", "reset-failed": "Reset failed state"}
