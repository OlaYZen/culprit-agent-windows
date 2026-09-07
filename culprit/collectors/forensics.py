"""Previous-boot forensics: the evidence the Coroner reads after a death.

The flight recorder (recorder.py) says *how the machine was doing* when the
record stops. This module collects what the machine itself wrote down about
the end -- on Windows, the System event log, which unlike journald survives
every reboot and needs no privilege for the channels that matter here:

* the shutdown record: USER32 1074 ("The process X has initiated the restart
  of computer Y on behalf of user Z for the following reason: ...") says
  who asked and why; Kernel-General 13 and EventLog 6006 prove the shutdown
  path ran; Kernel-Power 41 and EventLog 6008 say it did not
* the kernel's own last words: BugCheck 1001 (with the stop code), WHEA
  hardware errors, disk errors, thermal events, the Resource-Exhaustion
  Detector's 2004 (virtual memory ran out, and who consumed it)
* the last System events before the end, slimmed, as the tail
* minidumps on disk (the pstore analogue), Windows Update installs shortly
  before (a "kernel package" here is a cumulative update), and -- when only
  the agent died -- Task Scheduler's record of the agent's own task

Everything is a fact with a time. The verdict is the host's job
(culprit/coroner.py); marker kinds keep the Linux names where the meaning
is the same (`shutdown_target`, `panic`, `mce`, `disk_error`,
`thermal_critical`, `journal_stopped`) and two Windows-only kinds the host
learns to read: `shutdown_request` (who asked, and why) and
`memory_exhaustion` (the commit charge ran out; not a kill).
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from .. import windows
from . import events as events_mod

log = logging.getLogger("culprit.forensics")

_LOOKBACK_S = 1800.0          # how far before the death the scan reaches
_KEEP_TAIL = 60               # entries shipped verbatim (slimmed) as "last words"
_PACKAGE_WINDOW_S = 7200.0
_TAIL_LIMIT = 600

# (provider substring, event ids) -> marker kind. Matched on the System
# channel; the provider name is the stable identity, the id the subtype.
_MARKER_SPECS: tuple[tuple[str, tuple[int, ...], str], ...] = (
    ("USER32", (1074,), "shutdown_request"),
    ("Microsoft-Windows-Kernel-General", (13,), "shutdown_target"),
    ("EventLog", (6006,), "journal_stopped"),
    ("EventLog", (6008,), "unclean"),
    ("Microsoft-Windows-Kernel-Power", (41,), "unclean"),
    ("Microsoft-Windows-Kernel-Power", (42,), "suspend"),
    ("Microsoft-Windows-WER-SystemErrorReporting", (1001,), "panic"),
    ("Microsoft-Windows-WHEA-Logger", (1, 17, 18, 19, 20, 47), "mce"),
    ("Microsoft-Windows-Resource-Exhaustion-Detector", (2004,), "memory_exhaustion"),
    ("Microsoft-Windows-Kernel-Power", (125, 126, 127), "thermal_critical"),
    ("disk", (7, 11, 51, 129, 153, 157), "disk_error"),
    ("Ntfs", (55, 98), "disk_error"),
    ("stornvme", (129,), "disk_error"),
    ("storahci", (129,), "disk_error"),
)
_TARGET_WORDS = {"restart": "reboot", "reboot": "reboot", "power off": "poweroff",
                 "shutdown": "poweroff", "shut down": "poweroff"}


def investigate(death: dict[str, Any]) -> dict[str, Any]:
    """Evidence for one death record (from recorder.detect_death)."""
    started = time.perf_counter()
    died_at = float(death.get("died_at") or time.time())
    kind = str(death.get("kind") or "machine")
    readable = events_mod.AVAILABLE
    evidence: dict[str, Any] = {
        "journal": {"readable": readable,
                    "reason": None if readable else windows.missing("win32evtlog"),
                    "persistent": True},
        "boots": {"count": None, "previous": None, "current": None, "gap_seconds": None},
        "markers": [], "tail": [], "pstore": _minidumps(),
        "packages": [],
        "agent": None, "notes": [],
        "platform": "windows",
    }
    if not readable:
        evidence["notes"].append(
            "The event log could not be read, so the shutdown record, the "
            "kernel's last messages and the agent task's exit are unverifiable: "
            f"{evidence['journal']['reason']}")
        evidence["cost_ms"] = round((time.perf_counter() - started) * 1000, 1)
        return evidence

    entries = _system_window(died_at)
    evidence["boots"] = _boot_facts(entries, died_at, death)
    evidence["packages"] = _packages_before(died_at)
    if kind == "machine":
        evidence["markers"] = _markers(entries, died_at)
        evidence["tail"] = _slim(entries[:_KEEP_TAIL])
        if not entries:
            evidence["notes"].append(
                "No System events were found in the half hour before the "
                "record stops.")
    else:
        evidence["agent"] = _agent_end(death, died_at)
        evidence["markers"] = [m for m in _markers(entries, died_at)
                               if m["kind"] in ("memory_exhaustion", "mce", "disk_error",
                                                "thermal_critical", "suspend")]
        evidence["tail"] = _slim(entries[:20])
    evidence["cost_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return evidence


# ------------------------------------------------------------- event log
def _spec(channel: str, ids: tuple[int, ...] = (), providers: tuple[str, ...] = (),
          key: str = "forensics", limit: int = _TAIL_LIMIT) -> events_mod.EventSpec:
    return events_mod.EventSpec(key=key, label=key, channel=channel, ids=ids,
                                kind="forensics", providers=providers, limit=limit)


def _system_window(died_at: float) -> list[dict[str, Any]]:
    """Newest-first System events from the half hour before the death to a
    minute after it. The log is not per-boot like the journal, so the window
    is cut by time and the query asks the log for that window only."""
    lookback_ms = int(max(0.0, time.time() - (died_at - _LOOKBACK_S)) * 1000)
    xpath = f"*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]"
    try:
        raw = events_mod.query_channel(_spec("System"), 1, _TAIL_LIMIT, xpath=xpath)
    except Exception as exc:  # noqa: BLE001
        log.debug("forensics query failed: %s", exc)
        return []
    return [e for e in raw if (e.get("timestamp") or 0) <= died_at + 60]


def _boot_facts(entries: list[dict[str, Any]], died_at: float,
                death: dict[str, Any]) -> dict[str, Any]:
    """The previous boot's start and end, and this boot's start, from the
    EventLog service's 6005 (started) / 6006 (stopped) and Kernel-General 12
    (boot). The recorder's boot ids are boot times, so they line up."""
    boots = [e for e in entries if str(e.get("provider") or "") in ("EventLog", "Microsoft-Windows-Kernel-General")
             and e.get("id") in (6005, 6006, 12, 13)]
    prev_start = _boot_time_of(death.get("prev_boot_id"))
    cur_start = _boot_time_of(death.get("boot_id"))
    last = None
    for event in boots:
        ts = float(event.get("timestamp") or 0)
        if event.get("id") in (6006, 13) and ts <= died_at + 60:
            last = max(last or 0.0, ts)
    previous = {"boot_id": death.get("prev_boot_id"), "first": prev_start,
                "last": last or died_at} if prev_start else None
    current = {"boot_id": death.get("boot_id"), "first": cur_start,
               "last": None} if cur_start else None
    gap = None
    if previous and current and previous.get("last") and current.get("first"):
        gap = round(float(current["first"]) - float(previous["last"]), 1)
    return {"count": None, "previous": previous, "current": current, "gap_seconds": gap}


def _boot_time_of(boot_id: Any) -> float | None:
    """The recorder's boot id is `boot-<epoch>` (windows.boot_id)."""
    match = re.match(r"^boot-(\d+)$", str(boot_id or ""))
    return float(match.group(1)) if match else None


# The events catalogue's decoders, keyed the way _enrich switches: run on
# the raw window entries so a bugcheck carries its stop code and the
# low-memory event its consumers.
_ENRICH_KEY = {1001: "bugcheck", 2004: "low_memory", 7031: "service_fail", 7034: "service_fail",
               1: "mce", 17: "mce", 18: "mce", 19: "mce", 20: "mce", 47: "mce"}


def _markers(entries: list[dict[str, Any]], died_at: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries:
        provider = str(entry.get("provider") or "")
        event_id = entry.get("id")
        kind = next((k for prov, ids, k in _MARKER_SPECS
                     if prov.lower() in provider.lower() and event_id in ids), None)
        if kind is None:
            continue
        if event_id in _ENRICH_KEY and entry.get("source_key") == "forensics":
            entry["source_key"] = _ENRICH_KEY[event_id]
            try:
                events_mod._enrich(entry)
            except Exception:  # noqa: BLE001 -- a decoder must never lose the marker
                pass
        ts = entry.get("timestamp")
        message = str(entry.get("title") or entry.get("detail") or provider)
        data = entry.get("data") or {}
        positional = data.get("_values") if isinstance(data, dict) else None
        marker: dict[str, Any] = {"kind": kind, "ts": ts, "message": message[:240], "who": None}
        if kind == "shutdown_request":
            # USER32 1074 EventData (positional): process, computer, user,
            # reason text, reason code, ..., type ("restart" / "power off").
            values = positional or []
            process = values[0] if len(values) > 0 else None
            user = values[6] if len(values) > 6 else (values[2] if len(values) > 2 else None)
            reason = values[3] if len(values) > 3 else None
            shutdown_type = (values[4] if len(values) > 4 else "") or ""
            for word, target in _TARGET_WORDS.items():
                if word in str(shutdown_type).lower() or word in message.lower():
                    marker["target"] = target
                    break
            marker.setdefault("target", "shutdown")
            marker["who"] = user or None
            marker["command"] = str(process or "").rsplit("\\", 1)[-1] or None
            marker["reason"] = reason or None
            marker["via"] = ("Windows Update" if any(
                w in str(process or "").lower() for w in ("wuauclt", "musnotification",
                                                           "mousocoreworker", "usoclient",
                                                           "tiworker"))
                             else None)
            marker["message"] = (f"{user or 'someone'} asked for a {marker['target']} via "
                                 f"{marker['command'] or 'an unknown process'}"
                                 + (f": {reason}" if reason else ""))[:240]
        elif kind == "shutdown_target":
            marker["target"] = "shutdown"
            marker["manager"] = "system"
        elif kind == "journal_stopped":
            marker["message"] = "The event log service stopped (clean shutdown path)"
        elif kind == "panic":
            bugcheck = entry.get("bugcheck") or {}
            marker["message"] = (f"BugCheck {bugcheck.get('code')} {bugcheck.get('name')}: "
                                 f"{bugcheck.get('meaning')}" if bugcheck else message)[:240]
            marker["stop_code"] = bugcheck.get("code")
        elif kind == "memory_exhaustion":
            consumers = ((entry.get("memory") or {}).get("consumers")) or []
            if consumers:
                marker["victim"] = consumers[0].get("name")
                marker["pid"] = consumers[0].get("pid")
                marker["consumers"] = consumers[:3]
        out.append(marker)
    out = [m for m in out if m.get("ts") is None or float(m["ts"]) <= died_at + 60]
    out.sort(key=lambda m: -(m.get("ts") or 0))
    return out[:40]


def _slim(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "ts": entry.get("timestamp"),
        "origin": entry.get("provider"),
        "priority": entry.get("level"),
        "message": str(entry.get("title") or entry.get("detail") or "")[:240],
        "unit": None,
    } for entry in entries]


def _agent_end(death: dict[str, Any], died_at: float) -> dict[str, Any]:
    """What Task Scheduler recorded about the agent's own task around its end.
    The Operational channel is off by default on client editions; when it is,
    the note says so and the host's verdict marks the exit unverified."""
    task = windows.own_service_name()
    out: dict[str, Any] = {"unit": task, "events": [], "code": None, "status": None,
                           "result": None, "oom": False, "stopped_by_systemd": False,
                           "pid": death.get("agent_pid"), "note": None}
    if not task:
        out["note"] = ("The agent was not started by its scheduled task (a --run in a "
                       "console), so nothing recorded how its previous run ended.")
        return out
    lookback_ms = int(max(0.0, time.time() - (died_at - 900)) * 1000)
    xpath = (f"*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]"
             f"[EventData[Data[@Name='TaskName']='\\{task}']]")
    try:
        entries = events_mod.query_channel(
            _spec("Microsoft-Windows-TaskScheduler/Operational"), 1, 60, xpath=xpath)
    except PermissionError:
        out["note"] = ("Task Scheduler's Operational log needs administrator rights to read.")
        return out
    except Exception as exc:  # noqa: BLE001
        out["note"] = f"Task Scheduler's Operational log could not be read: {windows.short_error(exc)}"
        return out
    for entry in entries:
        ts = entry.get("timestamp")
        if ts and float(ts) > died_at + 120:
            continue
        event_id = entry.get("id")
        data = entry.get("data") or {}
        out["events"].append({"ts": ts, "message": f"Task Scheduler event {event_id}: "
                              f"{str(entry.get('title') or '')[:200]}"})
        if event_id == 201 and out["code"] is None:       # action completed
            code = data.get("ResultCode")
            out["code"] = "exited"
            out["status"] = str(code) if code is not None else None
        elif event_id == 203 and out["code"] is None:     # action failed to start
            out["code"] = "failed"
            out["status"] = str(data.get("ResultCode") or "")
        elif event_id in (102, 111):                      # task completed / terminated
            out["stopped_by_systemd"] = out["stopped_by_systemd"] or event_id == 111
    out["events"] = out["events"][:20]
    if not out["events"]:
        out["note"] = (f"Task Scheduler logged nothing about {task} around the end of the "
                       "previous run (its Operational log is off by default: enable it under "
                       "Task Scheduler > View > Show All Tasks History).")
    return out


# ------------------------------------------------------------------ minidumps
def _minidumps() -> dict[str, Any]:
    """Crash dumps on disk play the role pstore does on Linux: a bugcheck
    leaves a minidump, and a full MEMORY.DMP after a kernel crash."""
    dumps = events_mod.minidumps()
    files = [{"path": f.get("path"), "size": f.get("size"), "modified": f.get("modified")}
             for f in (dumps.get("files") or [])]
    reason = dumps.get("reason")
    return {"files": files[:20],
            "readable": not (reason and "elevation" in str(reason)),
            "reason": reason, "head": None,
            "note": "Windows has no pstore; minidumps are the crash output that survives a reboot"}


# ---------------------------------------------------------------- packages
def _packages_before(died_at: float) -> list[dict[str, Any]]:
    """Windows Update installs shortly before the end: a cumulative update
    is the usual honest reason for a reboot, the way a kernel package is on
    Linux."""
    out = []
    lookback_days = max(1.0, (time.time() - (died_at - _PACKAGE_WINDOW_S)) / 86400 + 0.01)
    try:
        events = []
        for spec in events_mod.UPDATE_SPECS:
            events += events_mod.query_channel(spec, lookback_days, 100)
    except Exception as exc:  # noqa: BLE001
        log.debug("update history query failed: %s", exc)
        return []
    for event in events:
        ts = float(event.get("timestamp") or 0)
        if died_at - _PACKAGE_WINDOW_S <= ts <= died_at + 60:
            title = str(event.get("title") or "")
            out.append({"ts": ts, "title": title[:200],
                        "kernel": bool(re.search(r"cumulative update|feature update|"
                                                 r"servicing stack", title, re.I))})
    out.sort(key=lambda p: -p["ts"])
    return out[:10]


__all__ = ["investigate"]
