"""Previous-boot forensics: the evidence the Coroner reads after a death.

The flight recorder (recorder.py) says *how the machine was doing* when the
record stops. This module collects what the machine itself wrote down about
the end: the previous boot's last journal entries, the markers that separate
a clean shutdown from a hang (the shutdown target reached, logind announcing
a reboot, the sudo line that asked for it, the power key), the kernel's own
last words (OOM kills, panics, watchdog lockups, thermal trips, hung tasks),
what survived in pstore, the packages installed shortly before (a kernel
upgrade is the most common honest reason for a reboot), and -- when only the
agent died -- what systemd recorded about the agent's own unit.

Everything is a fact with a time. The verdict is the host's job
(culprit/coroner.py), because the host also holds the findings and the change
log it stored before the node went quiet, and because a verdict should be
one piece of code, not one per agent version.

Access is the usual story: the journal is group-gated and pstore is
root-only; each source reports its own reason when it cannot be read, and
the verdict says what could not be checked instead of guessing.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import time
from typing import Any

from .. import linux
from . import events as events_mod

log = logging.getLogger("culprit.forensics")

_TAIL_ENTRIES = 1500          # previous-boot entries scanned for markers
_KEEP_TAIL = 60               # entries shipped verbatim (slimmed) as "last words"
_LOOKBACK_S = 1800.0          # how far before the death the scan reaches
_PACKAGE_WINDOW_S = 7200.0

# Targets whose "Reached target" line proves the shutdown path ran: the
# machine was *told* to go down and got as far as systemd's own end.
_SHUTDOWN_TARGETS = {
    "shutdown.target": "shutdown", "reboot.target": "reboot",
    "poweroff.target": "poweroff", "halt.target": "halt",
    "kexec.target": "kexec", "final.target": "shutdown",
}

_TARGET_TEXT = re.compile(
    r"Reached target (?:System )?(Shutdown|Reboot|Power-?Off|Halt|Kexec|Soft Reboot|"
    r"Final Step|Late Shutdown Services)\.?$")
_TARGET_WORDS = {
    "shutdown": "shutdown", "reboot": "reboot", "power-off": "poweroff",
    "poweroff": "poweroff", "halt": "halt", "kexec": "kexec", "soft reboot": "reboot",
    "final step": "shutdown", "late shutdown services": "shutdown",
}

# (kind, compiled regex) over the rendered MESSAGE. Kernel lines have no
# MESSAGE_ID, and for the user-space ones the text is the stable part.
_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("logind_shutdown", re.compile(
        r"System is (rebooting|powering down|halting|suspending|hibernating)")),
    ("shutdown_notice", re.compile(
        r"The system (will|is going down for) (reboot|power off|power-off|halt|shutdown)")),
    ("power_key", re.compile(r"Power key pressed|Power button pressed")),
    ("sudo_shutdown", re.compile(
        r"COMMAND=\S*?(?:/)?(reboot|shutdown|poweroff|halt|init [06]|"
        r"systemctl (?:--\S+ )?(?:reboot|poweroff|halt|kexec|soft-reboot))")),
    ("unattended_reboot", re.compile(
        r"[Uu]nattended-[Uu]pgrade.*(?:[Rr]eboot|[Rr]estart)|needrestart.*reboot|"
        r"Automatic reboot")),
    ("oom_kill", re.compile(r"Out of memory: Killed process (\d+) \(([^)]+)\)")),
    ("oom_unit", re.compile(r"killed by the OOM killer")),
    ("panic", re.compile(r"Kernel panic|BUG: unable to handle|BUG: kernel NULL pointer|"
                         r"general protection fault|Oops: ")),
    ("watchdog", re.compile(r"soft lockup|hard LOCKUP|Watchdog detected|"
                            r"watchdog did not stop|watchdog: BUG")),
    ("thermal_critical", re.compile(r"critical temperature reached|Critical temperature|"
                                    r"thermal.*(shutdown|critical)")),
    ("hung_task", re.compile(r"blocked for more than \d+ seconds")),
    ("disk_error", re.compile(
        r"(blk_update_request: I/O error|Buffer I/O error|critical medium error"
        r"|EXT4-fs error|XFS .* corruption|nvme.*(timeout|resetting)"
        r"|ata\d+.*failed command)")),
    ("mce", re.compile(r"Machine Check Exception|mce: \[Hardware Error")),
    ("journal_stopped", re.compile(r"^Journal stopped$")),
    ("suspend", re.compile(r"PM: suspend entry|Entering sleep state")),
)

# What systemd says about a unit's end, for the agent-died case.
_UNIT_EXIT = re.compile(r"Main process exited, code=(\w+), status=(\S+)")
_UNIT_RESULT = re.compile(r"Failed with result '([^']+)'")
_UNIT_STOPPED = re.compile(r"Deactivated successfully|Stopped ")
_UNIT_STOPPING = re.compile(r"^Stopping ")


def investigate(death: dict[str, Any]) -> dict[str, Any]:
    """Evidence for one death record (from recorder.detect_death)."""
    started = time.perf_counter()
    died_at = float(death.get("died_at") or time.time())
    kind = str(death.get("kind") or "machine")
    access = linux.journal_access()
    readable = bool(access.get("readable"))
    boots = _boots()
    prev_id = death.get("prev_boot_id")
    evidence: dict[str, Any] = {
        "journal": {"readable": readable, "reason": access.get("reason"),
                    "persistent": bool(access.get("persistent"))},
        "boots": _boot_facts(boots, prev_id, death.get("boot_id")),
        "markers": [], "tail": [], "pstore": _pstore(),
        "packages": _packages_before(died_at),
        "agent": None, "notes": [],
    }
    if not readable:
        evidence["notes"].append(
            "The previous boot's journal could not be read, so the shutdown "
            "path, the kernel's last messages and the agent unit's exit are "
            f"unverifiable: {access.get('reason')}")
    elif kind == "machine":
        if prev_id and not evidence["boots"].get("previous"):
            evidence["notes"].append(
                "The journal has no record of the previous boot (the journal "
                "is volatile, or was rotated), so only the flight recorder "
                "says how the machine was doing at the end.")
        else:
            entries = _boot_entries(prev_id, died_at)
            evidence["markers"] = _markers(entries, died_at)
            evidence["tail"] = _slim(entries[:_KEEP_TAIL])
            if not entries:
                evidence["notes"].append(
                    "No journal entries were found for the previous boot in "
                    "the half hour before the record stops.")
    else:
        evidence["agent"] = _agent_end(death, died_at)
        entries = _kernel_entries(died_at)
        evidence["markers"] = _markers(entries, died_at)
        evidence["tail"] = _slim(entries[:20])
    evidence["cost_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return evidence


# ---------------------------------------------------------------- journal
def _boots() -> list[dict[str, Any]]:
    payload = linux.run_json(["journalctl", "--list-boots", "-o", "json", "-q",
                              "--no-pager"], timeout=20)
    return payload if isinstance(payload, list) else []


def _boot_facts(boots: list[dict[str, Any]], prev_id: Any,
                current_id: Any) -> dict[str, Any]:
    def entry(boot: dict[str, Any] | None) -> dict[str, Any] | None:
        if not boot:
            return None
        first = events_mod._to_int(boot.get("first_entry"))
        last = events_mod._to_int(boot.get("last_entry"))
        return {"boot_id": _plain_id(boot.get("boot_id")),
                "first": first / 1e6 if first else None,
                "last": last / 1e6 if last else None}

    previous = next((b for b in boots if _plain_id(b.get("boot_id")) == _plain_id(prev_id)), None)
    current = next((b for b in boots if _plain_id(b.get("boot_id")) == _plain_id(current_id)), None)
    prev_entry, cur_entry = entry(previous), entry(current)
    gap = None
    if prev_entry and cur_entry and prev_entry.get("last") and cur_entry.get("first"):
        gap = round(float(cur_entry["first"]) - float(prev_entry["last"]), 1)
    return {"count": len(boots), "previous": prev_entry, "current": cur_entry,
            "gap_seconds": gap}


def _plain_id(value: Any) -> str | None:
    """journalctl shows boot ids without dashes; /proc has them with."""
    if not value:
        return None
    return str(value).replace("-", "").lower()


def _boot_entries(boot_id: Any, died_at: float) -> list[dict[str, Any]]:
    """Newest-first entries of one boot from the half hour before the death."""
    plain = _plain_id(boot_id)
    if not plain:
        return []
    return linux.journalctl_json(
        ["-b", plain, "--since", f"@{int(died_at - _LOOKBACK_S)}"],
        timeout=40, max_entries=_TAIL_ENTRIES)


def _kernel_entries(died_at: float) -> list[dict[str, Any]]:
    """Kernel lines around an agent death (same boot): an OOM kill of the
    agent shows here, not in the unit's own log."""
    return linux.journalctl_json(
        ["-k", "--since", f"@{int(died_at - 900)}", "--until", f"@{int(died_at + 60)}"],
        timeout=20, max_entries=200)


def _markers(entries: list[dict[str, Any]], died_at: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries:
        message = events_mod._first_line(events_mod._msg(entry))
        ts = events_mod._stamp(entry)
        # "Reached target X" from either manager: the system manager's own
        # line is often lost (journald is already stopping by then), but the
        # user manager's "Reached target Shutdown." lands, and it proves the
        # same thing -- the machine was told to go down and got that far.
        unit = str(entry.get("UNIT") or entry.get("USER_UNIT") or "")
        target_match = _TARGET_TEXT.search(message)
        if message.startswith("Reached target") and (unit in _SHUTDOWN_TARGETS or target_match):
            target = _SHUTDOWN_TARGETS.get(unit) or _TARGET_WORDS.get(
                (target_match.group(1) if target_match else "").lower(), "shutdown")
            out.append({"kind": "shutdown_target", "ts": ts, "message": message,
                        "target": target, "who": None,
                        "manager": "user" if entry.get("USER_UNIT") or
                        str(entry.get("_SYSTEMD_UNIT") or "").startswith("user@") else "system"})
            continue
        for kind, pattern in _MARKERS:
            match = pattern.search(message)
            if not match:
                continue
            marker: dict[str, Any] = {"kind": kind, "ts": ts, "message": message[:240],
                                      "who": None}
            comm = str(entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER") or "")
            if kind == "sudo_shutdown":
                if comm not in ("sudo", "doas", "pkexec", "su"):
                    continue    # the word appears in other people's messages too
                marker["who"] = message.split(" :", 1)[0].strip() or None
                marker["command"] = match.group(1)
            elif kind == "logind_shutdown":
                marker["target"] = {"rebooting": "reboot", "powering down": "poweroff",
                                    "halting": "halt"}.get(match.group(1), match.group(1))
                # logind records the user id of the session that asked.
                marker["who"] = entry.get("USER_ID") or None
            elif kind == "shutdown_notice":
                marker["target"] = {"reboot": "reboot", "power off": "poweroff",
                                    "power-off": "poweroff", "halt": "halt",
                                    "shutdown": "poweroff"}.get(match.group(2), match.group(2))
            elif kind == "oom_kill":
                marker["pid"] = events_mod._to_int(match.group(1))
                marker["victim"] = match.group(2)
            elif kind == "oom_unit":
                marker["unit"] = str(entry.get("UNIT") or entry.get("_SYSTEMD_UNIT") or "")
            out.append(marker)
            break
    # Markers from the whole scan, but only the ones that fall before the
    # death (plus a minute of slack for clock skew between journal and agent)
    # can explain it; anything later belongs to the next boot's story.
    out = [m for m in out if m.get("ts") is None or float(m["ts"]) <= died_at + 60]
    out.sort(key=lambda m: -(m.get("ts") or 0))
    return out[:40]


def _origin(entry: dict[str, Any]) -> str:
    if entry.get("_TRANSPORT") == "kernel":
        return "kernel"
    return str(entry.get("_SYSTEMD_UNIT") or entry.get("SYSLOG_IDENTIFIER")
               or entry.get("_COMM") or "?")


def _slim(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "ts": events_mod._stamp(entry),
        "unit": _origin(entry),
        "priority": events_mod._to_int(entry.get("PRIORITY")),
        "message": events_mod._first_line(events_mod._msg(entry))[:240],
    } for entry in entries]


# -------------------------------------------------------------- agent end
def _agent_end(death: dict[str, Any], died_at: float) -> dict[str, Any]:
    """What systemd wrote about the agent's own unit around its end."""
    unit = linux.unit_from_cgroup(os.getpid())
    out: dict[str, Any] = {"unit": unit, "events": [], "code": None, "status": None,
                           "result": None, "oom": False, "stopped_by_systemd": False,
                           "pid": death.get("agent_pid"), "note": None}
    if not unit or unit.endswith(".scope"):
        out["note"] = ("The agent is not running as a systemd service (unit "
                       f"{unit or 'unknown'}), so systemd kept no record of how "
                       "its previous run ended.")
        return out
    entries = linux.journalctl_json(
        ["--since", f"@{int(died_at - 900)}", "--until", f"@{int(died_at + 120)}",
         "-u", unit], timeout=20, max_entries=200)
    for entry in entries:
        # Only systemd's own lines about the unit; the agent's stdout is
        # already in its log and would swamp the few lines that matter.
        if entry.get("_COMM") not in ("systemd", None) and entry.get("SYSLOG_IDENTIFIER") != "systemd":
            continue
        message = events_mod._first_line(events_mod._msg(entry))
        ts = events_mod._stamp(entry)
        out["events"].append({"ts": ts, "message": message[:240]})
        match = _UNIT_EXIT.search(message)
        if match and out["code"] is None:
            out["code"], out["status"] = match.group(1), match.group(2)
        match = _UNIT_RESULT.search(message)
        if match and out["result"] is None:
            out["result"] = match.group(1)
        if "OOM" in message or "oom-kill" in message:
            out["oom"] = True
        if _UNIT_STOPPING.search(message):
            out["stopped_by_systemd"] = True
    out["events"] = out["events"][:20]
    if not out["events"]:
        out["note"] = (f"systemd logged nothing about {unit} around the end of "
                       "the previous run.")
    return out


# ------------------------------------------------------------------ pstore
def _pstore() -> dict[str, Any]:
    """Crash output that survives a reboot in firmware-backed storage. The
    kernel's pstore is root-only; systemd-pstore moves the files into
    /var/lib/systemd/pstore, which is usually readable."""
    files: list[dict[str, Any]] = []
    reason = None
    for base in ("/sys/fs/pstore", "/var/lib/systemd/pstore"):
        try:
            for path in sorted(glob.glob(os.path.join(base, "**", "*"), recursive=True)):
                if not os.path.isfile(path):
                    continue
                stat = os.stat(path)
                files.append({"path": path, "size": stat.st_size,
                              "modified": stat.st_mtime})
        except PermissionError:
            reason = f"{base} needs root to read"
        except OSError:
            continue
    if not files and reason is None:
        try:
            os.listdir("/sys/fs/pstore")
        except PermissionError:
            reason = "/sys/fs/pstore needs root to read (systemd-pstore may " \
                     "have moved its files to /var/lib/systemd/pstore, which is empty)"
        except OSError:
            reason = "no pstore on this machine"
    head = None
    for entry in sorted(files, key=lambda f: -float(f["modified"])):
        if "dmesg" in os.path.basename(str(entry["path"])) or "console" in str(entry["path"]):
            text = linux.read_text(str(entry["path"]))
            if text:
                head = text[:2000]
                entry["read"] = True
                break
    return {"files": files[:20], "readable": reason is None, "reason": reason,
            "head": head}


# ---------------------------------------------------------------- packages
def _packages_before(died_at: float) -> list[dict[str, Any]]:
    out = []
    for event in events_mod._apt_history(lookback_days=3, limit=100):
        ts = float(event.get("timestamp") or 0)
        if died_at - _PACKAGE_WINDOW_S <= ts <= died_at + 60:
            title = str(event.get("title") or "")
            out.append({"ts": ts, "title": title[:200],
                        "kernel": bool(re.search(r"linux-(image|headers|modules|generic|virtual)|"
                                                 r"\bkernel\b", title))})
    return out[:10]
