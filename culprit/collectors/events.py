"""System events from journald: crashes, OOM kills, disk errors, boots,
sessions, updates and pending-reboot state.

This replaces 1,200 lines of Windows event-log code with a fraction of that,
for two structural reasons:

* **journald fields are structured.** `MESSAGE_ID`, `UNIT`, `_SYSTEMD_UNIT`
  and `COREDUMP_*` are matched directly instead of parsing rendered text --
  the Windows build's worst bug (EvtFormatMessage silently reinterpreting an
  event ID as a Win32 error code and returning plausible, wrong text) has no
  Linux equivalent as long as we never trust rendered strings for identity.
* **A subprocess is cheap here.** `journalctl -o json` costs ~5ms to spawn;
  the queries themselves measured 0.1-2.6s warm (13s once, cold cache, at
  startup) on a 1.3GB journal. The events tier runs every 120s, so this is
  well within budget and avoids compiling python-systemd.

MESSAGE_IDs below were enumerated on the target system with
`journalctl --list-catalog` (systemd 255, Ubuntu 24.04) -- not recalled from
memory, per the porting notes. Text patterns are used only where the kernel
genuinely logs unstructured text (OOM, segfaults, IO errors).
"""

from __future__ import annotations

import glob
import logging
import os
import re
import time

from .. import linux

log = logging.getLogger("culprit.events")

# From `journalctl --list-catalog` on this machine (systemd 255):
MSGID_UNIT_FAILED = "d9b373ed55a64feb8242e02dbe79a49c"   # systemd: Unit failed
MSGID_COREDUMP = "fc2e22bc6ee647b6b90729ab34a250b1"      # Process dumped core

# Kernel log text patterns. The kernel has no MESSAGE_IDs for these; the
# patterns are the stable, greppable phrasing the kernel itself emits.
_KERNEL_PATTERNS: tuple[tuple[str, str, str, str, str], ...] = (
    # (source_key, severity, regex, label, hint)
    ("oom_kill", "critical", r"Out of memory: Killed process",
     "Out-of-memory kill",
     "The kernel ran out of memory and killed a process to survive. Whatever "
     "was killed lost its state; whatever caused the exhaustion may still be "
     "running."),
    ("app_crash", "error", r"segfault at [0-9a-f]+ ip",
     "Segmentation fault",
     "A process crashed on an invalid memory access."),
    ("app_crash", "error", r"trap (divide error|invalid opcode|int3)",
     "Process trap", "A process crashed on a CPU trap."),
    ("hung_task", "error", r"blocked for more than \d+ seconds",
     "Task hung in kernel",
     "khungtaskd: a task sat in uninterruptible sleep past the hang "
     "threshold -- almost always stuck storage or a dead network mount."),
    ("disk_error", "critical",
     r"(blk_update_request: I/O error|Buffer I/O error|critical medium error"
     r"|EXT4-fs error|XFS .* corruption|nvme.*(timeout|resetting)"
     r"|ata\d+.*failed command)",
     "Disk / filesystem error",
     "The block layer or filesystem reported a hardware-level error. Check "
     "SMART data and back up early."),
    ("mce", "critical", r"(Machine Check Exception|mce: \[Hardware Error)",
     "Hardware error (MCE)",
     "The CPU reported a machine-check -- possible RAM, cache or power "
     "problem. rasdaemon/EDAC has details if installed."),
)


class EventCollector:
    def __init__(self) -> None:
        self.access = linux.journal_access()
        self._boots_cache: list[dict] | None = None
        self._boots_at = 0.0
        self._auth_cache: list[dict] = []
        self._auth_cursor: str | None = None
        self.last_duration_ms = 0.0

    def sample(self, lookback_days: int = 30, max_per_source: int = 200
               ) -> dict[str, object]:
        started = time.perf_counter()
        since = f"-{int(lookback_days)}d"
        readable = bool(self.access.get("readable"))

        crashes: list[dict] = []
        policy: list[dict] = []
        failed: dict[str, str] = {}
        if readable:
            crashes += self._kernel_events(since, max_per_source)
            crashes += self._coredumps(since, max_per_source)
            crashes += self._unit_failures(since, max_per_source)
            policy += self._auth_failures(since, max_per_source)
            policy += self._suppressed(since, max_per_source)
        else:
            failed["journal"] = str(self.access.get("reason"))

        boots = self._boots()
        crashes += _unclean_shutdowns(boots, lookback_days)
        crashes.sort(key=lambda e: -(e.get("timestamp") or 0))

        updates = _apt_history(lookback_days, max_per_source)
        sessions = self._sessions(boots, lookback_days, readable)

        self.last_duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            "generated_at": time.time(),
            "lookback_days": lookback_days,
            "elevated": os.geteuid() == 0,
            "journal": dict(self.access),
            "sample_ms": self.last_duration_ms,
            "failed_channels": failed,
            "crashes": {
                "events": crashes[:max_per_source * 2],
                "summary": _summarise(crashes),
                # Apport / kdump artefacts play the role Windows minidumps did.
                "crash_files": _crash_files(),
            },
            "updates": {"events": updates, "summary": _summarise(updates)},
            "policy": {"events": policy, "summary": _summarise(policy)},
            "sessions": sessions,
            "pending_reboot": pending_reboot(),
        }

    # ------------------------------------------------------------- journald
    def _kernel_events(self, since: str, limit: int) -> list[dict]:
        combined = "|".join(f"({pattern})" for _, _, pattern, _, _
                            in _KERNEL_PATTERNS)
        entries = linux.journalctl_json(
            ["-k", "--since", since, "-g", combined],
            timeout=40, max_entries=limit * 2)
        out = []
        for entry in entries:
            message = _msg(entry)
            for source_key, severity, pattern, label, hint in _KERNEL_PATTERNS:
                if re.search(pattern, message):
                    out.append(_event(entry, kind="crash", source_key=source_key,
                                      source_label=label, severity=severity,
                                      title=_first_line(message), detail=hint))
                    break
        return out

    def _coredumps(self, since: str, limit: int) -> list[dict]:
        """systemd-coredump entries, matched on MESSAGE_ID rather than text."""
        entries = linux.journalctl_json(
            ["--since", since, f"MESSAGE_ID={MSGID_COREDUMP}"],
            timeout=30, max_entries=limit)
        out = []
        for entry in entries:
            exe = entry.get("COREDUMP_EXE") or entry.get("COREDUMP_COMM") or "?"
            sig = entry.get("COREDUMP_SIGNAL_NAME") or entry.get("COREDUMP_SIGNAL")
            out.append(_event(
                entry, kind="crash", source_key="app_crash",
                source_label="Core dump", severity="error",
                title=f"{os.path.basename(str(exe))} dumped core ({sig})",
                detail=_first_line(_msg(entry)),
                app={"name": os.path.basename(str(exe)), "path": exe,
                     "signal": sig,
                     "pid": _to_int(entry.get("COREDUMP_PID"))},
            ))
        return out

    def _unit_failures(self, since: str, limit: int) -> list[dict]:
        entries = linux.journalctl_json(
            ["--since", since, f"MESSAGE_ID={MSGID_UNIT_FAILED}"],
            timeout=30, max_entries=limit)
        # A restart-looping unit fails hundreds of times and would drown every
        # other event; keep the newest few per unit and carry the true count.
        per_unit: dict[str, int] = {}
        out = []
        for entry in entries:  # newest first
            unit = str(entry.get("UNIT") or entry.get("_SYSTEMD_UNIT") or "?")
            per_unit[unit] = per_unit.get(unit, 0) + 1
            if per_unit[unit] > 3:
                continue
            out.append(_event(
                entry, kind="crash", source_key="service_fail",
                source_label="Unit failed", severity="error",
                title=f"{unit} entered failed state",
                detail=_first_line(_msg(entry)),
                service={"name": unit},
            ))
        for event in out:
            unit = str((event.get("service") or {}).get("name"))
            if per_unit.get(unit, 0) > 3:
                event["detail"] = (f"Failed {per_unit[unit]} times in this "
                                   "window (showing the newest 3) -- a restart "
                                   "loop. " + str(event.get("detail") or ""))
        return out

    _AUTH_FIRST_PULL_DAYS = 2

    def _auth_failures(self, since: str, limit: int) -> list[dict]:
        """Failed sign-ins from sshd / sudo / PAM in the journal.

        /var/log/btmp would corroborate but needs root; the journal already
        has the same events for anyone in the journal group.

        This query is incremental on purpose. An internet-facing box logs a
        line per SSH connection (56k sshd entries in 30 days on this machine),
        and journalctl's -g grep runs over every one of them: a 30-day pull
        measured 20-26s. So the first pull covers only the last couple of
        days (~5s, paid during warm-up) and every later tick reads just the
        entries after the stored cursor (~16ms).
        """
        # No _COMM field matches here on purpose: a `+` disjunction of matches
        # makes journalctl ignore the cursor/-n short-circuit and scan the
        # whole journal (measured: 26s vs 16ms). The regex alone is selective
        # enough; the identifier filter happens below in Python.
        args = ["-g",
                r"(Failed password|authentication failure|Invalid user"
                r"|maximum authentication attempts)"]
        if self._auth_cursor:
            # reverse=False is load-bearing: --after-cursor plus -r makes
            # journalctl scan the whole journal (see linux.journalctl_json).
            entries = list(reversed(linux.journalctl_json(
                ["--after-cursor", self._auth_cursor, *args],
                timeout=30, max_entries=limit, reverse=False)))
        else:
            entries = linux.journalctl_json(
                ["--since", f"-{self._AUTH_FIRST_PULL_DAYS}d", *args],
                timeout=45, max_entries=limit)
        # Advance the cursor to the journal tail either way -- anchoring on
        # the last *match* would re-grep everything since it on every tick.
        tail = linux.journalctl_json([], timeout=10, max_entries=1)
        if tail:
            self._auth_cursor = tail[0].get("__CURSOR") or self._auth_cursor
        out = []
        for entry in entries:
            if entry.get("_COMM") not in ("sshd", "sshd-session", "sudo",
                                          "login", "su"):
                continue
            message = _first_line(_msg(entry))
            # sshd logs both a pam_unix line and a "Failed password" line for
            # the same attempt; keeping only the latter halves the noise
            # without losing an event.
            if (entry.get("_COMM") in ("sshd", "sshd-session")
                    and message.startswith("pam_unix")):
                continue
            out.append(_event(
                entry, kind="policy", source_key="auth_fail",
                source_label="Failed sign-in", severity="warn",
                title=message,
                detail=f"Auth history starts {self._AUTH_FIRST_PULL_DAYS} days "
                       "before Culprit first ran (older sshd noise is too "
                       "expensive to grep) and accumulates from there."))
        self._auth_cache = (out + self._auth_cache)[:limit]
        return list(self._auth_cache)

    def _suppressed(self, since: str, limit: int) -> list[dict]:
        """journald's own rate limiting -- surfaced so gaps in this very
        timeline are honest rather than silently missing."""
        entries = linux.journalctl_json(
            ["--since", since, "SYSLOG_IDENTIFIER=systemd-journald",
             "-g", r"[Ss]uppressed \d+ messages"],
            timeout=20, max_entries=limit)
        return [
            _event(entry, kind="policy", source_key="journal_ratelimit",
                   source_label="Journal rate limit", severity="info",
                   title=_first_line(_msg(entry)),
                   detail="journald dropped messages from this unit; this "
                          "window of the timeline is incomplete.")
            for entry in entries
        ]

    # ----------------------------------------------------------------- boots
    def _boots(self) -> list[dict]:
        # Past boots never change; only the current boot's last_entry moves.
        now = time.monotonic()
        if self._boots_cache is None or now - self._boots_at > 3600:
            payload = linux.run_json(["journalctl", "--list-boots", "-o", "json",
                                      "-q", "--no-pager"], timeout=20)
            self._boots_cache = payload if isinstance(payload, list) else []
            self._boots_at = now
        return self._boots_cache

    def _sessions(self, boots: list[dict], lookback_days: int,
                  readable: bool) -> dict[str, object]:
        """Sign-in history from logind.

        loginctl gives the authoritative *current* sessions (including
        LockedHint, readable without any privilege -- the inverse of Windows,
        where lock state needed the admin-only Security log). History comes
        from systemd-logind's journal messages, paired on session id, so the
        times are the ones logind recorded.
        """
        current = linux.run_json(["loginctl", "list-sessions", "-o", "json"],
                                 timeout=10)
        current_sessions = current if isinstance(current, list) else []
        open_ids = set()
        locked_hints = {}
        for session in current_sessions:
            sid = str(session.get("session"))
            open_ids.add(sid)
            props = linux.run(["loginctl", "show-session", sid,
                               "-p", "Type", "-p", "Class", "-p", "Service",
                               "-p", "Remote", "-p", "RemoteHost", "-p", "TTY",
                               "-p", "State", "-p", "LockedHint", "-p", "IdleHint"],
                              timeout=5)
            fields = dict(line.partition("=")[::2] for line in
                          (props or "").splitlines())
            # list-sessions carries the login name; keep it beside the props so
            # a current row can name *who* is on (and, via Service, that it's SSH).
            fields["_user"] = session.get("user") or fields.get("Name") or None
            locked_hints[sid] = fields

        note = None
        timeline: list[dict] = []
        summary: dict[str, object] = {}
        cutoff = time.time() - lookback_days * 86400

        if readable:
            # journalctl_json returns newest first; pairing New/Removed needs
            # chronological order.
            entries = list(reversed(linux.journalctl_json(
                ["--since", f"-{lookback_days}d", "_COMM=systemd-logind",
                 "-g", r"(New session|Removed session)"],
                timeout=30, max_entries=4000)))
            starts: dict[str, dict] = {}
            closed: list[dict] = []
            new_re = re.compile(r"New session (\S+) of user (\S+)\.")
            gone_re = re.compile(r"Removed session (\S+)\.")
            for entry in entries:
                message = _msg(entry)
                when = _stamp(entry)
                match = new_re.search(message)
                if match:
                    starts[match.group(1)] = {"start": when,
                                              "user": match.group(2)}
                    continue
                match = gone_re.search(message)
                if match:
                    opened = starts.pop(match.group(1), None)
                    if opened and opened["start"]:
                        closed.append({
                            "user": opened["user"], "start": opened["start"],
                            "end": when, "open": False, "exact": True,
                            "end_inferred": False,
                            "duration": (when - opened["start"]) if when else None,
                        })
            # Sessions with a start and no removal: either still open, or the
            # machine went down with them -- the reboot bounds the end.
            for sid, opened in starts.items():
                still_open = sid in open_ids
                end = None if still_open else _boot_end_after(boots, opened["start"])
                closed.append({
                    "user": opened["user"], "start": opened["start"],
                    "end": end, "open": still_open, "exact": still_open,
                    "end_inferred": not still_open,
                    "duration": ((end or time.time()) - opened["start"])
                    if opened["start"] else None,
                })
            timeline = sorted((s for s in closed if (s["start"] or 0) >= cutoff),
                              key=lambda s: -(s["start"] or 0))[:60]
        else:
            note = ("Session history needs journal access: " +
                    str(self.access.get("reason")))

        boot_events = _boot_timeline(boots, lookback_days)
        locks = [
            {"timestamp": None, "action": "locked" if
             fields.get("LockedHint") == "yes" else "unlocked",
             "user": None, "session": sid}
            for sid, fields in locked_hints.items()
        ]
        summary = {
            "sessions": len(timeline),
            "open_sessions": len(open_ids),
            "total_seconds": round(sum(s.get("duration") or 0 for s in timeline)),
            "boots": sum(1 for b in boot_events if b["action"] == "boot"),
            "shutdowns": sum(1 for b in boot_events if b["action"] == "shutdown"),
            "locks": None,      # logind exposes current LockedHint, not history
            "unlocks": None,
            "lock_events": [],  # no historical lock log outside desktop DEs
            "boot_events": boot_events,
        }
        return {
            "available": True,
            "source": "logind" if readable else "loginctl-only",
            "exact": readable,
            "note": note,
            "requires_elevation": not readable,
            "current": [
                {"id": sid,
                 "user": fields.get("_user"),
                 "type": fields.get("Type"),
                 "class": fields.get("Class") or None,
                 # The PAM service that opened it -- "sshd" is the SSH marker.
                 "service": fields.get("Service") or None,
                 "remote": fields.get("Remote") == "yes",
                 "tty": fields.get("TTY") or None,
                 "remote_host": fields.get("RemoteHost") or None,
                 "state": fields.get("State") or None,
                 "locked": fields.get("LockedHint") == "yes",
                 "idle": fields.get("IdleHint") == "yes"}
                for sid, fields in locked_hints.items()
            ],
            "locks": locks,
            "timeline": timeline,
            "summary": summary,
        }

    def close(self) -> None:
        pass


# --------------------------------------------------------------------- events
def _event(entry: dict, kind: str, source_key: str, source_label: str,
           severity: str, title: str, detail: str | None, **extra: object) -> dict:
    return {
        "id": None,  # journald identity is the cursor, not a numeric id
        "record_id": entry.get("__CURSOR"),
        "channel": "journal",
        "provider": (entry.get("_SYSTEMD_UNIT") or entry.get("SYSLOG_IDENTIFIER")
                     or entry.get("_COMM")),
        "source_key": source_key,
        "source_label": source_label,
        "kind": kind,
        "level": _level(entry.get("PRIORITY")),
        "severity": severity,
        "timestamp": _stamp(entry),
        "user": None,
        "title": title[:300],
        "detail": detail,
        "data": {k: v for k, v in entry.items()
                 if k in ("UNIT", "_PID", "_UID", "_SYSTEMD_UNIT",
                          "SYSLOG_IDENTIFIER", "_BOOT_ID")},
        **extra,
    }


def _msg(entry: dict) -> str:
    message = entry.get("MESSAGE")
    if isinstance(message, list):  # journald encodes non-UTF8 as byte arrays
        try:
            message = bytes(message).decode("utf-8", "replace")
        except (TypeError, ValueError):
            message = ""
    return str(message or "")


def _first_line(text: str) -> str:
    return text.split("\n", 1)[0][:300]


def _stamp(entry: dict) -> float | None:
    raw = entry.get("_SOURCE_REALTIME_TIMESTAMP") or entry.get("__REALTIME_TIMESTAMP")
    value = _to_int(raw)
    return value / 1e6 if value else None


def _level(priority: object) -> str:
    try:
        return {0: "emergency", 1: "alert", 2: "critical", 3: "error",
                4: "warning", 5: "notice", 6: "info", 7: "debug"}[int(priority)]  # type: ignore[arg-type]
    except (TypeError, ValueError, KeyError):
        return "info"


def _to_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _summarise(events: list[dict]) -> dict[str, object]:
    by_source: dict[str, int] = {}
    for event in events:
        key = str(event.get("source_key"))
        by_source[key] = by_source.get(key, 0) + 1
    return {"total": len(events), "by_source": by_source}


# ----------------------------------------------------------------------- boots
def _unclean_shutdowns(boots: list[dict], lookback_days: int) -> list[dict]:
    """A gap between one boot's last journal entry and the next boot's first
    entry is normal; a previous boot whose journal just *stops* mid-activity
    with no shutdown record is the analogue of Windows event 6008.

    The reliable low-cost heuristic: journald writes continuously until a
    clean shutdown; if the next boot started more than a few minutes after the
    previous boot's last entry, the machine most likely lost power or hung --
    journald keeps writing to the very end of a clean shutdown.
    """
    out = []
    cutoff = (time.time() - lookback_days * 86400) * 1e6
    for previous, current in zip(boots, boots[1:]):
        last = _to_int(previous.get("last_entry"))
        first = _to_int(current.get("first_entry"))
        if not last or not first or last < cutoff:
            continue
        gap = (first - last) / 1e6
        if gap > 600:
            out.append({
                "id": None,
                "record_id": f"unclean:{previous.get('boot_id')}",
                "channel": "journal", "provider": "journald",
                "source_key": "unclean_shutdown",
                "source_label": "Possible unclean shutdown",
                "kind": "crash", "level": "warning", "severity": "warn",
                "timestamp": last / 1e6, "user": None,
                "title": ("Journal for the previous boot ends "
                          f"{gap / 60:.0f} min before the next boot"),
                "detail": "The journal stopped abruptly and the machine came "
                          "back much later -- consistent with a power loss, "
                          "hang or panic rather than a clean shutdown. (A "
                          "machine that was simply switched off for a while "
                          "looks the same; treat this as a hint, not proof.)",
                "data": {"boot_id": previous.get("boot_id")},
            })
    return out


def _boot_timeline(boots: list[dict], lookback_days: int) -> list[dict]:
    cutoff = (time.time() - lookback_days * 86400) * 1e6
    out = []
    for boot in boots:
        first = _to_int(boot.get("first_entry"))
        last = _to_int(boot.get("last_entry"))
        if first and first >= cutoff:
            out.append({"action": "boot", "timestamp": first / 1e6,
                        "title": "Booted"})
        is_current = boot is boots[-1]
        if last and last >= cutoff and not is_current:
            out.append({"action": "shutdown", "timestamp": last / 1e6,
                        "title": "Shut down / journal ended"})
    out.sort(key=lambda b: -(b["timestamp"] or 0))
    return out[:40]


def _boot_end_after(boots: list[dict], start: float | None) -> float | None:
    if start is None:
        return None
    for boot in boots:
        first = _to_int(boot.get("first_entry"))
        last = _to_int(boot.get("last_entry"))
        if first and last and first / 1e6 <= start <= last / 1e6:
            return last / 1e6
    return None


# ------------------------------------------------------------------- apt / dpkg
def _apt_history(lookback_days: int, limit: int) -> list[dict]:
    """Package operations from /var/log/apt/history.log (Debian/Ubuntu).

    A plain world-readable file, so no privilege gate. On RPM distros this
    section simply reports nothing; the pending-reboot matrix below covers
    them separately.
    """
    out: list[dict] = []
    cutoff = time.time() - lookback_days * 86400
    for path in ("/var/log/apt/history.log",):
        text = linux.read_text(path)
        if not text:
            continue
        for block in text.strip().split("\n\n"):
            fields: dict[str, str] = {}
            for line in block.splitlines():
                key, found, value = line.partition(": ")
                if found:
                    fields[key] = value
            start = fields.get("Start-Date")
            if not start:
                continue
            try:
                when = time.mktime(time.strptime(start, "%Y-%m-%d  %H:%M:%S"))
            except ValueError:
                continue
            if when < cutoff:
                continue
            actions = []
            for verb in ("Install", "Upgrade", "Remove", "Purge"):
                if verb in fields:
                    # "pkg:arch (versions), pkg2:arch (...)" -- name the first
                    # few packages, count the rest.
                    names = [chunk.strip().split(":")[0]
                             for chunk in re.split(r"\([^)]*\),?", fields[verb])
                             if chunk.strip()]
                    shown = ", ".join(names[:4])
                    more = f" +{len(names) - 4} more" if len(names) > 4 else ""
                    actions.append(f"{verb.lower()}: {shown}{more}")
            error = fields.get("Error")
            out.append({
                "id": None, "record_id": f"apt:{start}", "channel": "apt",
                "provider": (fields.get("Commandline") or "apt").split()[0],
                "source_key": "update_fail" if error else "update_ok",
                "source_label": "Package operation failed" if error
                                else "Packages updated",
                "kind": "update", "level": "error" if error else "info",
                "severity": "warn" if error else "info",
                "timestamp": when, "user": fields.get("Requested-By"),
                "title": (", ".join(actions) or "package operation")
                + (f" -- {error}" if error else ""),
                "detail": (fields.get("Commandline") or "")[:200] or None,
                "data": {},
            })
    out.sort(key=lambda e: -(e["timestamp"] or 0))
    return out[:limit]


# --------------------------------------------------------------- crash files
def _crash_files() -> dict[str, object]:
    """Crash artefacts on disk: apport reports and kdump/pstore remains."""
    files = []
    for pattern in ("/var/crash/*", "/var/lib/systemd/coredump/*"):
        for path in glob.glob(pattern):
            try:
                stat = os.stat(path)
                files.append({"name": os.path.basename(path), "path": path,
                              "size": stat.st_size, "modified": stat.st_mtime})
            except OSError:
                continue
    files.sort(key=lambda f: -f["modified"])
    pstore_note = None
    try:
        pstore = os.listdir("/sys/fs/pstore")
        if pstore:
            pstore_note = (f"{len(pstore)} file(s) in /sys/fs/pstore -- panic "
                           "output from a previous boot survives there")
    except PermissionError:
        pstore_note = "/sys/fs/pstore needs root to read"
    except OSError:
        pass
    return {"count": len(files), "files": files[:20], "pstore": pstore_note,
            "reason": None if files else "nothing in /var/crash or "
                                         "/var/lib/systemd/coredump"}


# ------------------------------------------------------------- pending reboot
def pending_reboot() -> dict[str, object]:
    """Distro matrix plus the universal deleted-libraries scan.

    The deleted-mappings scan is what `needrestart` does and it is more
    actionable than any flag file: it names the processes actually running
    against updated libraries. /proc/<pid>/maps is permission-gated like
    /proc/<pid>/io, so the unreadable count is reported.
    """
    reasons: list[str] = []
    sources: dict[str, object] = {}

    # Debian/Ubuntu flag file, written by update-notifier.
    if os.path.exists("/var/run/reboot-required"):
        packages = (linux.read_text("/var/run/reboot-required.pkgs") or "").split()
        reasons.append("packages require a restart"
                       + (f": {', '.join(sorted(set(packages))[:6])}" if packages
                          else ""))
        sources["reboot_required_file"] = True

    # Running kernel older than the newest installed one.
    running = os.uname().release
    try:
        installed = sorted(os.listdir("/usr/lib/modules"), key=_kernel_sort_key)
        newest = installed[-1] if installed else None
        if newest and _kernel_sort_key(newest) > _kernel_sort_key(running):
            reasons.append(f"kernel {newest} is installed but {running} is running")
        sources["kernel"] = {"running": running, "newest_installed": newest}
    except OSError:
        pass

    # Deleted mapped libraries: processes running against files that were
    # replaced by an update.
    stale_pids: list[int] = []
    unreadable = 0
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/maps", "r") as handle:
                    for line in handle:
                        if line.rstrip().endswith("(deleted)") and (
                                ".so" in line or "/usr/lib" in line
                                or "/usr/bin" in line):
                            stale_pids.append(int(name))
                            break
            except OSError:
                unreadable += 1
    except OSError:
        pass
    if stale_pids:
        reasons.append(f"{len(stale_pids)} process(es) still map deleted "
                       "libraries or binaries (restart them, or reboot)")
    sources["deleted_maps"] = {
        "processes": stale_pids[:40],
        "unreadable_processes": unreadable,
        "note": ("only own processes are scannable without CAP_SYS_PTRACE"
                 if unreadable else None),
    }

    return {"pending": bool(reasons), "reasons": reasons, "sources": sources}


def _kernel_sort_key(release: str) -> tuple:
    parts = re.split(r"[.-]", release)
    key = []
    for part in parts:
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)
