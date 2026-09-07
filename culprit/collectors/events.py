"""Windows event log: crashes, bluescreens, sessions, updates, policy.

Reads through `win32evtlog`'s Evt* API rather than shelling out to
`Get-WinEvent`. A PowerShell round trip costs ~700ms of process startup and
there are a dozen queries here; the native API answers all of them in about
three seconds including message construction.

Filtering happens *inside* the event log via XPath, including the time window
(`timediff`), so Windows never hands over 30 days of records for Python to
discard.

**Why descriptions are written here instead of read from Windows.**
The obvious approach is `EvtFormatMessage`, which renders a provider's own
message text. It is not usable: pywin32's `EvtOpenPublisherMetadata` rejects
every argument form with "The object is not a PyHANDLE object", and calling
`EvtFormatMessage` with `None` metadata -- which *appears* to work -- silently
reinterprets the event ID as a Win32 error code and returns that system string
instead. The results look completely plausible and are entirely wrong:

    Application Hang, event 1002  -> "The window cannot act on the sent message."
    Kernel-Power,     event 521   -> "The operation was aborted because the
                                      observed volume identity..."

Both are the Win32 error strings for 1002 and 521. Shipping that would put
confident nonsense on a dashboard, so message-table rendering is not used at
all. Instead every event's fields are extracted by *name* from its EventData and
composed into a description here. That is more work but it is accurate, it is
concise (Windows' own text is wrapped boilerplate), and it can say what a thing
*means* rather than only what happened.

Elevation matters in exactly one place: the Security channel -- interactive
logon (4624), logoff (4634/4647), lock/unlock (4800/4801), failed sign-ins
(4625) -- returns ERROR_ACCESS_DENIED to a standard user. The session history
then falls back to the User Profile Service channel, which is readable
unelevated. That fallback is approximate and the payload says so.

**The payload is the Linux agent's shape.** `journal` describes the event
log's readability the way the Linux field describes journald's (the System
and Application channels are always readable; `persistent` is always true --
the event log survives reboots); `crashes.crash_files` lists the minidumps;
`sessions.current` comes from the terminal-services session table (WTS), the
Windows counterpart of loginctl, and is readable unelevated; the source keys
the dashboard groups on are shared where the meaning is the same
(`app_crash`, `disk_error`, `service_fail`, `update_ok`, `update_fail`,
`unclean_shutdown`, `mce`, `auth_fail`) and Windows-only otherwise
(`bugcheck`, `app_hang`, `dotnet`, `low_memory`, `policy_*`, `time_sync`,
`netlogon`, `dns_client`).
"""

from __future__ import annotations

import functools
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.etree import ElementTree

import psutil

from .. import windows
from ..util import is_elevated

log = logging.getLogger("culprit.events")

win32evtlog = windows.win32evtlog
AVAILABLE = win32evtlog is not None

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Windows Level values. 1 and 2 are the ones worth surfacing.
_LEVELS = {0: "info", 1: "critical", 2: "error", 3: "warning", 4: "info", 5: "verbose"}


@dataclass(frozen=True)
class EventSpec:
    key: str
    label: str
    channel: str
    ids: tuple[int, ...]
    kind: str
    severity: str = "warn"
    providers: tuple[str, ...] = ()
    requires_admin: bool = False
    limit: int = 60
    descriptions: dict[int, str] = field(default_factory=dict)


# --------------------------------------------------------------------- catalogue
CRASH_SPECS: tuple[EventSpec, ...] = (
    EventSpec(
        key="bugcheck", label="Bluescreen (BugCheck)", channel="System",
        ids=(1001,), providers=("Microsoft-Windows-WER-SystemErrorReporting",),
        kind="crash", severity="critical", limit=40,
    ),
    EventSpec(
        key="unclean_shutdown", label="Unclean shutdown (Kernel-Power 41)", channel="System",
        ids=(41,), providers=("Microsoft-Windows-Kernel-Power",),
        kind="crash", severity="critical", limit=40,
        descriptions={41: "The system restarted without shutting down cleanly - "
                          "power loss, a hard reset, or a crash too severe to log."},
    ),
    EventSpec(
        key="unclean_shutdown", label="Unexpected shutdown (6008)", channel="System",
        ids=(6008,), providers=("EventLog",), kind="crash", severity="critical",
        limit=40,
        descriptions={6008: "The previous shutdown was unexpected."},
    ),
    EventSpec(
        key="mce", label="Hardware error (WHEA)", channel="System",
        ids=(1, 17, 18, 19, 20, 47), providers=("Microsoft-Windows-WHEA-Logger",),
        kind="hardware", severity="critical", limit=60,
        descriptions={1: "The platform reported a hardware error. Repeated "
                         "entries point at RAM, the CPU, or the PCIe bus."},
    ),
    EventSpec(
        key="app_crash", label="Application crash", channel="Application",
        ids=(1000,), providers=("Application Error",), kind="app",
        severity="error", limit=120,
    ),
    EventSpec(
        key="app_hang", label="Application hang", channel="Application",
        ids=(1002,), providers=("Application Hang",), kind="app",
        severity="error", limit=120,
    ),
    EventSpec(
        key="dotnet", label=".NET runtime error", channel="Application",
        ids=(1023, 1026, 1027), providers=(".NET Runtime",), kind="app",
        severity="error", limit=60,
        descriptions={1026: "A .NET application threw an exception it did not "
                            "handle, which terminates the process."},
    ),
    EventSpec(
        key="disk_error", label="Disk / storage error", channel="System",
        ids=(7, 11, 51, 52, 55, 98, 129, 153, 157), kind="storage",
        severity="error", limit=80,
        providers=("disk", "Disk", "Ntfs", "volmgr", "storahci", "stornvme",
                   "iaStorA", "iaStorAC"),
        descriptions={
            7: "A bad block was found on the disk.",
            11: "The driver detected a controller error.",
            51: "A paging error occurred during a disk write.",
            52: "The disk is predicting its own failure. Back up now.",
            55: "The file system structure is corrupt. Run chkdsk.",
            98: "An NTFS operation could not be completed.",
            129: "The storage controller had to be reset - a request timed out. "
                 "This causes multi-second whole-system freezes.",
            153: "An I/O request was retried after failing.",
            157: "The disk was surprise-removed.",
        },
    ),
    EventSpec(
        key="low_memory", label="Low virtual memory", channel="System",
        ids=(2004,), providers=("Microsoft-Windows-Resource-Exhaustion-Detector",),
        kind="crash", severity="critical", limit=40,
        descriptions={2004: "Windows diagnosed a low virtual memory condition: the "
                            "commit charge reached its limit. The event names the "
                            "processes that consumed the most."},
    ),
    EventSpec(
        key="service_fail", label="Service failure", channel="System",
        ids=(7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7034),
        providers=("Service Control Manager",), kind="service",
        severity="error", limit=120,
    ),
)

UPDATE_SPECS: tuple[EventSpec, ...] = (
    EventSpec(
        key="update_ok", label="Update installed", channel="System",
        ids=(19,), providers=("Microsoft-Windows-WindowsUpdateClient",),
        kind="update", severity="info", limit=80,
    ),
    EventSpec(
        key="update_fail", label="Update failed", channel="System",
        ids=(20, 24, 25, 31, 34, 35),
        providers=("Microsoft-Windows-WindowsUpdateClient",),
        kind="update", severity="error", limit=80,
    ),
)

POLICY_SPECS: tuple[EventSpec, ...] = (
    EventSpec(
        key="policy_error", label="Group Policy error", channel="System",
        ids=(1030, 1055, 1058, 1085, 1096, 1097, 1129),
        providers=("Microsoft-Windows-GroupPolicy",), kind="policy",
        severity="error", limit=60,
        descriptions={
            1030: "Group Policy could not be queried from the domain.",
            1055: "Group Policy could not resolve the computer's domain name.",
            1058: "Group Policy could not read a policy file from the domain "
                  "share - usually a network or permissions problem.",
            1085: "A Group Policy extension failed to apply. Some settings on "
                  "this machine are not what the domain intends them to be.",
            1096: "A registry policy file could not be applied.",
            1129: "Group Policy could not be applied because no domain "
                  "controller was reachable at boot. Common on laptops that "
                  "start up off the corporate network.",
        },
    ),
    EventSpec(
        key="policy_apply", label="Group Policy applied", channel="System",
        ids=(1500, 1501, 1502, 1503), providers=("Microsoft-Windows-GroupPolicy",),
        kind="policy", severity="info", limit=20,
        descriptions={
            1500: "Computer and user policy applied successfully.",
            1501: "User policy applied successfully.",
            1502: "Computer policy applied successfully.",
            1503: "Policy applied successfully.",
        },
    ),
    EventSpec(
        key="time_sync", label="Time sync problem", channel="System",
        ids=(36, 38, 47, 129, 134, 144),
        providers=("Microsoft-Windows-Time-Service",),
        kind="sync", severity="warn", limit=40,
        descriptions={
            36: "The time service has not synchronised for too long.",
            38: "The time service is no longer receiving valid samples.",
            47: "No response from the configured time source.",
            134: "A time sample was rejected as out of range. Clock skew this "
                 "large breaks Kerberos, and therefore single sign-on.",
            144: "The system clock was stepped by a large amount.",
        },
    ),
    EventSpec(
        key="netlogon", label="Domain connectivity", channel="System",
        ids=(5719, 5783, 5807), providers=("NETLOGON", "Netlogon"),
        kind="sync", severity="warn", limit=40,
        descriptions={
            5719: "No domain controller was available. Mapped drives, single "
                  "sign-on and domain resources fail until this clears.",
            5783: "The session to the domain controller is no longer available.",
            5807: "Clients were served from a site with no site mapping.",
        },
    ),
    EventSpec(
        key="dns_client", label="Name resolution", channel="System",
        ids=(1014,), providers=("Microsoft-Windows-DNS-Client",),
        kind="sync", severity="warn", limit=40,
        descriptions={1014: "A DNS query timed out. Slow or failing name "
                            "resolution makes everything feel broken."},
    ),
)

# Security channel: exact interactive session history. Administrator only.
SESSION_SPECS: tuple[EventSpec, ...] = (
    EventSpec(key="logon", label="Sign-in", channel="Security", ids=(4624,),
              kind="session", severity="info", requires_admin=True, limit=200),
    EventSpec(key="logoff", label="Sign-out", channel="Security", ids=(4634, 4647),
              kind="session", severity="info", requires_admin=True, limit=200),
    EventSpec(key="lock", label="Lock / unlock", channel="Security",
              ids=(4800, 4801), kind="session", severity="info",
              requires_admin=True, limit=200),
    EventSpec(key="auth_fail", label="Failed sign-in", channel="Security",
              ids=(4625,), kind="session", severity="warn",
              requires_admin=True, limit=100),
    EventSpec(key="lockout", label="Account locked out", channel="Security",
              ids=(4740,), kind="session", severity="error",
              requires_admin=True, limit=40),
)

# Unelevated fallback. Profile load/unload brackets each sign-in and sign-out.
PROFILE_SPECS: tuple[EventSpec, ...] = (
    EventSpec(
        key="profile", label="Profile load / unload",
        channel="Microsoft-Windows-User Profile Service/Operational",
        ids=(1, 2, 3, 4, 5, 6), kind="session", severity="info", limit=200,
        descriptions={
            1: "Sign-in started - the user profile is being loaded.",
            2: "Sign-in completed - the user profile finished loading.",
            3: "Sign-out started.",
            4: "Sign-out - the profile is being unloaded.",
            5: "Sign-out completed - the profile was unloaded.",
        },
    ),
    EventSpec(
        key="boot", label="Boot / shutdown", channel="System",
        ids=(6005, 6006, 6013), providers=("EventLog",), kind="session",
        severity="info", limit=100,
    ),
)

# Stop codes that actually turn up on managed laptops, with what they mean.
STOP_CODES: dict[int, tuple[str, str]] = {
    0x0000000A: ("IRQL_NOT_LESS_OR_EQUAL", "A driver touched pageable memory at too high an IRQL. Almost always a driver bug."),
    0x0000001A: ("MEMORY_MANAGEMENT", "The memory manager found an inconsistency. Test the RAM."),
    0x0000001E: ("KMODE_EXCEPTION_NOT_HANDLED", "A kernel component raised an exception nobody handled."),
    0x00000024: ("NTFS_FILE_SYSTEM", "A fault inside the NTFS driver, often caused by failing storage."),
    0x0000003B: ("SYSTEM_SERVICE_EXCEPTION", "An exception during a system call, usually from a graphics or security driver."),
    0x00000050: ("PAGE_FAULT_IN_NONPAGED_AREA", "Invalid memory was referenced. Suspect faulty RAM or a driver writing out of bounds."),
    0x0000007A: ("KERNEL_DATA_INPAGE_ERROR", "A page could not be read back from disk. Storage or its cabling is failing."),
    0x0000007E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A system thread raised an unhandled exception."),
    0x0000009F: ("DRIVER_POWER_STATE_FAILURE", "A driver did not complete a power transition. The classic sleep/resume bluescreen."),
    0x000000C2: ("BAD_POOL_CALLER", "A driver made an illegal pool allocation."),
    0x000000C4: ("DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier caught a driver misbehaving."),
    0x000000D1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A driver accessed bad memory at high IRQL. Network and storage drivers are the usual culprits."),
    0x000000EF: ("CRITICAL_PROCESS_DIED", "A process Windows cannot run without exited."),
    0x000000F4: ("CRITICAL_OBJECT_TERMINATION", "A critical system object was terminated."),
    0x0000012B: ("FAULTY_HARDWARE_CORRUPTED_PAGE", "A single-bit memory error. Run a memory test."),
    0x00000124: ("WHEA_UNCORRECTABLE_ERROR", "The platform reported a fatal hardware error - CPU, RAM, or bus."),
    0x00000133: ("DPC_WATCHDOG_VIOLATION", "A DPC ran too long, often a storage driver or firmware issue."),
    0x00000139: ("KERNEL_SECURITY_CHECK_FAILURE", "A kernel data structure failed a corruption check."),
    0x0000015A: ("KERNEL_STORAGE_SLOT_IN_USE", "A storage slot conflict."),
    0x000001CA: ("SYNTHETIC_WATCHDOG_TIMEOUT", "A watchdog fired while the system was unresponsive."),
}

# Exception codes on Application Error 1000. Says *how* the app died.
EXCEPTION_CODES: dict[int, str] = {
    0xC0000005: "Access violation - read or wrote memory it does not own",
    0xC0000006: "In-page error - a memory-mapped file could not be read",
    0xC000001D: "Illegal instruction",
    0xC0000025: "Non-continuable exception",
    0xC0000094: "Integer divide by zero",
    0xC0000096: "Privileged instruction",
    0xC00000FD: "Stack overflow - usually runaway recursion",
    0xC0000135: "A required DLL was not found",
    0xC0000142: "A DLL failed to initialise",
    0xC0000374: "Heap corruption detected",
    0xC0000409: "Stack buffer overrun - caught by /GS",
    0xC000041D: "Unhandled exception inside a callback",
    0xE0434352: ".NET unhandled exception",
    0xE06D7363: "Unhandled C++ exception",
    0x80000003: "Breakpoint - a debug build hit an assertion",
    0xCFFFFFFF: "Application self-terminated abnormally",
}

# Windows Update result codes worth naming.
WU_ERRORS: dict[int, str] = {
    0x80240022: "All updates in the batch failed",
    0x8024200B: "Install failed and was rolled back",
    0x80070020: "A file needed by the update was locked by another process",
    0x80070005: "Access denied",
    0x80070070: "Not enough disk space",
    0x800F0922: "Could not install - often too little space in the reserved partition",
    0x80244022: "The update server returned HTTP 503 (busy)",
    0x8024402C: "Could not reach the update server - proxy or DNS problem",
    0x80D02002: "Download timed out",
}

_HEX = re.compile(r"0x([0-9a-fA-F]{8,16})")



# --------------------------------------------------------------------- querying
class EventCollector:
    def __init__(self) -> None:
        self._failed_channels: dict[str, str] = {}
        self.last_duration_ms = 0.0
        # The Linux field: is the log readable at all, and does it survive a
        # reboot. The System/Application channels always are; the Security
        # channel is the gated part and is reported per query.
        self.access = {
            "readable": AVAILABLE,
            "reason": None if AVAILABLE else windows.missing("win32evtlog"),
            "persistent": True,
            "groups": None,
        }

    def sample(self, lookback_days: int = 30, max_per_source: int = 200
               ) -> dict[str, object]:
        started = time.perf_counter()
        elevated = is_elevated()

        crashes = self._gather(CRASH_SPECS, lookback_days, max_per_source)
        updates = self._gather(UPDATE_SPECS, lookback_days, max_per_source)
        policy = self._gather(POLICY_SPECS, lookback_days, max_per_source)

        if elevated:
            session_events = self._gather(SESSION_SPECS, lookback_days, max_per_source)
            session_source = "security"
            session_note = None
        else:
            session_events = self._gather(PROFILE_SPECS, lookback_days, max_per_source)
            session_source = "profile"
            session_note = (
                "Sign-in and sign-out times below are derived from the User "
                "Profile Service log, because the Security event log requires "
                "administrator rights. Times are approximate (the profile loads "
                "shortly after sign-in and unloads shortly after sign-out), and "
                "lock/unlock times and failed sign-in attempts are not "
                "available at this privilege level."
            )
        # Failed sign-ins are security events, not session history: the
        # dashboard's Events view groups them with the other auth failures.
        policy += [e for e in session_events if e.get("source_key") == "auth_fail"]
        policy.sort(key=lambda item: float(item.get("timestamp") or 0), reverse=True)

        sessions = _build_sessions(session_events, session_source)

        self.last_duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            "generated_at": time.time(),
            "lookback_days": lookback_days,
            "elevated": elevated,
            "journal": dict(self.access),
            "sample_ms": self.last_duration_ms,
            "failed_channels": dict(self._failed_channels),
            "crashes": {
                "events": crashes,
                "summary": _summarise(crashes),
                # Minidumps play the role apport / kdump artefacts do on Linux.
                "crash_files": minidumps(),
            },
            "updates": {"events": updates, "summary": _summarise(updates)},
            "policy": {"events": policy, "summary": _summarise(policy)},
            "sessions": {
                "available": True,
                "source": session_source,
                "exact": session_source == "security",
                "note": session_note,
                "requires_elevation": not elevated,
                "events": session_events,
                "current": current_sessions(),
                "locks": [],
                "timeline": sessions["timeline"],
                "summary": sessions["summary"],
            },
            "pending_reboot": pending_reboot(),
        }

    # ---------------------------------------------------------------- engine
    def _gather(self, specs: tuple[EventSpec, ...], lookback_days: int,
                cap: int) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        for spec in specs:
            try:
                out.extend(query_channel(spec, lookback_days, min(spec.limit, cap)))
            except PermissionError as exc:
                self._failed_channels[spec.channel] = str(exc)
            except Exception as exc:  # noqa: BLE001 -- one channel must not kill the tier
                self._failed_channels[spec.channel] = _short(exc)
                log.debug("event query %s failed: %s", spec.key, exc)
        out.sort(key=lambda item: float(item.get("timestamp") or 0), reverse=True)
        return out

    def close(self) -> None:
        pass


def query_channel(spec: EventSpec, lookback_days: float, limit: int,
                  xpath: str | None = None) -> list[dict[str, object]]:
    """Newest-first events of one spec within the lookback. Shared with the
    Coroner's forensics, which asks for a specific window."""
    if win32evtlog is None:
        return []
    xpath = xpath or _build_xpath(spec.ids, spec.providers, lookback_days)
    try:
        handle = win32evtlog.EvtQuery(
            spec.channel, win32evtlog.EvtQueryReverseDirection, xpath, None
        )
    except Exception as exc:
        code = getattr(exc, "args", (None,))[0]
        if code == 5:  # ERROR_ACCESS_DENIED
            raise PermissionError(
                f"the {spec.channel} channel requires administrator rights"
            ) from exc
        raise

    results: list[dict[str, object]] = []
    while len(results) < limit:
        try:
            batch = win32evtlog.EvtNext(handle, min(20, limit - len(results)))
        except Exception:  # noqa: BLE001 -- end of the log raises on some builds
            break
        if not batch:
            break
        for raw in batch:
            parsed = _parse(raw, spec)
            if parsed is not None:
                results.append(parsed)
    return results


# ----------------------------------------------------------- current sessions
_WTS_STATE = {0: "active", 1: "connected", 2: "connect_query", 3: "shadow",
              4: "disconnected", 5: "idle", 6: "listen", 7: "reset", 8: "down",
              9: "init"}


def current_sessions() -> list[dict[str, object]]:
    """Who is signed in right now, from the terminal-services session table:
    the Windows counterpart of `loginctl list-sessions`, readable without
    elevation. Lock state is not in the table; LogonUI.exe running inside a
    session is the reliable sign that its lock (or sign-in) screen is up."""
    ts = windows.win32ts
    if ts is None:
        return []
    try:
        sessions = ts.WTSEnumerateSessions(ts.WTS_CURRENT_SERVER_HANDLE)
    except Exception as exc:  # noqa: BLE001
        log.debug("WTSEnumerateSessions failed: %s", exc)
        return []
    logon_ui = _logon_ui_sessions()
    out: list[dict[str, object]] = []
    for session in sessions:
        sid = int(session.get("SessionId", 0))
        station = str(session.get("WinStationName") or "")
        state = _WTS_STATE.get(int(session.get("State", 9)), "unknown")
        if station.lower() == "services" or state in ("listen", "down", "init", "reset"):
            continue

        def info(kind: int) -> object:
            try:
                return ts.WTSQuerySessionInformation(ts.WTS_CURRENT_SERVER_HANDLE, sid, kind)
            except Exception:  # noqa: BLE001
                return None

        user = info(ts.WTSUserName)
        if not user:
            continue    # a console session with nobody on it
        domain = info(ts.WTSDomainName)
        client = info(ts.WTSClientName)
        protocol = info(ts.WTSClientProtocolType)
        remote = protocol == 2       # 0 console, 1 ICA, 2 RDP
        out.append({
            "id": str(sid),
            "user": (f"{domain}\\{user}" if domain and str(domain).lower() != str(user).lower()
                     else str(user)),
            "type": "rdp" if remote else "console",
            "class": "user",
            "service": "rdp" if remote else (station.lower() or None),
            "remote": remote,
            "tty": station or None,
            "remote_host": str(client) if remote and client else None,
            "state": state,
            "locked": sid in logon_ui,
            "idle": state == "disconnected",
        })
    return out


def _logon_ui_sessions() -> set[int]:
    """Session ids with a LogonUI.exe (the lock / sign-in screen) running."""
    ts = windows.win32ts
    found: set[int] = set()
    if ts is None:
        return found
    try:
        for proc in psutil.process_iter(["name"]):
            if str(proc.info.get("name") or "").lower() != "logonui.exe":
                continue
            try:
                found.add(int(ts.ProcessIdToSessionId(proc.pid)))
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return found


def _parse(raw: object, spec: EventSpec) -> dict[str, object] | None:
    try:
        xml = win32evtlog.EvtRender(raw, win32evtlog.EvtRenderEventXml)
        root = ElementTree.fromstring(xml)
    except Exception:
        return None

    system = root.find("e:System", _NS)
    if system is None:
        return None

    event_id = _int(_text(system.find("e:EventID", _NS)))
    provider_el = system.find("e:Provider", _NS)
    provider = (provider_el.get("Name") if provider_el is not None else None) or ""
    time_el = system.find("e:TimeCreated", _NS)
    timestamp = _parse_time(time_el.get("SystemTime") if time_el is not None else None)
    level = _int(_text(system.find("e:Level", _NS))) or 0

    # The acting account lives in System/Security/@UserID, not in EventData.
    # This is the only place the User Profile Service events identify a user.
    security_el = system.find("e:Security", _NS)
    user_sid = security_el.get("UserID") if security_el is not None else None

    entry: dict[str, object] = {
        "id": event_id,
        "record_id": _int(_text(system.find("e:EventRecordID", _NS))),
        "channel": spec.channel,
        "provider": provider,
        "source_key": spec.key,
        "source_label": spec.label,
        "kind": spec.kind,
        "level": _LEVELS.get(level, "info"),
        "severity": spec.severity,
        "timestamp": timestamp,
        "computer": _text(system.find("e:Computer", _NS)),
        "user_sid": user_sid,
        "user": resolve_sid(user_sid) if user_sid else None,
        "data": _event_data(root),
        "hint": spec.descriptions.get(event_id or -1),
    }
    _enrich(entry)
    return entry


# ------------------------------------------------------------------- enrichment
def _enrich(entry: dict[str, object]) -> None:
    """Give every event a title and a description built from its own fields."""
    event_id = entry.get("id")
    data = entry.get("data") or {}
    positional = data.get("_values") if isinstance(data, dict) else None
    key = entry["source_key"]

    def field_of(*names: str, index: int | None = None) -> str | None:
        for name in names:
            value = data.get(name)
            if value not in (None, ""):
                return str(value)
        if index is not None and positional and 0 <= index < len(positional):
            return positional[index] or None
        return None

    if key == "bugcheck":
        code = _stop_code(data, positional)
        parameters = _stop_parameters(data, positional)
        if code is not None:
            name, meaning = STOP_CODES.get(
                code,
                ("UNKNOWN_STOP_CODE",
                 "This stop code is not in the local table. Look it up against "
                 "the matching minidump."),
            )
            entry["title"] = f"Bluescreen - {name}"
            entry["detail"] = meaning
            entry["bugcheck"] = {"code": f"0x{code:08X}", "name": name,
                                 "meaning": meaning, "parameters": parameters}
        else:
            entry["title"] = "Bluescreen"
            entry["detail"] = ("The machine rebooted from a stop error, but the "
                               "stop code was not recorded in the event.")
        return

    if key == "app_crash":
        # Field names verified against real events: ModuleName, not ModName.
        app = field_of("AppName", index=0)
        module = field_of("ModuleName", index=3)
        exception = field_of("ExceptionCode", index=6)
        code = _hex_int(exception)
        meaning = EXCEPTION_CODES.get(code or -1) if code is not None else None
        entry["title"] = f"{app or 'An application'} crashed"
        pieces = []
        if module:
            pieces.append(f"Faulted inside {module}")
        if meaning:
            pieces.append(meaning)
        elif exception:
            pieces.append(f"Exception 0x{exception.upper()}")
        entry["detail"] = ". ".join(pieces) + "." if pieces else \
            "The application terminated unexpectedly."
        entry["app"] = {
            "name": app,
            "version": field_of("AppVersion", index=1),
            "faulting_module": module,
            "module_version": field_of("ModuleVersion", index=4),
            "module_path": field_of("ModulePath", index=11),
            "exception_code": exception,
            "exception_meaning": meaning,
            "fault_offset": field_of("FaultingOffset", index=7),
            "pid": _hex_int(field_of("ProcessId", index=8)),
            "path": field_of("AppPath", index=10),
            "package": field_of("PackageFullName", index=13),
        }
        return

    if key == "app_hang":
        app = field_of("AppName", index=0)
        hang_type = field_of("HangType", index=9)
        entry["title"] = f"{app or 'An application'} stopped responding"
        entry["detail"] = (
            "The window stopped processing messages and Windows terminated it."
            + (f" Hang type: {hang_type}." if hang_type else "")
        )
        entry["app"] = {
            "name": app,
            "version": field_of("AppVersion", index=1),
            "pid": _hex_int(field_of("ProcessId", index=2)),
            "path": field_of("ExeFileName", index=5),
            "hang_type": hang_type,
            "package": field_of("PackageFullName", index=7),
        }
        return

    if key == "service_fail":
        first = _clean(field_of("param1", index=0))
        second = _clean(field_of("param2", index=1))
        # Field order is not consistent across Service Control Manager events.
        # Most put the service name first ("The %1 service terminated..."), but
        # the two timeout events put the *timeout* first and the service name
        # second ("Timeout (%1 milliseconds) waiting for the %2 service..."),
        # which produced titles like "30000 timed out starting".
        if event_id in (7009, 7011):
            service, timeout = second, first
            extra = f"after {timeout} ms" if timeout else None
        elif event_id in (7031, 7034):
            # "...has done this %2 time(s)." A bare "Reported: 1" said nothing;
            # the repeat count is the interesting part of a crashing service.
            service = first
            extra = (f"{second} occurrence{'s' if second != '1' else ''} so far"
                     if second else None)
        else:
            service, extra = first, second
        entry["title"] = f"{service or 'A service'} {_service_verb(event_id)}"
        entry["detail"] = _SERVICE_MEANINGS.get(
            event_id or -1, "The service control manager reported a failure."
        )
        if extra:
            entry["detail"] = f"{entry['detail']} Reported: {extra}."
        entry["service"] = {"name": service, "extra": extra}
        return

    if key in ("update_ok", "update_fail"):
        title = field_of("updateTitle", index=0)
        error = field_of("errorCode", index=1)
        code = _hex_int(error)
        entry["title"] = title or ("An update was installed"
                                   if key == "update_ok" else "An update failed")
        if key == "update_ok":
            entry["detail"] = "Installed successfully."
        else:
            named = WU_ERRORS.get(code or -1)
            entry["detail"] = (named or "The update did not install.") + (
                f" (code 0x{code:08X})" if code is not None else ""
            )
        entry["update"] = {"title": title, "error_code": error,
                           "error_meaning": WU_ERRORS.get(code or -1)}
        return

    if key == "logon":
        logon_type = _int(field_of("LogonType", index=8))
        label = LOGON_TYPES.get(logon_type or -1, f"type {logon_type}")
        user = field_of("TargetUserName", index=5)
        entry["title"] = f"Sign-in - {user or 'unknown user'}"
        entry["detail"] = f"Logon type {logon_type}: {label}."
        entry["session"] = {
            "action": "logon", "user": user,
            "domain": field_of("TargetDomainName", index=6),
            "logon_id": field_of("TargetLogonId", index=7),
            "logon_type": logon_type, "logon_type_label": label,
            "process": field_of("ProcessName", index=17),
            "workstation": field_of("WorkstationName", index=11),
            "source_ip": field_of("IpAddress", index=18),
        }
        return

    if key == "logoff":
        user = field_of("TargetUserName", index=1)
        entry["title"] = f"Sign-out - {user or 'unknown user'}"
        entry["detail"] = ("The user signed out." if event_id == 4647
                           else "The logon session ended.")
        entry["session"] = {
            "action": "logoff", "user": user,
            "domain": field_of("TargetDomainName", index=2),
            "logon_id": field_of("TargetLogonId", index=3),
        }
        return

    if key == "lock":
        locked = event_id == 4800
        user = field_of("TargetUserName", index=1)
        entry["title"] = ("Workstation locked" if locked
                          else "Workstation unlocked") + (f" - {user}" if user else "")
        entry["detail"] = ("The session was locked."
                           if locked else "The session was unlocked.")
        entry["session"] = {"action": "lock" if locked else "unlock", "user": user,
                            "logon_id": field_of("TargetLogonId", index=3)}
        return

    if key == "auth_fail":
        user = field_of("TargetUserName", index=5)
        entry["title"] = f"Failed sign-in - {user or 'unknown user'}"
        status = field_of("Status", index=7)
        entry["detail"] = _LOGON_FAILURE.get(
            (_hex_int(field_of("SubStatus", index=9)) or _hex_int(status) or -1),
            "The sign-in attempt was rejected.",
        )
        entry["session"] = {
            "action": "failed", "user": user,
            "domain": field_of("TargetDomainName", index=6), "status": status,
            "source_ip": field_of("IpAddress", index=19),
        }
        return

    if key == "lockout":
        user = field_of("TargetUserName", index=0)
        entry["title"] = f"Account locked out - {user or 'unknown user'}"
        entry["detail"] = ("Too many failed sign-in attempts locked the account. "
                           "A stale credential in a service or mapped drive is a "
                           "common cause.")
        entry["session"] = {"action": "lockout", "user": user}
        return

    if key == "profile":
        action = {1: "logon_start", 2: "logon", 3: "logoff_start",
                  4: "logoff_start", 5: "logoff"}.get(event_id or -1)
        # These events carry no user name in EventData -- only a session number,
        # and for unload events the profile path and SID. The acting account
        # comes from System/Security/@UserID, resolved in _parse.
        user = entry.get("user") or _profile_user_from_data(data)
        entry["title"] = {
            "logon_start": "Sign-in started", "logon": "Sign-in completed",
            "logoff_start": "Sign-out started", "logoff": "Sign-out completed",
        }.get(action or "", f"Profile event {event_id}")
        if user:
            entry["title"] = f"{entry['title']} - {user}"
        entry["detail"] = str(entry.get("hint") or "")
        entry["session"] = {"action": action, "user": user,
                            "logon_session": data.get("Session")}
        return

    if key == "boot":
        # 6013 is the *daily uptime report*, not a shutdown. Classifying anything
        # that was not 6005 as a shutdown produced 61 shutdowns against 2 boots.
        action = {6005: "boot", 6006: "shutdown", 6013: "uptime_report"}.get(
            event_id or -1
        )
        if action == "uptime_report":
            # Positional field 4 holds the uptime in seconds; the first four are
            # empty in real events.
            seconds = _first_number(positional)
            entry["title"] = (f"Uptime report - {seconds / 86400:.1f} days"
                              if seconds else "Daily uptime report")
            entry["detail"] = ("The event log service reports system uptime once "
                               "a day. Useful as a liveness record, not an event.")
            entry["uptime_seconds"] = seconds
        else:
            entry["title"] = ("System booted" if action == "boot"
                              else "System shut down cleanly")
            entry["detail"] = ("The event log service started, which marks the "
                               "start of a boot." if action == "boot"
                               else "The event log service stopped as part of an "
                                    "orderly shutdown.")
        entry["session"] = {"action": action}
        return

    if key == "low_memory":
        # EventData: consumed by up to three processes, as name/pid/bytes
        # triplets (names differ by build; take them by prefix).
        consumers = []
        for index in range(1, 4):
            name = field_of(f"Process{index}Name", f"ProcessName{index}")
            if not name:
                continue
            consumers.append({
                "name": name,
                "pid": _int(field_of(f"Process{index}Id", f"ProcessId{index}")),
                "bytes": _int(field_of(f"Process{index}Bytes", f"ProcessBytes{index}")),
            })
        entry["title"] = "Virtual memory ran out"
        entry["detail"] = str(entry.get("hint") or "")
        if consumers:
            entry["detail"] += " Largest: " + ", ".join(
                f"{c['name']} (pid {c['pid']})" if c.get("pid") else str(c["name"])
                for c in consumers) + "."
        entry["memory"] = {"consumers": consumers}
        return

    if key == "dotnet":
        # .NET Runtime writes the exception type and stack as one unnamed blob.
        blob = (positional or [""])[0] if positional else ""
        first_line = next((line.strip() for line in str(blob).splitlines()
                           if line.strip()), "")
        exception_type = None
        match = re.search(r"([A-Za-z0-9_.]+Exception)", str(blob))
        if match:
            exception_type = match.group(1)
        entry["title"] = (f"Unhandled {exception_type}" if exception_type
                          else ".NET runtime error")
        entry["detail"] = str(entry.get("hint") or "")
        entry["dotnet"] = {"exception_type": exception_type,
                           "first_line": first_line[:400]}
        return

    # Everything else: the curated description is the detail, and the source
    # label is the title. The event id is already a separate field, so it does
    # not need to be jammed into the headline.
    entry["title"] = str(entry["source_label"])
    entry["detail"] = str(entry.get("hint") or "")


LOGON_TYPES = {
    2: "interactive, at the keyboard",
    3: "network - a file share or RPC call",
    4: "batch - a scheduled task",
    5: "service",
    7: "unlock",
    8: "network, cleartext credentials",
    9: "new credentials (runas /netonly)",
    10: "remote interactive (RDP)",
    11: "cached interactive - signed in without reaching a domain controller",
    12: "cached remote interactive",
    13: "cached unlock",
}

# Logon types that mean a human is using the machine. Network and service
# logons happen hundreds of times a day and are not sessions.
INTERACTIVE_LOGON_TYPES = {2, 7, 10, 11, 12, 13}

_SERVICE_MEANINGS = {
    7000: "The service could not be started at all.",
    7001: "The service could not start because a service it depends on failed.",
    7009: "The service did not signal that it had started within the timeout.",
    7011: "The service did not respond to a control request in time - it is hung.",
    7022: "The service hung during startup.",
    7023: "The service stopped because of an error.",
    7024: "The service stopped with a service-specific error.",
    7026: "A boot-start or system-start driver failed to load.",
    7031: "The service terminated unexpectedly and Windows will try to recover it.",
    7034: "The service terminated unexpectedly and has no recovery action.",
}

_LOGON_FAILURE = {
    0xC0000064: "The account name does not exist.",
    0xC000006A: "The password was wrong.",
    0xC000006D: "The credentials did not match.",
    0xC000006E: "An account restriction blocked the sign-in.",
    0xC000006F: "Sign-in outside the permitted hours.",
    0xC0000070: "Sign-in from a workstation this account may not use.",
    0xC0000071: "The password has expired.",
    0xC0000072: "The account is disabled.",
    0xC0000133: "The clocks are too far apart between this machine and the domain.",
    0xC0000193: "The account has expired.",
    0xC0000224: "The user must change their password.",
    0xC0000234: "The account is locked out.",
}


_PLACEHOLDER = re.compile(r"^%{1,2}\d+$")


def _clean(value: str | None) -> str | None:
    """Drop unexpanded message-table insertion strings.

    Some providers write `%%1` or `%1` into EventData when the real text lives
    only in a message table we cannot read (see the module docstring on
    EvtFormatMessage). Rendering that verbatim produced lines like "The service
    stopped because of an error. Reported: %%1." -- worse than saying nothing.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def _service_verb(event_id: int | None) -> str:
    return {
        7000: "failed to start", 7001: "failed - a dependency did not start",
        7009: "timed out starting", 7011: "stopped responding",
        7022: "hung on startup", 7023: "stopped with an error",
        7024: "stopped with a service-specific error",
        7026: "failed to load", 7031: "terminated unexpectedly",
        7034: "terminated unexpectedly",
    }.get(event_id or -1, "reported a failure")


def _stop_code(data: dict, positional: list[str] | None) -> int | None:
    for name in ("BugcheckCode",):
        value = data.get(name)
        if value:
            try:
                return int(str(value), 10) & 0xFFFFFFFF
            except ValueError:
                pass
    # WER-SystemErrorReporting 1001 writes the whole "0x... (0x..., ...)" string
    # as a positional value on most builds.
    for candidate in (positional or []):
        match = _HEX.search(candidate)
        if match:
            try:
                return int(match.group(1), 16) & 0xFFFFFFFF
            except ValueError:
                continue
    return None


def _stop_parameters(data: dict, positional: list[str] | None) -> list[str]:
    """The four bugcheck parameters, which narrow down the faulting driver."""
    for name in ("BugcheckParameter1", "BugcheckParameter2",
                 "BugcheckParameter3", "BugcheckParameter4"):
        if name in data:
            return [str(data[name_]) for name_ in
                    ("BugcheckParameter1", "BugcheckParameter2",
                     "BugcheckParameter3", "BugcheckParameter4")
                    if data.get(name_)]
    for candidate in (positional or []):
        inside = re.search(r"\(([^)]*0x[^)]*)\)", candidate)
        if inside:
            return [part.strip() for part in inside.group(1).split(",")
                    if "0x" in part][:4]
    return []


def _profile_user_from_data(data: dict) -> str | None:
    """Profile unload events carry the SID in `Key` and the path in `File`."""
    sid = data.get("Key")
    if sid:
        # "S-1-5-21-..._Classes" -> strip the suffix before resolving.
        text = str(sid).split("_")[0]
        resolved = resolve_sid(text)
        if resolved:
            return resolved
    path = data.get("File")
    if path:
        # C:\Users\olai.boe\ntuser.dat -> olai.boe
        parts = str(path).replace("/", "\\").split("\\")
        if "Users" in parts:
            index = parts.index("Users")
            if index + 1 < len(parts):
                return parts[index + 1]
    return None


@functools.lru_cache(maxsize=512)
def resolve_sid(sid_text: str | None) -> str | None:
    """SID -> 'DOMAIN\\account'. Cached; a domain lookup can cost a round trip."""
    if not sid_text or not sid_text.startswith("S-"):
        return None
    win32security = windows.win32security
    if win32security is None:
        return None
    try:
        sid = win32security.ConvertStringSidToSid(sid_text)
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}" if domain else name
    except Exception:
        return None


# ---------------------------------------------------------------- session build
def _build_sessions(events: list[dict], source: str) -> dict[str, object]:
    """Pair sign-ins with sign-outs into a timeline.

    From the Security log, sessions pair on TargetLogonId, which is exact. The
    profile-service fallback has no session id, so consecutive logon/logoff
    events for the same user are matched in time order. That is good enough for
    "when was I on this machine" and is flagged `exact: false` so the UI can say
    so rather than implying a precision it does not have.
    """
    logons: list[dict] = []
    logoffs: list[dict] = []
    locks: list[dict] = []
    boots: list[dict] = []

    for event in events:
        session = event.get("session") or {}
        action = session.get("action")
        record = {
            "timestamp": event.get("timestamp"),
            "user": session.get("user") or event.get("user"),
            "domain": session.get("domain"),
            "logon_id": session.get("logon_id"),
            "logon_type": session.get("logon_type"),
            "logon_type_label": session.get("logon_type_label"),
            "source_ip": session.get("source_ip"),
            "event_id": event.get("id"),
            "title": event.get("title"),
        }
        if action == "logon":
            logon_type = session.get("logon_type")
            # Drop the flood of service and network logons.
            if source == "security" and logon_type is not None:
                if int(logon_type) not in INTERACTIVE_LOGON_TYPES:
                    continue
            logons.append(record)
        elif action == "logoff":
            logoffs.append(record)
        elif action in ("lock", "unlock"):
            locks.append({**record, "action": action})
        elif action in ("boot", "shutdown"):
            boots.append({**record, "action": action})

    logons.sort(key=lambda r: float(r["timestamp"] or 0))
    logoffs.sort(key=lambda r: float(r["timestamp"] or 0))

    by_logon_id = {str(r["logon_id"]): r for r in logoffs if r.get("logon_id")}

    # Boot and clean-shutdown times, used to close sessions that have no
    # matching sign-out. A session cannot outlive a restart, and without this
    # every sign-in before the last reboot stays "open" forever -- which showed
    # up as two simultaneously-open sessions nineteen days apart.
    restarts = sorted(
        float(b["timestamp"]) for b in boots
        if b["action"] in ("boot", "shutdown") and b.get("timestamp")
    )

    timeline: list[dict[str, object]] = []
    consumed: set[int] = set()
    for logon in logons:
        start = float(logon.get("timestamp") or 0)
        end_ts: float | None = None
        exact = False
        inferred = False

        logon_id = logon.get("logon_id")
        if logon_id and str(logon_id) in by_logon_id:
            end_ts = float(by_logon_id[str(logon_id)]["timestamp"] or 0)
            exact = True
        else:
            for index, candidate in enumerate(logoffs):
                if index in consumed:
                    continue
                candidate_ts = float(candidate["timestamp"] or 0)
                if candidate_ts <= start:
                    continue
                if logon.get("user") and candidate.get("user") \
                        and candidate["user"] != logon["user"]:
                    continue
                end_ts = candidate_ts
                consumed.add(index)
                break

        if end_ts is None:
            # No sign-out recorded. If the machine has restarted since, the
            # session ended then at the latest.
            next_restart = next((r for r in restarts if r > start), None)
            if next_restart is not None:
                end_ts = next_restart
                inferred = True

        duration = (end_ts - start) if (end_ts and start) else None
        timeline.append({
            "user": logon.get("user"),
            "domain": logon.get("domain"),
            "logon_type": logon.get("logon_type"),
            "logon_type_label": logon.get("logon_type_label"),
            "source_ip": logon.get("source_ip"),
            "start": logon.get("timestamp"),
            "end": end_ts,
            "duration": duration,
            "open": end_ts is None,
            "exact": exact,
            # True when the end came from a reboot rather than a sign-out event,
            # so the UI can label it "ended at restart" instead of implying a
            # recorded sign-out.
            "end_inferred": inferred,
        })

    timeline.sort(key=lambda item: float(item.get("start") or 0), reverse=True)
    total = sum(float(s["duration"] or 0) for s in timeline if s.get("duration"))

    return {
        "timeline": timeline[:120],
        "summary": {
            "sessions": len(timeline),
            "open_sessions": sum(1 for s in timeline if s["open"]),
            "total_seconds": round(total),
            "locks": sum(1 for l in locks if l["action"] == "lock"),
            "unlocks": sum(1 for l in locks if l["action"] == "unlock"),
            "boots": sum(1 for b in boots if b["action"] == "boot"),
            "shutdowns": sum(1 for b in boots if b["action"] == "shutdown"),
            "lock_events": sorted(locks, key=lambda l: -(float(l["timestamp"] or 0)))[:40],
            "boot_events": sorted(boots, key=lambda b: -(float(b["timestamp"] or 0)))[:40],
        },
    }


def _summarise(events: list[dict]) -> dict[str, object]:
    by_source: dict[str, int] = {}
    by_day: dict[str, int] = {}
    worst = "ok"
    for event in events:
        key = str(event.get("source_key"))
        by_source[key] = by_source.get(key, 0) + 1
        timestamp = event.get("timestamp")
        if timestamp:
            day = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d")
            by_day[day] = by_day.get(day, 0) + 1
        severity = str(event.get("severity"))
        if severity == "critical" or (severity == "error" and worst != "critical"):
            worst = severity
    return {
        "total": len(events),
        "by_source": by_source,
        "by_day": dict(sorted(by_day.items())),
        "worst_severity": worst,
        "latest": events[0]["timestamp"] if events else None,
    }


# -------------------------------------------------------------------- filesystem
def minidumps() -> dict[str, object]:
    """Crash dump files. Their presence corroborates a bugcheck event."""
    out: dict[str, object] = {"available": True, "reason": None}
    files: list[dict[str, object]] = []
    notes: list[str] = []
    for folder, label in (
        (r"C:\Windows\Minidump", "minidump"),
        (r"C:\Windows\LiveKernelReports", "live kernel report"),
    ):
        try:
            if not os.path.isdir(folder):
                continue
            with os.scandir(folder) as entries:
                for entry in entries:
                    if not entry.is_file():
                        continue
                    if not entry.name.lower().endswith((".dmp", ".zip")):
                        continue
                    stat = entry.stat()
                    files.append({"name": entry.name, "path": entry.path,
                                  "kind": label, "size": stat.st_size,
                                  "modified": stat.st_mtime})
        except PermissionError:
            notes.append(f"{folder} needs elevation to list")
        except OSError as exc:
            notes.append(f"{folder}: {exc}")
    try:
        if os.path.isfile(r"C:\Windows\MEMORY.DMP"):
            stat = os.stat(r"C:\Windows\MEMORY.DMP")
            files.append({"name": "MEMORY.DMP", "path": r"C:\Windows\MEMORY.DMP",
                          "kind": "full kernel dump", "size": stat.st_size,
                          "modified": stat.st_mtime})
    except OSError:
        pass
    files.sort(key=lambda f: -float(f["modified"]))
    out["files"] = files[:40]
    out["count"] = len(files)
    out["pstore"] = None
    out["reason"] = ("; ".join(notes) or None) if files or notes else \
        "no minidump, live kernel report or MEMORY.DMP on disk"
    return out


def pending_reboot() -> dict[str, object]:
    """Whether Windows is waiting on a restart, and what is asking for it."""
    winreg = windows.winreg
    if winreg is None:
        return {"pending": False, "reasons": [], "sources": {}}

    reasons: list[str] = []
    checks = (
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
         "A Windows update is staged and needs a restart"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
         "Windows Update has installed updates that need a restart"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
         "Packages are pending installation"),
        (r"SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts",
         "A reboot attempt is recorded"),
    )
    for path, reason in checks:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
                reasons.append(reason)
        except OSError:
            pass

    # A queued file rename is the strongest signal: something is waiting to
    # replace a file that is locked right now, which only a reboot can do.
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "PendingFileRenameOperations")
            entries = [v for v in (value or []) if v]
            if entries:
                # The value alternates source/destination, so pairs, not entries.
                reasons.append(f"{max(1, len(entries) // 2)} file replacement(s) "
                               "queued for the next boot")
    except OSError:
        pass

    return {"pending": bool(reasons), "reasons": reasons,
            "sources": {"registry": [path for path, _ in checks],
                        "pending_file_renames": any("file replacement" in r for r in reasons)}}


# ------------------------------------------------------------------- xml helpers
def _build_xpath(ids: tuple[int, ...], providers: tuple[str, ...],
                 lookback_days: int) -> str:
    """Compose an XPath so filtering happens inside Windows, not in Python.

    `timediff(@SystemTime)` takes milliseconds and is evaluated by the event log
    service, which is far cheaper than reading every record and filtering here.
    """
    clauses = []
    if ids:
        clauses.append("(" + " or ".join(f"EventID={i}" for i in ids) + ")")
    if providers:
        clauses.append("Provider[" + " or ".join(f"@Name='{p}'" for p in providers) + "]")
    clauses.append(f"TimeCreated[timediff(@SystemTime) <= {int(lookback_days * 86_400_000)}]")
    return "*[System[" + " and ".join(clauses) + "]]"


def _event_data(root: ElementTree.Element) -> dict[str, object]:
    """Flatten EventData/UserData into a dict.

    Named `<Data Name="X">` entries become keys -- most modern providers use
    them, and they are what the enrichment reads. Unnamed entries (older
    providers such as EventLog and Service Control Manager) keep their order
    under `_values`, because those are addressed positionally.
    """
    out: dict[str, object] = {}
    values: list[str] = []
    for container in ("e:EventData", "e:UserData"):
        node = root.find(container, _NS)
        if node is None:
            continue
        for element in node.iter():
            tag = element.tag.split("}")[-1]
            if tag not in ("Data", "Binary"):
                continue
            name = element.get("Name")
            text = (element.text or "").strip()
            if name:
                out[name] = text
            else:
                # Kept even when empty: positional indices must stay aligned.
                values.append(text)
    if values:
        out["_values"] = values
    return out


def _first_number(values: list[str] | None) -> int | None:
    """First value that parses as a number. 6013 pads with four empty fields."""
    for candidate in (values or []):
        if candidate and candidate.isdigit():
            return int(candidate)
    return None


def _text(element: ElementTree.Element | None) -> str | None:
    return element.text if element is not None else None


def _int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _hex_int(value: object) -> int | None:
    """Parse '0x4b70', 'c0000005' or '3221225477' into an int."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        # Bare hex is the common form for exception codes.
        if re.fullmatch(r"[0-9a-fA-F]{8}", text):
            return int(text, 16)
        return int(text, 10) & 0xFFFFFFFF
    except ValueError:
        return None


def _parse_time(value: str | None) -> float | None:
    """'2026-08-28T09:12:34.1234567Z' -> epoch seconds.

    Windows writes 7-digit fractional seconds, which `fromisoformat` rejects on
    older Pythons, so it is trimmed to 6 first.
    """
    if not value:
        return None
    text = value.rstrip("Z")
    if "." in text:
        head, _, frac = text.partition(".")
        text = f"{head}.{frac[:6]}"
    try:
        return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _short(exc: Exception) -> str:
    args = getattr(exc, "args", ())
    if len(args) >= 3 and isinstance(args[2], str):
        return args[2]
    return str(exc)
