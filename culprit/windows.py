"""The Windows data-source layer -- what linux.py is to the Linux agent.

Everything here is a thin, defensive wrapper over the three ways Windows
hands out machine state to an unelevated process:

* **PDH** (performance counters, `win32pdh`) -- the only unelevated source
  for per-PID GPU utilisation, disk queue depth and latency, hard-fault
  rates and the whole process table in one call (`\\Process V2`).
* **WMI** (`win32com`) -- identity: CPU model, BIOS, adapters, disk media.
  Allowed to be broken; every query returns `[]` rather than raising.
* **The registry** (`winreg`, stdlib) -- OS build, pending reboots,
  OneDrive accounts, known folders.

Plus the Service Control Manager (`win32service`) for the Outage Doctor's
verbs, and a subprocess helper that never opens a console window.

Three measured properties of PDH shape the query class, carried over from
the original Windows build:

1. The first `CollectQueryData` on a wildcard path is expensive -- ~550ms for
   `\\GPU Engine(*)` with ~600 instances, because PDH enumerates every
   instance. Steady-state collects on the *same* open query cost 10-30ms. So
   one query is opened at startup and kept for the process lifetime; it is
   never reopened per tick.
2. Rate counters need two collects before they mean anything. The first
   `GetFormattedCounterValue` raises PDH_INVALID_DATA. That is normal, not an
   error, and surfaces here as `None`.
3. Counters are optional. Not every machine has `\\Thermal Zone Information`,
   and counter names are localised on some Windows installs. Every counter is
   added individually so one missing counter degrades one tile rather than
   the whole dashboard.

The honesty rule is the same as on Linux: a helper that cannot read its
source returns `None` / `[]` and the caller says why a panel is empty.
Nothing here ever invents a value. The module imports cleanly on any OS --
every pywin32 module is optional and reported through `MISSING` -- so the
shape tools can run the collectors on a Linux dev box in their degraded
form.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import subprocess
import sys
import threading
from typing import Iterable

log = logging.getLogger("culprit.windows")

IS_WINDOWS = sys.platform == "win32"

# Which optional modules are present, and why not when they are not. Every
# collector names the exact module its panel needs, so "install pywin32" is
# the fix the UI shows, never a blank panel.
MISSING: dict[str, str] = {}


def _optional(name: str):  # type: ignore[no-untyped-def]
    try:
        return __import__(name)
    except ImportError as exc:
        MISSING[name] = (f"{name} is not importable ({exc}); it ships with pywin32"
                         if IS_WINDOWS else f"{name} only exists on Windows")
        return None


win32pdh = _optional("win32pdh")
win32evtlog = _optional("win32evtlog")
win32gui = _optional("win32gui")
win32process = _optional("win32process")
win32service = _optional("win32service")
win32serviceutil = _optional("win32serviceutil")
win32ts = _optional("win32ts")
win32job = _optional("win32job")
win32api = _optional("win32api")
win32security = _optional("win32security")
win32con = _optional("win32con")
winreg = _optional("winreg")

NOT_CAPABLE = "Not capable in Windows"


def not_capable(what: str) -> str:
    """The standard reason string for a Linux-only source. The dashboard
    renders it verbatim, so it is a sentence, not a code."""
    return f"{NOT_CAPABLE}: {what}"


def missing(module: str) -> str:
    return MISSING.get(module, f"{module} is not available")


# ------------------------------------------------------------------------ PDH
# GPU engine instances look like:
#   pid_23324_luid_0x00000004_0xAB370C9F_phys_0_eng_0_engtype_3D
# One process gets one instance per (adapter, physical engine, engine type), so
# a browser alone can account for dozens.
_GPU_INSTANCE = re.compile(
    r"^pid_(?P<pid>\d+)_luid_(?P<luid>0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)"
    r"(?:_phys_(?P<phys>\d+))?(?:_eng_(?P<eng>\d+))?(?:_engtype_(?P<engtype>.+))?$"
)


def parse_gpu_instance(name: str) -> dict[str, str] | None:
    m = _GPU_INSTANCE.match(name)
    return m.groupdict() if m else None


class PdhQuery:
    """One long-lived PDH query holding many counters.

    Counters are registered by a short key; `collect()` refreshes them all in a
    single call, then `value()` / `array()` read the formatted results. Without
    win32pdh every counter is recorded as unavailable and every read is None,
    so a collector built on this degrades to `available: False` with the
    module named as the reason rather than failing to construct.
    """

    def __init__(self, name: str = "query") -> None:
        self.name = name
        self._handle = None
        self._counters: dict[str, tuple[int, int, bool]] = {}  # key -> (h, fmt, is_array)
        self.unavailable: dict[str, str] = {}
        self._collected = 0
        if win32pdh is not None:
            try:
                self._handle = win32pdh.OpenQuery()
            except Exception as exc:  # pragma: no cover - PDH itself broken
                log.warning("PDH OpenQuery failed: %s", exc)
                self._handle = None

    @property
    def ok(self) -> bool:
        return self._handle is not None

    @property
    def reason(self) -> str:
        """Why this query has no counters at all (for the collector's
        `available: False`)."""
        if win32pdh is None:
            return missing("win32pdh")
        if self._handle is None:
            return ("PDH could not open a query (the performance counter "
                    "service may be disabled)")
        return "; ".join(f"{k}: {v}" for k, v in list(self.unavailable.items())[:3]) \
            or "no counters registered"

    def add(self, key: str, path: str, *, fmt: str = "double", array: bool = False,
            nocap: bool = False) -> bool:
        """Register a counter. Returns False (and records why) if unavailable.

        `nocap` sets PDH_FMT_NOCAP100, which is **required** for any percentage
        counter that can legitimately exceed 100 -- per-process `% Processor
        Time` is summed across cores, so on a 12-core machine it ranges 0..1200.
        Without the flag PDH silently clamps at 100, which hides exactly the
        processes worth finding: measured on the original dev machine, `Memory
        Compression` reported 100% clamped versus 252% uncapped.
        """
        if not self.ok:
            self.unavailable[key] = self.reason if win32pdh is None else "PDH unavailable"
            return False
        flag = {
            "double": win32pdh.PDH_FMT_DOUBLE,
            "large": win32pdh.PDH_FMT_LARGE,
            "long": win32pdh.PDH_FMT_LONG,
        }[fmt]
        if nocap:
            flag |= getattr(win32pdh, "PDH_FMT_NOCAP100", 0x00008000)
        try:
            handle = win32pdh.AddCounter(self._handle, path)
        except Exception as exc:
            # Missing counter set, or a localised Windows using translated names.
            self.unavailable[key] = f"counter not available ({short_error(exc)})"
            return False
        self._counters[key] = (handle, flag, array)
        return True

    def add_many(self, specs: Iterable[tuple[str, str]], *, fmt: str = "double",
                 array: bool = False, nocap: bool = False) -> None:
        for key, path in specs:
            self.add(key, path, fmt=fmt, array=array, nocap=nocap)

    def has(self, key: str) -> bool:
        return key in self._counters

    def collect(self) -> bool:
        """Take a sample. Safe to call before any counter has valid data."""
        if not self.ok:
            return False
        try:
            win32pdh.CollectQueryData(self._handle)
        except Exception as exc:
            # PDH_NO_DATA: every instance of every wildcard counter vanished
            # (e.g. all GPU processes exited). Transient, not fatal.
            log.debug("PDH collect on %s: %s", self.name, short_error(exc))
            return False
        self._collected += 1
        return True

    @property
    def warm(self) -> bool:
        """True once rate counters can produce a value (needs >= 2 collects)."""
        return self._collected >= 2

    def value(self, key: str) -> float | None:
        entry = self._counters.get(key)
        if entry is None:
            return None
        handle, flag, _ = entry
        try:
            return float(win32pdh.GetFormattedCounterValue(handle, flag)[1])
        except Exception:
            # First sample of a rate counter, or the instance disappeared.
            return None

    def array(self, key: str) -> dict[str, float]:
        """Read a wildcard counter as {instance_name: value}."""
        entry = self._counters.get(key)
        if entry is None:
            return {}
        handle, flag, _ = entry
        try:
            raw = win32pdh.GetFormattedCounterArray(handle, flag)
        except Exception:
            return {}
        out: dict[str, float] = {}
        for inst, val in raw.items():
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                out[inst] = float(val)
        return out

    def close(self) -> None:
        if self._handle is not None:
            try:
                win32pdh.CloseQuery(self._handle)
            except Exception:
                pass
            self._handle = None
            self._counters.clear()


def expand(path: str) -> list[str]:
    """Enumerate the instances a wildcard path currently matches."""
    if win32pdh is None:
        return []
    try:
        return list(win32pdh.ExpandCounterPath(path))
    except Exception:
        return []


def short_error(exc: BaseException) -> str:
    """pywintypes.error stringifies as a 3-tuple; keep just the message."""
    args = getattr(exc, "args", ())
    if len(args) >= 3 and isinstance(args[2], str):
        return args[2]
    return str(exc)


# ------------------------------------------------------------------------ WMI
_local = threading.local()


def _ensure_apartment() -> bool:
    """Initialise COM for this thread, once. Returns False if unavailable.

    Calling CoInitialize/CoUninitialize around each query prints "Win32
    exception occurred releasing IUnknown" on stderr, because the COM objects
    the query returned are finalised by Python's garbage collector *after*
    the apartment has been torn down. Every caller runs on a long-lived,
    single-threaded executor (the sampler's tiers), so the apartment is
    initialised once per thread and left alone.
    """
    if getattr(_local, "ready", False):
        return True
    if getattr(_local, "failed", False):
        return False
    try:
        import pythoncom

        try:
            pythoncom.CoInitialize()
        except Exception as exc:
            # RPC_E_CHANGED_MODE means the thread is already in an apartment,
            # which is fine -- we can still use it.
            if getattr(exc, "hresult", None) not in (-2147417850,):
                raise
        _local.ready = True
        return True
    except Exception as exc:
        log.debug("COM init failed on %s: %s", threading.current_thread().name, exc)
        _local.failed = True
        return False


def wmi_query(wql: str, fields: tuple[str, ...],
              namespace: str = "winmgmts:") -> list[dict[str, object]]:
    """Run one WQL query and return plain dicts. Never raises.

    Values are copied into plain Python before returning so no COM object
    outlives the call. On a managed machine the WMI repository can be corrupt,
    throttled, or slow enough to matter -- a broken WMI degrades a few identity
    fields instead of taking the tier down.
    """
    if not _ensure_apartment():
        return []
    try:
        import win32com.client

        service = win32com.client.GetObject(namespace)
        rows: list[dict[str, object]] = []
        for item in service.ExecQuery(wql):
            rows.append({name: _plain(getattr(item, name, None)) for name in fields})
        return rows
    except Exception as exc:
        log.debug("WMI query failed (%s): %s", wql.split(" FROM ")[-1], exc)
        return []


def wmi_reason() -> str:
    if not IS_WINDOWS:
        return "WMI only exists on Windows"
    if "win32com" in MISSING or _optional("win32com") is None:
        return missing("win32com")
    return "WMI returned nothing (the repository may be corrupt or the service stopped)"


def _plain(value: object) -> object:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    # SAFEARRAY properties (IPAddress, DNSServerSearchOrder, ...) arrive as tuples.
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return str(value)


def wmi_date(value: object) -> str | None:
    """WMI CIM_DATETIME is 'yyyymmddHHMMSS.ffffff+UUU'; keep the date part."""
    if not value:
        return None
    text = str(value)
    if len(text) >= 8 and text[:8].isdigit():
        return f"{text[0:4]}-{text[4:6]}-{text[6:8]}"
    return None


# ------------------------------------------------------------------- registry
HKLM = "HKLM"
HKCU = "HKCU"


def _hive(name: str):  # type: ignore[no-untyped-def]
    if winreg is None:
        return None
    return {HKLM: winreg.HKEY_LOCAL_MACHINE, HKCU: winreg.HKEY_CURRENT_USER}[name]


def reg_value(hive: str, path: str, name: str) -> object | None:
    """One registry value, or None when the key/value does not exist."""
    root = _hive(hive)
    if root is None:
        return None
    try:
        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def reg_key_exists(hive: str, path: str) -> bool:
    root = _hive(hive)
    if root is None:
        return False
    try:
        with winreg.OpenKey(root, path):
            return True
    except OSError:
        return False


def reg_values(hive: str, path: str) -> dict[str, object] | None:
    """Every value under one key as a dict, None when the key is missing."""
    root = _hive(hive)
    if root is None:
        return None
    try:
        with winreg.OpenKey(root, path) as key:
            out: dict[str, object] = {}
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                out[name] = value
            return out
    except OSError:
        return None


def reg_subkeys(hive: str, path: str) -> list[str]:
    root = _hive(hive)
    if root is None:
        return []
    out: list[str] = []
    try:
        with winreg.OpenKey(root, path) as key:
            index = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
    except OSError:
        return []
    return out


# ---------------------------------------------------------------- privilege
@functools.lru_cache(maxsize=1)
def is_elevated() -> bool:
    """True when running as administrator (or as SYSTEM, which passes the
    same check). Gates the Security event log and other users' processes."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def access_map() -> dict[str, object]:
    """Every gated source and the exact thing that unlocks it -- the Windows
    analogue of the Linux agent's group/capability map. Windows privilege is
    binary (administrator or not), so nearly every gate names the same key,
    but each is still listed separately so a panel can say precisely why it
    is empty."""
    admin = is_elevated()
    run_admin = "run the agent elevated (an Administrator, or the SYSTEM task agent.ps1 sets up)"
    return {
        "elevated": admin,
        # `journal` keeps the Linux key on purpose: the Overview reads
        # system.access.journal.ok to say whether history is complete. On
        # Windows the gated log is the Security channel.
        "journal": {"ok": admin, "needs": None if admin else run_admin,
                    "what": "the Security event log (sign-ins, lock/unlock, failed sign-ins)"},
        "security_log": {"ok": admin, "needs": None if admin else run_admin},
        "other_users_processes": {"ok": admin, "needs": None if admin else run_admin,
                                  "what": "exe path, user and open handles of other users' processes"},
        "smart": {"ok": admin, "needs": None if admin else run_admin,
                  "what": "the drive failure-prediction bit (MSStorageDriver_FailurePredictStatus)"},
        "minidumps": {"ok": admin, "needs": None if admin else run_admin,
                      "what": "listing C:\\Windows\\Minidump"},
        "process_actions": {"ok": admin, "needs": None if admin else run_admin,
                            "what": "ending, reprioritising or throttling other users' processes"},
        "pywin32": {"ok": not MISSING, "needs": None if not MISSING else
                    "pip install pywin32 in the agent's venv (agent.ps1 does this)",
                    "missing": sorted(MISSING)},
    }


# -------------------------------------------------------------- subprocess
def run(argv: list[str], timeout: float = 10.0) -> str | None:
    """Run a command and return stdout, or None on any failure. Never opens a
    console window (a scheduled task or service would flash one otherwise).
    Output is decoded as the OEM code page first, then UTF-8, because
    console tools such as w32tm and schtasks write in the console encoding."""
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        completed = subprocess.run(argv, capture_output=True, timeout=timeout,
                                   check=False, **kwargs)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log.debug("%s failed: %s", argv[0], exc)
        return None
    if completed.returncode != 0:
        log.debug("%s exited %s: %s", argv[0], completed.returncode,
                  completed.stderr[:200])
        return None
    raw = completed.stdout
    for encoding in ("utf-8-sig", "cp1252", "utf-16"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


# ------------------------------------------------------------------- boot id
def boot_id() -> str | None:
    """A token that changes on every boot -- the Coroner's way to tell "the
    machine rebooted" from "only the agent restarted". Windows keeps no
    kernel boot id a user can read, so the boot time (to the second) plays
    the part: two boots cannot share it."""
    try:
        import psutil

        return f"boot-{int(psutil.boot_time())}"
    except Exception:
        return None


# -------------------------------------------------------------- services
_SERVICE_STATE = {1: "stopped", 2: "start_pending", 3: "stop_pending",
                  4: "running", 5: "continue_pending", 6: "pause_pending",
                  7: "paused"}


def service_status(name: str) -> dict[str, object] | None:
    """State, pid and exit codes of one service from the SCM, or None."""
    if win32service is None:
        return None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except Exception:
        return None
    try:
        handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_STATUS)
        try:
            status = win32service.QueryServiceStatusEx(handle)
        finally:
            win32service.CloseServiceHandle(handle)
    except Exception as exc:
        log.debug("QueryServiceStatusEx(%s): %s", name, short_error(exc))
        return None
    finally:
        win32service.CloseServiceHandle(scm)
    state = int(status.get("CurrentState", 0))
    return {
        "state": _SERVICE_STATE.get(state, str(state)),
        "pid": int(status.get("ProcessId") or 0) or None,
        "exit_code": int(status.get("Win32ExitCode") or 0),
        "service_exit_code": int(status.get("ServiceSpecificExitCode") or 0),
    }


def service_dependencies(name: str) -> list[str] | None:
    """The services this one depends on (QueryServiceConfig lpDependencies),
    or None when the SCM cannot be asked."""
    if win32service is None:
        return None
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except Exception:
        return None
    try:
        handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
        try:
            config = win32service.QueryServiceConfig(handle)
        finally:
            win32service.CloseServiceHandle(handle)
    except Exception:
        return None
    finally:
        win32service.CloseServiceHandle(scm)
    # QueryServiceConfig returns a tuple; index 6 is the dependency list.
    try:
        deps = config[6] or []
    except (IndexError, TypeError):
        return []
    # Group dependencies are prefixed with '+'; they are load-order groups,
    # not services, so they are dropped rather than walked.
    return [str(d) for d in deps if d and not str(d).startswith("+")]


def own_service_name() -> str | None:
    """The scheduled task / service this agent runs under, when the installer
    started it that way. The Linux agent reads its unit from its cgroup; on
    Windows the installer passes the name in the environment because a
    scheduled task carries nothing else the process could read back."""
    return os.environ.get("CULPRIT_AGENT_TASK") or None
