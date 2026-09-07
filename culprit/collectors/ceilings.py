"""Resource ceilings: the limits a machine hits before it runs out of memory
or CPU, and which process is holding each one near its cap.

On Linux this reads file-descriptor counts against RLIMIT_NOFILE, the
system-wide file-handle table, threads-max, pid_max, conntrack and inotify
watches. Windows has its own ceilings, and the ones that actually stop a
process are different:

* **Handles per process.** A leaking process climbs toward the ~16M
  per-process handle limit; long before that, tens of thousands of handles is
  the classic leak signature. `\\Process V2(*)\\Handle Count` gives it for
  every process in one collect (the process table already has it), so the
  holder is named without a second query.
* **GDI and USER objects.** Each process has a 10,000-object default quota for
  each; exhausting GDI objects is why a long-running app's windows suddenly
  render as black boxes. `GetGuiResources` reads both, per process, unelevated.
* **The machine-wide handle count.** `\\Process(_Total)\\Handle Count` against
  no hard limit is still worth watching as a trend; there is no fixed maximum
  to divide by, so it is reported as a count, not a percentage.

What Linux has and Windows does not: cgroup pids.max, conntrack, inotify. Those
are absent (the OOM section and conntrack report unavailable with a reason).
The OOM "who dies first" ranking is Linux's oom_score; Windows has no such
kernel ranking, so that section is unavailable too -- the memory forecast
(memtrend) is the Windows answer to "what is about to exhaust memory".
"""

from __future__ import annotations

import time


from .. import windows

_REPORT_FROM = 0.50            # only surface a ceiling once it is half-used
_OOM_TOP = 8
# Default per-process GDI and USER object quotas (HKLM ...\Windows\
# GDIProcessHandleQuota / USERProcessHandleQuota; 10000 unless overridden).
_GUI_QUOTA_DEFAULT = 10_000
_GR_GDIOBJECTS = 0
_GR_USEROBJECTS = 1
# A per-process handle count worth calling a ceiling on its own: there is no
# small hard cap, so this is the "clearly leaking" line rather than a fraction.
_HANDLE_WATCH = 10_000
_HANDLE_SOFT_MAX = 16_711_680  # the documented per-process maximum


class CeilingCollector:
    def __init__(self) -> None:
        self._gui_quota = _gui_quota()

    def sample(self, processes: list[dict] | None = None) -> dict[str, object]:
        started = time.perf_counter()
        by_pid: dict[int, dict] = {}
        for proc in processes or []:
            try:
                by_pid[int(proc.get("pid") or 0)] = proc
            except (TypeError, ValueError):
                continue

        limits: list[dict[str, object]] = []

        # Per-process handle leak: the process table already carries the count.
        for pid, proc in by_pid.items():
            handles = proc.get("handles")
            if isinstance(handles, int) and handles >= _HANDLE_WATCH:
                limits.append(_limit(
                    "handles", f"Kernel handles of {_name_of(pid, by_pid)}",
                    handles, _HANDLE_SOFT_MAX, holder=_holder(pid, by_pid),
                    fix="the process is most likely leaking handles (sockets, "
                        "files, registry keys not closed); restart it, and check "
                        "for an updated version"))

        # GDI / USER objects per process, when win32gui can read them.
        for kind, gr, label in (("gdi_objects", _GR_GDIOBJECTS, "GDI objects"),
                                 ("user_objects", _GR_USEROBJECTS, "USER objects")):
            top = _gui_top(by_pid, gr)
            if top and self._gui_quota:
                pid, count = top
                limits.append(_limit(
                    kind, f"{label} of {_name_of(pid, by_pid)}", count, self._gui_quota,
                    holder=_holder(pid, by_pid),
                    fix=(f"the per-process {label} quota is {self._gui_quota:,}; a UI "
                         "process that reaches it renders black boxes and stops "
                         "drawing. Restart it.")))

        # Machine-wide handle table: a trend, no fixed cap to divide by.
        total_handles = _total_handles(by_pid)

        limits.sort(key=lambda entry: -float(entry["pct"]))
        # The handle line is a leak threshold (a count), not a share of a cap
        # that is never reached in practice; it is reported whenever it fired.
        near = [entry for entry in limits
                if float(entry["pct"]) >= _REPORT_FROM * 100 or entry["kind"] == "handles"]

        not_capable = windows.not_capable(
            "the OOM killer's ranking is the Linux kernel's oom_score; Windows "
            "has no equivalent. The memory forecast names what is about to "
            "exhaust memory instead")
        return {
            "available": True,
            "reason": None,
            "limits": near,
            "watched": len(limits) + (1 if total_handles else 0),
            "fds_unreadable": 0,
            "fds_note": None,
            "totals": {"handles": total_handles} if total_handles else {},
            "conntrack": {"available": False, "reason": windows.not_capable(
                "connection-tracking limits are a Linux netfilter interface")},
            "oom": {"available": False, "reason": not_capable, "next": [],
                    "protected": 0, "note": not_capable},
            "sample_ms": round((time.perf_counter() - started) * 1000, 1),
        }


def _gui_quota() -> int:
    for value_name in ("GDIProcessHandleQuota", "USERProcessHandleQuota"):
        raw = windows.reg_value(
            windows.HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", value_name)
        if isinstance(raw, int) and raw > 0:
            return raw
    return _GUI_QUOTA_DEFAULT


def _gui_top(by_pid: dict[int, dict], flag: int) -> tuple[int, int] | None:
    """(pid, object count) of the process using the most GDI/USER objects."""
    gui, api = windows.win32gui, windows.win32api
    con = windows.win32con
    if gui is None or api is None:
        return None
    best: tuple[int, int] | None = None
    access = getattr(con, "PROCESS_QUERY_INFORMATION", 0x0400) | \
        getattr(con, "PROCESS_QUERY_LIMITED_INFORMATION", 0x1000)
    for pid in by_pid:
        if pid <= 4:
            continue
        try:
            handle = api.OpenProcess(access, False, pid)
        except Exception:  # noqa: BLE001 -- another user's process, or gone
            continue
        try:
            count = gui.GetGuiResources(int(handle), flag)
        except Exception:  # noqa: BLE001
            count = 0
        finally:
            try:
                api.CloseHandle(handle)
            except Exception:  # noqa: BLE001
                pass
        if count and (best is None or count > best[1]):
            best = (pid, count)
    return best


def _total_handles(by_pid: dict[int, dict]) -> int | None:
    total = sum(int(p.get("handles") or 0) for p in by_pid.values())
    return total or None


def _limit(kind: str, label: str, current: int, maximum: int,
           holder: dict | None = None, holder_share: int | None = None,
           fix: str | None = None, partial: bool = False) -> dict[str, object]:
    return {
        "kind": kind, "label": label, "current": current, "max": maximum,
        "pct": round(100.0 * current / maximum, 1) if maximum else 0.0,
        "holder": holder,
        "holder_share": holder_share,
        "fix": fix,
        "partial": partial,
    }


def _name_of(pid: int, by_pid: dict[int, dict]) -> str:
    proc = by_pid.get(pid)
    if proc and proc.get("name"):
        return f"{proc['name']} (pid {pid})"
    return f"pid {pid}"


def _holder(pid: int, by_pid: dict[int, dict]) -> dict[str, object]:
    proc = by_pid.get(pid) or {}
    return {
        "pid": pid,
        "name": proc.get("name") or f"pid {pid}",
        "username": proc.get("username"),
        "unit": None,
        "container": None,
        "working_set": proc.get("working_set"),
    }
