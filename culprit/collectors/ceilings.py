"""Ceilings with a named holder, and who the OOM killer would take first.

Some failures are not pressure at all: a hard limit is reached and the next
call returns EMFILE, or the connection tracker drops packets, or a sync
client silently stops seeing file changes. Every one of these has a ceiling,
a current value, and a process (or the whole machine) holding it -- so the
Lag Doctor can say "nginx (pid 1234) has 3,900 of its 4,096 file descriptors
open" *before* the accept loop starts failing, instead of a graph going red
when it already has.

Watched:

- open file descriptors per process against its own RLIMIT_NOFILE
  (/proc/<pid>/limits is world-readable; the fd *count* is not, so the
  unreadable processes are counted and the unlock named);
- system-wide file handles (fs.file-nr / fs.file-max);
- threads against kernel.threads-max, PIDs against kernel.pid_max;
- netfilter connection tracking (nf_conntrack_count / _max) -- when this
  fills, new connections are dropped with nothing in the application's logs;
- inotify watches against fs.inotify.max_user_watches, with the process
  holding the most (the "sync stopped working" failure), and instances
  against max_user_instances.

And the OOM victims: /proc/<pid>/oom_score is the kernel's own badness
ranking, readable for every process, so "if memory runs out, the kernel
kills X first" is a fact, not a guess. It is shown as information, never as
a finding -- nothing is wrong until memory actually runs out, and the
memory findings carry the list when it does.

Slow tier (20 s): ~10 ms with ~215 processes (a readlink per readable fd,
one small read per process).
"""

from __future__ import annotations

import os
import time

from .. import linux
from .containers import identify

# A ceiling is reported once usage reaches this share of it; findings
# fire from 80%.
_REPORT_FROM = 0.5
_OOM_TOP = 5


class CeilingCollector:
    def __init__(self) -> None:
        self._uid = os.geteuid()

    def sample(self, processes: list[dict] | None = None) -> dict[str, object]:
        """`processes` is the latest process table (name, username, unit,
        container per pid) so holders are labelled the way the rest of the
        UI labels them; without it, holders carry pid and comm only."""
        started = time.perf_counter()
        by_pid: dict[int, dict] = {}
        for proc in processes or []:
            try:
                by_pid[int(proc.get("pid") or 0)] = proc
            except (TypeError, ValueError):
                continue

        limits: list[dict[str, object]] = []
        fds_unreadable = 0
        inotify_used = 0
        inotify_instances = 0
        inotify_top: tuple[int, int] | None = None   # (watches, pid)
        oom: list[tuple[int, int, int]] = []          # (score, adj, pid)

        try:
            pids = [int(n) for n in os.listdir("/proc") if n.isdigit()]
        except OSError:
            pids = []
        for pid in pids:
            score = linux.read_int(f"/proc/{pid}/oom_score")
            if score is not None and score > 0:
                adj = linux.read_int(f"/proc/{pid}/oom_score_adj") or 0
                oom.append((score, adj, pid))
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                fds_unreadable += 1
                continue
            count = len(fds)
            soft = _nofile_limit(pid)
            if soft and count / soft >= _REPORT_FROM:
                limits.append(_limit(
                    "fds", f"Open files of {_name_of(pid, by_pid)}", count, soft,
                    holder=_holder(pid, by_pid),
                    fix="raise LimitNOFILE= in the unit (or ulimit -n for a shell); "
                        "or the process is leaking descriptors"))
            watches = 0
            for fd in fds:
                try:
                    if os.readlink(f"{fd_dir}/{fd}") != "anon_inode:inotify":
                        continue
                except OSError:
                    continue
                inotify_instances += 1
                info = linux.read_text(f"/proc/{pid}/fdinfo/{fd}") or ""
                watches += info.count("inotify wd:")
            if watches:
                inotify_used += watches
                if inotify_top is None or watches > inotify_top[0]:
                    inotify_top = (watches, pid)

        # --- machine-wide ceilings ------------------------------------------
        file_nr = (linux.read_line("/proc/sys/fs/file-nr") or "").split()
        file_max = linux.read_int("/proc/sys/fs/file-max")
        if len(file_nr) >= 1 and file_max and file_max < 2 ** 62:
            try:
                limits.append(_limit("file_handles", "Open file handles (system-wide)",
                                     int(file_nr[0]), file_max, fix="fs.file-max"))
            except ValueError:
                pass
        loadavg = (linux.read_line("/proc/loadavg") or "").split()
        threads_max = linux.read_int("/proc/sys/kernel/threads-max")
        if len(loadavg) >= 4 and threads_max:
            try:
                threads = int(loadavg[3].split("/")[1])
                limits.append(_limit("threads", "Threads (kernel.threads-max)",
                                     threads, threads_max, fix="kernel.threads-max"))
            except (ValueError, IndexError):
                pass
        pid_max = linux.read_int("/proc/sys/kernel/pid_max")
        if pid_max and pids:
            limits.append(_limit("pids", "Process IDs (kernel.pid_max)", len(pids),
                                 pid_max, fix="kernel.pid_max"))
        ct = linux.read_int("/proc/sys/net/netfilter/nf_conntrack_count")
        ct_max = linux.read_int("/proc/sys/net/netfilter/nf_conntrack_max")
        conntrack: dict[str, object]
        if ct is not None and ct_max:
            limits.append(_limit(
                "conntrack", "Tracked connections (nf_conntrack)", ct, ct_max,
                fix="net.netfilter.nf_conntrack_max; when full, new connections "
                    "are dropped with `nf_conntrack: table full` in dmesg and "
                    "nothing in the application's logs"))
            conntrack = {"available": True, "current": ct, "max": ct_max}
        else:
            conntrack = {"available": False,
                         "reason": "nf_conntrack is not loaded (no NAT / stateful "
                                   "firewall on this machine)"}
        watches_max = linux.read_int("/proc/sys/fs/inotify/max_user_watches")
        instances_max = linux.read_int("/proc/sys/fs/inotify/max_user_instances")
        if watches_max:
            holder = _holder(inotify_top[1], by_pid) if inotify_top else None
            limits.append(_limit(
                "inotify_watches", "inotify watches (fs.inotify.max_user_watches)",
                inotify_used, watches_max, holder=holder,
                holder_share=(inotify_top[0] if inotify_top else None),
                fix="fs.inotify.max_user_watches; when this runs out, sync "
                    "clients and editors silently stop seeing file changes",
                partial=fds_unreadable > 0))
        if instances_max:
            limits.append(_limit(
                "inotify_instances", "inotify instances (fs.inotify.max_user_instances)",
                inotify_instances, instances_max, fix="fs.inotify.max_user_instances",
                partial=fds_unreadable > 0))

        # Only what is worth looking at, worst first; the machine-wide ones
        # are cheap to keep so the panel can say "all far from their limit".
        limits.sort(key=lambda entry: -float(entry["pct"]))
        near = [entry for entry in limits if float(entry["pct"]) >= _REPORT_FROM * 100]

        oom.sort(reverse=True)
        victims = []
        for score, adj, pid in oom[:_OOM_TOP]:
            entry = _holder(pid, by_pid)
            entry.update({"oom_score": score, "oom_score_adj": adj,
                          "working_set": (by_pid.get(pid) or {}).get("working_set")})
            victims.append(entry)

        return {
            "available": True,
            "reason": None,
            "limits": near,
            "watched": len(limits),
            "fds_unreadable": fds_unreadable,
            "fds_note": (
                f"file-descriptor counts and inotify watches cover only the "
                f"processes readable at this privilege level ({fds_unreadable} "
                "not readable); their true usage is at least this. Other users' "
                "descriptors need CAP_SYS_PTRACE or root."
                if fds_unreadable else None),
            "conntrack": conntrack,
            "oom": {
                "available": bool(oom),
                "reason": None if oom else "no process has a non-zero oom_score",
                "next": victims,
                "protected": sum(1 for _, adj, _ in oom if adj <= -1000),
                "note": ("oom_score is the kernel's own badness ranking (memory "
                         "share adjusted by oom_score_adj); the first entry is "
                         "what the OOM killer takes if memory runs out now."),
            },
            "sample_ms": round((time.perf_counter() - started) * 1000, 1),
        }


# --------------------------------------------------------------------- helpers
def _limit(kind: str, label: str, current: int, maximum: int,
           holder: dict | None = None, holder_share: int | None = None,
           fix: str | None = None, partial: bool = False) -> dict[str, object]:
    return {
        "kind": kind, "label": label, "current": current, "max": maximum,
        "pct": round(100.0 * current / maximum, 1) if maximum else 0.0,
        "holder": holder,
        "holder_share": holder_share,
        "fix": fix,
        # True when the count is a lower bound (some processes unreadable).
        "partial": partial,
    }


def _nofile_limit(pid: int) -> int | None:
    text = linux.read_text(f"/proc/{pid}/limits")
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("Max open files"):
            parts = line.split()
            # "Max open files  1024  1048576  files" -> soft is parts[3]
            try:
                return None if parts[3] == "unlimited" else int(parts[3])
            except (IndexError, ValueError):
                return None
    return None


def _name_of(pid: int, by_pid: dict[int, dict]) -> str:
    proc = by_pid.get(pid)
    if proc and proc.get("name"):
        return f"{proc['name']} (pid {pid})"
    comm = linux.read_line(f"/proc/{pid}/comm")
    return f"{comm} (pid {pid})" if comm else f"pid {pid}"


def _holder(pid: int, by_pid: dict[int, dict]) -> dict[str, object]:
    proc = by_pid.get(pid) or {}
    container = proc.get("container")
    if container is None:
        ident = identify(linux.cgroup_path_of(pid))
        container = ({"runtime": ident[0], "id": ident[1], "name": None}
                     if ident else None)
    return {
        "pid": pid,
        "name": proc.get("name") or linux.read_line(f"/proc/{pid}/comm") or f"pid {pid}",
        "username": proc.get("username"),
        "unit": proc.get("unit") or linux.unit_from_cgroup(pid),
        "container": container,
    }
