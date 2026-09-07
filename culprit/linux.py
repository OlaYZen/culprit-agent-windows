"""The Linux data-source layer: /proc, /sys, systemd and the journal.

This replaces both `pdh.py` (performance counters) and `wmi.py` (COM) from the
Windows build with something far smaller, because on Linux the kernel's
interfaces are plain files. A /proc read costs microseconds; measured on this
machine, reading stat+statm for all 229 processes takes 8ms where the Windows
psutil path took 13.5 *seconds* for the same coverage.

systemd and the journal are reached through `systemctl`/`journalctl`/`loginctl`
subprocesses with `-o json` rather than through D-Bus bindings. Measured:
`busctl call ... ListUnits` and `systemctl list-units -o json` both cost ~12ms,
so a pure-Python D-Bus stack (jeepney et al.) would buy nothing but a
dependency. The Windows build rejected subprocesses because PowerShell cost
~700ms per spawn and it needed a dozen; here a spawn is ~5ms and the slow/events
tiers need a handful every 20-120s.

Everything degrades to an explicit unavailable state: helpers return None (or
raise nothing) and the caller reports *why* a panel is empty.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("culprit.linux")

CGROUP_ROOT = Path("/sys/fs/cgroup")


# ------------------------------------------------------------------ file reads
def read_text(path: str | Path) -> str | None:
    """Read a whole (small) file, or None if it does not exist / is gated."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def read_line(path: str | Path) -> str | None:
    text = read_text(path)
    return text.strip() if text is not None else None


def read_int(path: str | Path) -> int | None:
    text = read_line(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def parse_kv_file(path: str | Path, sep: str = ":") -> dict[str, str]:
    """'Key:   value' files like /proc/meminfo and /proc/<pid>/status."""
    out: dict[str, str] = {}
    text = read_text(path)
    if text is None:
        return out
    for line in text.splitlines():
        key, found, value = line.partition(sep)
        if found:
            out[key.strip()] = value.strip()
    return out


def meminfo_kb(fields: dict[str, str], key: str) -> int | None:
    """'MemAvailable' -> bytes. meminfo values are always in kB."""
    raw = fields.get(key)
    if raw is None:
        return None
    try:
        return int(raw.split()[0]) * 1024
    except (ValueError, IndexError):
        return None


# ------------------------------------------------------------------------- PSI
def read_psi(path: str | Path) -> dict[str, dict[str, float]] | None:
    """Parse one pressure file into {'some': {...}, 'full': {...}}.

    Values are the percentage of wall time at least one task ('some') or every
    non-idle task ('full') was stalled on this resource, over 10/60/300s
    windows, plus a cumulative stall total in microseconds.
    """
    text = read_text(path)
    if text is None:
        return None
    out: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        kind = parts[0]  # "some" | "full"
        values: dict[str, float] = {}
        for token in parts[1:]:
            key, _, value = token.partition("=")
            try:
                values[key] = float(value)
            except ValueError:
                pass
        out[kind] = values
    return out or None


@lru_cache(maxsize=1)
def psi_available() -> bool:
    """PSI needs kernel >= 4.20 with CONFIG_PSI=y (and psi=1 where the distro
    default-disables it). Existence of the directory is the reliable test."""
    return os.path.isdir("/proc/pressure")


def system_psi() -> dict[str, dict[str, dict[str, float]] | None] | None:
    if not psi_available():
        return None
    return {
        "cpu": read_psi("/proc/pressure/cpu"),
        "memory": read_psi("/proc/pressure/memory"),
        "io": read_psi("/proc/pressure/io"),
    }


# ---------------------------------------------------------------------- cgroup
@lru_cache(maxsize=1)
def cgroup_version() -> int:
    """2 for the unified hierarchy, 1 for legacy, 0 for none (odd containers)."""
    if (CGROUP_ROOT / "cgroup.controllers").exists():
        return 2
    if (CGROUP_ROOT / "memory").is_dir():
        return 1
    return 0


def unit_cgroup_dir(control_group: str | None) -> Path | None:
    """systemd's ControlGroup property ('/system.slice/ssh.service') -> path."""
    if not control_group or cgroup_version() != 2:
        return None
    path = CGROUP_ROOT / control_group.lstrip("/")
    return path if path.is_dir() else None


def cgroup_stats(path: Path) -> dict[str, object]:
    """CPU time, memory and PSI for one cgroup. Caller computes rates."""
    out: dict[str, object] = {}
    cpu = parse_kv_file(path / "cpu.stat", sep=" ")
    if "usage_usec" in cpu:
        try:
            out["cpu_usec"] = int(cpu["usage_usec"])
        except ValueError:
            pass
    out["memory_bytes"] = read_int(path / "memory.current")
    swap = read_int(path / "memory.swap.current")
    if swap:
        out["swap_bytes"] = swap
    # io.stat: one line per device: "8:0 rbytes=... wbytes=... ..."
    io_text = read_text(path / "io.stat")
    if io_text:
        read_total = write_total = 0
        for line in io_text.splitlines():
            for token in line.split()[1:]:
                key, _, value = token.partition("=")
                try:
                    if key == "rbytes":
                        read_total += int(value)
                    elif key == "wbytes":
                        write_total += int(value)
                except ValueError:
                    pass
        out["io_read_bytes"] = read_total
        out["io_write_bytes"] = write_total
    for resource in ("cpu", "memory", "io"):
        psi = read_psi(path / f"{resource}.pressure")
        if psi and "some" in psi:
            out[f"psi_{resource}_some"] = psi["some"].get("avg10")
    events = parse_kv_file(path / "memory.events", sep=" ")
    if events.get("oom_kill") not in (None, "0"):
        try:
            out["oom_kills"] = int(events["oom_kill"])
        except ValueError:
            pass
    return out


_UNIT_SUFFIXES = (".service", ".socket", ".scope", ".mount", ".target")


def cgroup_path_of(pid: int) -> str | None:
    """The cgroup v2 path of a PID (the '0::<path>' line of /proc/<pid>/cgroup).
    In a container this can be namespace-relative, e.g. '/../ssh.service'."""
    text = read_text(f"/proc/{pid}/cgroup")
    if not text:
        return None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            return parts[2]
    return None


def unit_from_cgroup(pid: int) -> str | None:
    """The systemd unit owning a PID, read from its own cgroup path.

    Needs no systemctl / D-Bus, so it works where the bus is unreachable (an
    agent in a container). Returns the deepest .service/.socket/.scope,
    preferring a real unit over a wrapping .slice; namespace-relative '..'
    segments are skipped.
    """
    path = cgroup_path_of(pid)
    if not path:
        return None
    segments = [s for s in path.strip("/").split("/") if s and s != ".."]
    for suffix in _UNIT_SUFFIXES:
        for seg in reversed(segments):
            if seg.endswith(suffix):
                return seg
    return None


@lru_cache(maxsize=1)
def in_container() -> str | None:
    """Container name ('docker', 'lxc', ...) or None on bare metal / full VM.

    Inside a container /proc/meminfo, /proc/stat and /proc/loadavg show the
    *host* unless lxcfs is mounted, so every collector that reads them must know
    this and say which numbers it is showing.
    """
    text = run(["systemd-detect-virt", "--container"], timeout=3)
    if text and text.strip() != "none":
        return text.strip()
    if os.path.exists("/.dockerenv"):
        return "docker"
    cgroup = read_text("/proc/1/cgroup") or ""
    for hint in ("docker", "lxc", "kubepods", "containerd"):
        if hint in cgroup:
            return hint
    return None


# ----------------------------------------------------------------- subprocesses
def run(argv: list[str], timeout: float = 10.0) -> str | None:
    """Run a helper binary, returning stdout or None. Never raises."""
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("%s failed: %s", argv[0], exc)
        return None
    if completed.returncode != 0:
        log.debug("%s exited %d: %s", argv[0], completed.returncode,
                  completed.stderr.strip()[:200])
        return None
    return completed.stdout


def run_json(argv: list[str], timeout: float = 10.0) -> object | None:
    text = run(argv, timeout=timeout)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError as exc:
        log.debug("%s produced non-JSON output: %s", argv[0], exc)
        return None


def journalctl_json(args: list[str], timeout: float = 30.0,
                    max_entries: int = 2000, reverse: bool = True) -> list[dict]:
    """`journalctl -o json`, newest first by default, one object per line.

    Two measured performance traps drive the flags here (1.3GB journal):

    * `-r -n <max>` lets journalctl walk backwards and stop at the cap
      instead of scanning the whole lookback window -- but only when matches
      are plentiful; a sparse `-g` still scans everything in the window.
    * **`--after-cursor` + `-r` ignores the cursor** and degrades to a full
      30s journal scan, and `--after-cursor` + `-n` (forward) simply hangs
      until killed. So incremental cursor queries pass reverse=False, which
      also drops `-n`; the cap is applied to the parsed lines instead.
    """
    order = ["-r", "-n", str(max_entries)] if reverse else []
    text = run(["journalctl", "-q", "-o", "json", "--no-pager",
                *order, *args], timeout=timeout)
    if text is None:
        return []
    out: list[dict] = []
    for line in text.splitlines():
        if len(out) >= max_entries:
            break
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


@lru_cache(maxsize=1)
def journal_access() -> dict[str, object]:
    """Can we read the system journal, and is it persistent?

    Access is group-gated (systemd-journal, or adm on Debian/Ubuntu) -- the
    direct analogue of the Windows Security-log elevation gate, and it gets the
    same treatment: an explicit state naming the exact group that would fix it.
    """
    import grp

    groups: set[str] = set()
    try:
        for gid in os.getgroups():
            try:
                groups.add(grp.getgrgid(gid).gr_name)
            except KeyError:
                pass
    except OSError:
        pass
    # A real read is the authoritative test; group membership only shapes the
    # advice when it fails (ACLs and MACs can gate access either way).
    probe = run(["journalctl", "-q", "-n", "1", "-o", "cat", "--no-pager"],
                timeout=10)
    readable = probe is not None
    return {
        "readable": readable,
        "reason": None if readable else (
            "the system journal is only readable by the 'systemd-journal' or "
            "'adm' group -- add this user to one of them "
            "(sudo usermod -aG systemd-journal <user>) and log in again"
        ),
        "persistent": os.path.isdir("/var/log/journal"),
        "groups": sorted(groups),
    }


# ------------------------------------------------------------------ privileges
@lru_cache(maxsize=1)
def capabilities() -> set[str]:
    """Effective capabilities of this process, decoded from /proc/self/status."""
    status = parse_kv_file("/proc/self/status")
    raw = status.get("CapEff")
    if not raw:
        return set()
    try:
        mask = int(raw, 16)
    except ValueError:
        return set()
    # Only the ones collectors actually gate on; the full table is not needed.
    names = {
        "CAP_DAC_READ_SEARCH": 2, "CAP_SYS_RAWIO": 17, "CAP_SYS_PTRACE": 19,
        "CAP_SYS_ADMIN": 21, "CAP_PERFMON": 38,
    }
    return {name for name, bit in names.items() if mask & (1 << bit)}


@lru_cache(maxsize=1)
def ptrace_scope() -> int | None:
    """Yama LSM setting that tightens /proc/<pid>/io and fd access further."""
    return read_int("/proc/sys/kernel/yama/ptrace_scope")
