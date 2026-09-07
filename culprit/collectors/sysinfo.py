"""Static machine identity: distro, kernel, CPU model, RAM, GPUs, virt state.

Collected once at startup and cached (uptime stays live). Everything here is a
plain file read -- /etc/os-release, DMI sysfs, /proc/cpuinfo -- plus one
`systemd-detect-virt` call, so the WMI layer this replaces disappears without a
successor.

Includes the privilege map: which optional sources are gated and by exactly
which group or capability, so the UI can say "add yourself to systemd-journal"
instead of the Windows-era "run as administrator".
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import socket
import sys
import time

import psutil

from .. import linux
from ..util import is_elevated

log = logging.getLogger("culprit.sysinfo")


def _os_release() -> dict[str, str]:
    out: dict[str, str] = {}
    text = linux.read_text("/etc/os-release") or ""
    for line in text.splitlines():
        key, found, value = line.partition("=")
        if found:
            out[key] = value.strip().strip('"')
    return out


def _cpu_identity() -> dict[str, object]:
    info: dict[str, object] = {
        "logical_cores": os.cpu_count() or 1,
        "arch": os.uname().machine,
        "name": "Unknown CPU",
    }
    text = linux.read_text("/proc/cpuinfo") or ""
    packages: set[str] = set()
    cores: set[tuple[str, str]] = set()
    package = "0"
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "model name" and info["name"] == "Unknown CPU":
            info["name"] = value
        elif key == "vendor_id" and "vendor" not in info:
            info["vendor"] = value
        elif key == "physical id":
            package = value
            packages.add(value)
        elif key == "core id":
            cores.add((package, value))
    # Topology from cpuinfo can be absent in VMs; fall back to sysfs, then to
    # "logical == physical" as the last honest guess.
    if cores:
        info["physical_cores"] = len(cores)
        info["sockets"] = max(1, len(packages))
    else:
        sysfs_cores: set[tuple[str, str]] = set()
        base = "/sys/devices/system/cpu"
        try:
            for entry in os.listdir(base):
                if entry.startswith("cpu") and entry[3:].isdigit():
                    core = linux.read_line(f"{base}/{entry}/topology/core_id")
                    pkg = linux.read_line(
                        f"{base}/{entry}/topology/physical_package_id")
                    if core is not None and pkg is not None:
                        sysfs_cores.add((pkg, core))
        except OSError:
            pass
        info["physical_cores"] = len(sysfs_cores) or info["logical_cores"]
    try:
        freq = psutil.cpu_freq()
        if freq and (freq.max or freq.current):
            info["base_mhz"] = round(freq.max or freq.current)
    except Exception:  # noqa: BLE001 -- cpufreq can be entirely absent (VMs)
        pass
    return info


def _gpu_identity() -> list[dict[str, object]]:
    """DRM cards by driver name and PCI id. Honest rather than pretty: without
    a vendor tool there is no marketing name, so the driver is the identity."""
    gpus: list[dict[str, object]] = []
    base = "/sys/class/drm"
    try:
        cards = sorted(c for c in os.listdir(base)
                       if c.startswith("card") and c[4:].isdigit())
    except OSError:
        cards = []
    for card in cards:
        device = f"{base}/{card}/device"
        uevent = linux.parse_kv_file(f"{device}/uevent", sep="=")
        driver = uevent.get("DRIVER") or "unknown driver"
        vendor_id = (linux.read_line(f"{device}/vendor") or "").removeprefix("0x")
        device_id = (linux.read_line(f"{device}/device") or "").removeprefix("0x")
        vendor = {"10de": "NVIDIA", "1002": "AMD", "8086": "Intel",
                  "1234": "QEMU", "15ad": "VMware", "1af4": "virtio"}.get(
            vendor_id, vendor_id or "?")
        gpus.append({
            "name": f"{vendor} GPU ({driver}, {vendor_id}:{device_id})",
            "driver": driver,
            "card": card,
            "integrated": driver in ("i915", "xe", "amdgpu") and vendor == "Intel",
        })
    return gpus


def _dmi() -> dict[str, object]:
    dmi = "/sys/class/dmi/id"
    info: dict[str, object] = {
        "manufacturer": linux.read_line(f"{dmi}/sys_vendor"),
        "model": linux.read_line(f"{dmi}/product_name"),
        "board": linux.read_line(f"{dmi}/board_name"),
        "bios_version": linux.read_line(f"{dmi}/bios_version"),
        "bios_date": linux.read_line(f"{dmi}/bios_date"),
        "part_of_domain": False,  # kept for payload compatibility; no AD here
    }
    # Serials are root-gated on purpose; say so instead of showing blank.
    serial = linux.read_line(f"{dmi}/product_serial")
    info["serial"] = serial
    if serial is None and os.geteuid() != 0:
        info["serial_reason"] = "DMI serial numbers need root"
    return info


def _access_map() -> dict[str, object]:
    """Which gated sources are available, and what would unlock the rest.

    This is the Linux replacement for the single Windows elevated/not-elevated
    bit: privilege here is granular, so every gate names its exact key.
    """
    journal = linux.journal_access()
    caps = linux.capabilities()
    return {
        "root": os.geteuid() == 0,
        "groups": journal.get("groups"),
        "capabilities": sorted(caps),
        "journal": {"ok": journal.get("readable"),
                    "needs": None if journal.get("readable")
                    else "systemd-journal (or adm) group membership"},
        "process_io": {"ok": os.geteuid() == 0 or "CAP_SYS_PTRACE" in caps,
                       "needs": "CAP_SYS_PTRACE for other users' "
                                "/proc/<pid>/io and fd counts",
                       "ptrace_scope": linux.ptrace_scope()},
        "smart": {"ok": os.geteuid() == 0 or "CAP_SYS_RAWIO" in caps,
                  "needs": "CAP_SYS_RAWIO or root for SMART health"},
        "dmi_serial": {"ok": os.geteuid() == 0, "needs": "root"},
        "btmp": {"ok": os.access("/var/log/btmp", os.R_OK),
                 "needs": "root (or utmp group) for failed-login records"},
        "gpu_perf": {"ok": "CAP_PERFMON" in caps or os.geteuid() == 0,
                     "needs": "CAP_PERFMON or relaxed perf_event_paranoid "
                              "for i915 PMU counters"},
    }


_PRO_DIR = "/var/lib/ubuntu-advantage"
_PRO_STATUS = f"{_PRO_DIR}/status.json"


def _pro_expiry(raw: object) -> tuple[float | None, bool]:
    """(epoch seconds, perpetual). A free personal token encodes 'no expiry'
    as the year 9999, which we surface as perpetual rather than a silly date."""
    if not raw:
        return None, False
    text = str(raw)
    if text.startswith("9999"):
        return None, True
    try:
        import datetime
        return datetime.datetime.fromisoformat(
            text.replace("Z", "+00:00")).timestamp(), False
    except (ValueError, TypeError):
        return None, False


def _ubuntu_pro(release: dict[str, str]) -> dict[str, object] | None:
    """Ubuntu Pro subscription state, or None on non-Ubuntu (so the UI omits it).

    Read from the pro client's world-readable cache
    (`/var/lib/ubuntu-advantage/status.json`), never `pro status` -- that
    contacts contracts.canonical.com and measured ~5s here, unacceptable for a
    background sampler. The cache is refreshed by the client's own timer; a
    stale-but-instant read is the right trade. The account email is deliberately
    not surfaced.
    """
    if (release.get("ID") or "").lower() != "ubuntu":
        return None
    if not os.path.exists(_PRO_DIR):
        return {"available": False, "attached": False,
                "reason": "Ubuntu Pro client (ubuntu-pro-client) is not installed"}
    text = linux.read_text(_PRO_STATUS)
    if text is None:
        return {"available": False, "attached": False,
                "reason": "pro status cache is absent or unreadable "
                          "(/var/lib/ubuntu-advantage/status.json)"}
    try:
        data = json.loads(text)
    except ValueError:
        return {"available": False, "attached": False,
                "reason": "pro status cache is not valid JSON"}

    attached = bool(data.get("attached"))
    enabled: list[str] = []
    services: list[dict[str, object]] = []
    for svc in data.get("services") or []:
        name = svc.get("name")
        if not name:
            continue
        status = svc.get("status")            # enabled | disabled | n/a | ...
        entitled = svc.get("entitled")        # yes | no
        if status == "enabled":
            enabled.append(name)
        # Only the services worth showing: entitled here or currently on. The
        # long tail of n/a-on-this-hardware entries is noise.
        if entitled == "yes" or status == "enabled":
            services.append({
                "name": name,
                "description": svc.get("description"),
                "status": status,
                "entitled": entitled,
                "available": svc.get("available"),
            })

    expires_epoch, perpetual = _pro_expiry(data.get("expires"))
    return {
        "available": True,
        "attached": attached,
        "origin": data.get("origin"),         # "free" | "contract" | ...
        "expires_epoch": expires_epoch,
        "perpetual": perpetual,
        "enabled": enabled,
        "services": services,
        "reason": None if attached else "this machine is not attached to Ubuntu Pro",
    }


_cache: dict[str, object] | None = None


def collect(force: bool = False) -> dict[str, object]:
    global _cache
    if _cache is not None and not force:
        # Uptime is the one field that must stay live.
        _cache["uptime_seconds"] = time.time() - float(_cache["boot_time"])  # type: ignore[arg-type]
        return _cache

    release = _os_release()
    uname = os.uname()
    boot = psutil.boot_time()
    virt = (linux.run(["systemd-detect-virt"], timeout=3) or "").strip() or None
    if virt == "none":
        virt = None
    container = linux.in_container()

    payload: dict[str, object] = {
        "hostname": socket.gethostname(),
        "fqdn": _fqdn(),
        "user": getpass.getuser(),
        "user_domain": None,
        "elevated": is_elevated(),
        "os": {
            "product": release.get("PRETTY_NAME") or release.get("NAME")
            or "Linux",
            "display_version": release.get("VERSION_ID"),
            "id": release.get("ID"),
            "id_like": release.get("ID_LIKE"),
            "codename": release.get("VERSION_CODENAME"),
            # The kernel release plays the role the Windows build number did.
            "build": uname.release,
            "build_full": uname.release,
        },
        "kernel": f"{uname.sysname} {uname.release} {uname.version}",
        "machine_id": linux.read_line("/etc/machine-id"),
        "cpu": _cpu_identity(),
        "gpus": _gpu_identity(),
        "machine": _dmi(),
        "virtualization": virt,
        "container": container,
        "container_warning": (
            f"running in a {container} container: /proc-derived numbers are "
            "the host's unless lxcfs is mounted" if container else None),
        "cgroup_version": linux.cgroup_version(),
        "psi_available": linux.psi_available(),
        "access": _access_map(),
        "total_ram": psutil.virtual_memory().total,
        "boot_time": boot,
        "uptime_seconds": time.time() - boot,
        "python": sys.version.split()[0],
        "pid": os.getpid(),
        "timezone": time.strftime("%Z"),
        "utc_offset_minutes": -time.timezone // 60 if not time.daylight
                              else -time.altzone // 60,
    }
    # Ubuntu Pro only exists on Ubuntu; the key is omitted entirely elsewhere so
    # the dashboard never shows it on a non-Ubuntu machine.
    pro = _ubuntu_pro(release)
    if pro is not None:
        payload["ubuntu_pro"] = pro
    _cache = payload
    return payload


def _fqdn() -> str:
    # getfqdn() can block on a reverse DNS lookup; guard it.
    try:
        socket.setdefaulttimeout(1.0)
        return socket.getfqdn()
    except Exception:  # noqa: BLE001
        return socket.gethostname()
    finally:
        socket.setdefaulttimeout(None)
