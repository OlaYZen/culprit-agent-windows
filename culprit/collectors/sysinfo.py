"""Static machine identity: OS build, CPU model, RAM, GPU, domain, boot time.

Collected once at startup and cached. Nothing here changes without a reboot or
a domain-join change, so paying WMI's cost on every tick would be waste.

The payload is the Linux agent's shape plus the Windows facts the original
build reported (edition, UBR, domain membership). Two keys matter to the
host beyond display: `platform` says which agent this is (the host picks the
version feed, the Patch notes mirror and the dashboard's vocabulary by it),
and `access` names every gated source with the exact thing that unlocks it.
"""

from __future__ import annotations

import getpass
import logging
import os
import platform
import socket
import sys
import time

import psutil

from .. import windows
from ..util import is_elevated

log = logging.getLogger("culprit.sysinfo")

PLATFORM = "windows"

# Windows product names are not exposed anywhere cheap, so the caption comes
# from the registry rather than platform.win32_ver() (which reports "10" for 11).
_CV_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def _registry_os() -> dict[str, object]:
    out: dict[str, object] = {}
    values = windows.reg_values(windows.HKLM, _CV_KEY) or {}
    for name, target in (
        ("ProductName", "product"),
        ("DisplayVersion", "display_version"),
        ("CurrentBuildNumber", "build"),
        ("UBR", "ubr"),
        ("EditionID", "edition"),
        ("InstallationType", "installation_type"),
        ("InstallDate", "install_date"),
    ):
        if values.get(name) is not None:
            out[target] = str(values[name])
    # Windows 11 still reports ProductName "Windows 10 ..." on every build.
    build = str(out.get("build", "0"))
    try:
        if int(build) >= 22000 and str(out.get("product", "")).startswith("Windows 10"):
            out["product"] = str(out["product"]).replace("Windows 10", "Windows 11", 1)
    except ValueError:
        pass
    if not out.get("product"):
        release = platform.release() or "unknown"
        out["product"] = f"Windows {release}" if windows.IS_WINDOWS else \
            f"not Windows ({platform.system()})"
    if not out.get("build"):
        out["build"] = platform.version() or None
    out["build_full"] = (f"{out['build']}.{out['ubr']}" if out.get("ubr")
                         else out.get("build"))
    # The Linux fields, absent by construction.
    out.setdefault("id", "windows")
    out.setdefault("id_like", None)
    out.setdefault("codename", None)
    return out


def _cpu_identity() -> dict[str, object]:
    info: dict[str, object] = {
        "logical_cores": psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
        "arch": platform.machine(),
        "name": platform.processor() or "Unknown CPU",
        "vendor": None,
        "sockets": None,
        "base_mhz": None,
    }
    try:
        freq = psutil.cpu_freq()
        if freq:
            info["base_mhz"] = round(freq.max or freq.current or 0) or None
    except Exception:  # noqa: BLE001
        pass
    # PROCESSOR_IDENTIFIER is terse; WMI has the marketing name.
    rows = windows.wmi_query(
        "SELECT Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors, "
        "L2CacheSize, L3CacheSize, Manufacturer, VirtualizationFirmwareEnabled "
        "FROM Win32_Processor",
        ("Name", "MaxClockSpeed", "NumberOfCores", "NumberOfLogicalProcessors",
         "L2CacheSize", "L3CacheSize", "Manufacturer",
         "VirtualizationFirmwareEnabled"),
    )
    if rows:
        row = rows[0]
        if row.get("Name"):
            info["name"] = str(row["Name"]).strip()
        for src, dst in (
            ("MaxClockSpeed", "base_mhz"),
            ("Manufacturer", "vendor"),
        ):
            if row.get(src):
                info[dst] = row[src]
        cores = sum(int(r.get("NumberOfCores") or 0) for r in rows)
        logical = sum(int(r.get("NumberOfLogicalProcessors") or 0) for r in rows)
        if cores:
            info["physical_cores"] = cores
        if logical:
            info["logical_cores"] = logical
        for src, dst in (("L2CacheSize", "l2_kb"), ("L3CacheSize", "l3_kb")):
            if row.get(src):
                info[dst] = row[src]
        info["virtualization_firmware"] = bool(row.get("VirtualizationFirmwareEnabled"))
        info["sockets"] = len(rows)
    return info


def _gpu_identity() -> list[dict[str, object]]:
    rows = windows.wmi_query(
        "SELECT Name, AdapterRAM, DriverVersion, DriverDate, VideoProcessor, "
        "CurrentHorizontalResolution, CurrentVerticalResolution, "
        "CurrentRefreshRate, Status FROM Win32_VideoController",
        ("Name", "AdapterRAM", "DriverVersion", "DriverDate", "VideoProcessor",
         "CurrentHorizontalResolution", "CurrentVerticalResolution",
         "CurrentRefreshRate", "Status"),
    )
    gpus: list[dict[str, object]] = []
    for row in rows:
        ram = row.get("AdapterRAM")
        # Win32_VideoController.AdapterRAM is a uint32 and wraps above 4 GB, so
        # it is a hint about the adapter, never a VRAM budget. Real numbers come
        # from the GPU Adapter Memory performance counters.
        try:
            ram = int(ram) if ram is not None else None
        except (TypeError, ValueError):
            ram = None
        width = row.get("CurrentHorizontalResolution")
        height = row.get("CurrentVerticalResolution")
        name = str(row.get("Name") or "Unknown GPU").strip()
        gpus.append({
            "name": name,
            "driver": row.get("VideoProcessor"),
            "card": None,
            "adapter_ram": ram,
            "driver_version": row.get("DriverVersion"),
            "driver_date": windows.wmi_date(row.get("DriverDate")),
            "video_processor": row.get("VideoProcessor"),
            "resolution": f"{width}x{height}" if width and height else None,
            "refresh_hz": row.get("CurrentRefreshRate"),
            "status": row.get("Status"),
            "integrated": _looks_integrated(name),
        })
    return gpus


def _looks_integrated(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in ("iris", "uhd graphics", "hd graphics", "vega", "radeon graphics",
                      "microsoft basic", "arc(tm) graphics", "radeon(tm) graphics")
    )


def _machine() -> dict[str, object]:
    rows = windows.wmi_query(
        "SELECT Name, Domain, Workgroup, PartOfDomain, Manufacturer, Model, "
        "TotalPhysicalMemory, SystemType, DomainRole, NumberOfProcessors, "
        "HypervisorPresent FROM Win32_ComputerSystem",
        ("Name", "Domain", "Workgroup", "PartOfDomain", "Manufacturer", "Model",
         "TotalPhysicalMemory", "SystemType", "DomainRole", "NumberOfProcessors",
         "HypervisorPresent"),
    )
    info: dict[str, object] = {
        "manufacturer": None, "model": None, "board": None,
        "bios_version": None, "bios_date": None, "part_of_domain": False,
        "serial": None, "serial_reason": None,
        "computer_name": None, "domain": None, "workgroup": None,
        "system_type": None, "hypervisor_present": None,
    }
    if rows:
        row = rows[0]
        info.update({
            "computer_name": row.get("Name"),
            "domain": row.get("Domain"),
            "workgroup": row.get("Workgroup"),
            "part_of_domain": bool(row.get("PartOfDomain")),
            "manufacturer": row.get("Manufacturer"),
            "model": row.get("Model"),
            "system_type": row.get("SystemType"),
            "hypervisor_present": (bool(row["HypervisorPresent"])
                                   if row.get("HypervisorPresent") is not None else None),
        })
    bios = windows.wmi_query(
        "SELECT SerialNumber, SMBIOSBIOSVersion, ReleaseDate, Manufacturer FROM Win32_BIOS",
        ("SerialNumber", "SMBIOSBIOSVersion", "ReleaseDate", "Manufacturer"),
    )
    if bios:
        info["bios_version"] = bios[0].get("SMBIOSBIOSVersion")
        info["bios_date"] = windows.wmi_date(bios[0].get("ReleaseDate"))
        info["serial"] = str(bios[0].get("SerialNumber") or "").strip() or None
    board = windows.wmi_query("SELECT Product, Manufacturer FROM Win32_BaseBoard",
                              ("Product", "Manufacturer"))
    if board:
        info["board"] = board[0].get("Product")
    if not rows and not bios:
        info["serial_reason"] = windows.wmi_reason()
    return info


def _virtualization(machine: dict[str, object]) -> str | None:
    """What hypervisor this is a guest of, from the model string the
    firmware reports -- the Windows counterpart of systemd-detect-virt."""
    model = str(machine.get("model") or "").lower()
    manufacturer = str(machine.get("manufacturer") or "").lower()
    blob = f"{manufacturer} {model}"
    for hint, name in (("virtual machine", "hyperv"), ("vmware", "vmware"),
                       ("virtualbox", "oracle"), ("kvm", "kvm"), ("qemu", "qemu"),
                       ("xen", "xen"), ("parallels", "parallels"),
                       ("amazon ec2", "amazon"), ("google compute", "google")):
        if hint in blob:
            return name
    if machine.get("hypervisor_present") and "microsoft corporation" in manufacturer:
        return "hyperv"
    return None


_cache: dict[str, object] | None = None


def collect(force: bool = False) -> dict[str, object]:
    global _cache
    if _cache is not None and not force:
        # Uptime is the one field that must stay live.
        _cache["uptime_seconds"] = time.time() - float(_cache["boot_time"])  # type: ignore[arg-type]
        return _cache

    boot = psutil.boot_time()
    total_ram = psutil.virtual_memory().total
    machine = _machine()
    payload: dict[str, object] = {
        "platform": PLATFORM,
        "hostname": socket.gethostname(),
        "fqdn": _fqdn(),
        "user": getpass.getuser(),
        "user_domain": os.environ.get("USERDOMAIN"),
        "elevated": is_elevated(),
        "os": _registry_os(),
        "kernel": f"Windows NT {platform.version()}" if windows.IS_WINDOWS
                  else f"{platform.system()} {platform.release()}",
        "machine_id": windows.reg_value(windows.HKLM, r"SOFTWARE\Microsoft\Cryptography",
                                        "MachineGuid"),
        "cpu": _cpu_identity(),
        "gpus": _gpu_identity(),
        "machine": machine,
        "virtualization": _virtualization(machine),
        "container": None,
        "container_warning": None,
        "cgroup_version": None,
        "psi_available": False,
        "psi_reason": windows.not_capable("PSI is a Linux kernel interface; "
                                          "pressure is derived from counters"),
        "access": windows.access_map(),
        "total_ram": total_ram,
        "boot_time": boot,
        "uptime_seconds": time.time() - boot,
        "python": sys.version.split()[0],
        "pid": os.getpid(),
        "timezone": time.strftime("%Z"),
        "utc_offset_minutes": -time.timezone // 60 if not time.daylight
                              else -time.altzone // 60,
    }
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
