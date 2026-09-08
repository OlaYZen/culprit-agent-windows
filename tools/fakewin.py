"""Fake pywin32 / winreg modules for exercising the Windows collectors on a
Linux dev box.

They answer the exact calls culprit/windows.py and the collectors make, with
canned data shaped like the real thing (a `\\Process V2` array keyed
`name:pid`, GPU engine instances, PhysicalDisk instances, event-log XML,
registry values, WTS sessions, an SCM status). Nothing here proves the real
APIs behave this way -- the original Windows build did, on a real machine --
but it proves the parsing, the aggregation and every payload key, which is
what breaks silently when a field is renamed.

Install with `install()` BEFORE importing anything from `culprit`.
"""

from __future__ import annotations

import os
import sys
import types
import time

OWN_PID = os.getpid()
NOW = time.time()

# ------------------------------------------------------------------ PDH
_PROC_V2 = {
    "System:4": {"cpu": 1.2, "working_set": 8_000_000, "working_set_private": 100_000,
                 "private_bytes": 200_000, "threads": 200, "handles": 4000, "ppid": 0,
                 "io_read": 1000.0, "io_write": 500.0, "page_faults": 5.0, "elapsed": 90000.0},
    "chrome:4242": {"cpu": 240.0, "working_set": 900_000_000, "working_set_private": 700_000_000,
                    "private_bytes": 800_000_000, "threads": 60, "handles": 2400, "ppid": 1000,
                    "io_read": 4_000_000.0, "io_write": 1_500_000.0, "page_faults": 3000.0,
                    "elapsed": 3600.0},
    "notepad:5151": {"cpu": 0.0, "working_set": 30_000_000, "working_set_private": 10_000_000,
                     "private_bytes": 12_000_000, "threads": 4, "handles": 300, "ppid": 1000,
                     "io_read": 0.0, "io_write": 0.0, "page_faults": 0.0, "elapsed": 600.0},
    "svchost:1300": {"cpu": 3.0, "working_set": 40_000_000, "working_set_private": 20_000_000,
                     "private_bytes": 25_000_000, "threads": 20, "handles": 12000, "ppid": 700,
                     "io_read": 10.0, "io_write": 20.0, "page_faults": 10.0, "elapsed": 89000.0},
    f"python:{OWN_PID}": {"cpu": 2.0, "working_set": 60_000_000, "working_set_private": 40_000_000,
                          "private_bytes": 50_000_000, "threads": 12, "handles": 500, "ppid": 700,
                          "io_read": 100.0, "io_write": 100.0, "page_faults": 2.0, "elapsed": 100.0},
    "_Total": {"cpu": 246.2, "working_set": 1_038_000_000, "working_set_private": 770_100_000,
               "private_bytes": 887_200_000, "threads": 296, "handles": 19200, "ppid": 0,
               "io_read": 4_001_110.0, "io_write": 1_500_620.0, "page_faults": 3017.0,
               "elapsed": 0.0},
}
_PROC_COUNTER_KEY = {
    "% Processor Time": "cpu", "Working Set": "working_set",
    "Working Set - Private": "working_set_private", "Private Bytes": "private_bytes",
    "Thread Count": "threads", "Handle Count": "handles",
    "Creating Process ID": "ppid", "IO Read Bytes/sec": "io_read",
    "IO Write Bytes/sec": "io_write", "Page Faults/sec": "page_faults",
    "Elapsed Time": "elapsed",
}
_GPU_ENGINE = {
    "pid_4242_luid_0x00000000_0x0000ABCD_phys_0_eng_0_engtype_3D": 35.0,
    "pid_4242_luid_0x00000000_0x0000ABCD_phys_0_eng_1_engtype_VideoDecode": 12.0,
    "pid_5151_luid_0x00000000_0x0000ABCD_phys_0_eng_0_engtype_3D": 2.0,
    "pid_4_luid_0x00000000_0x0000ABCD_phys_0_eng_2_engtype_Copy": 0.0,
}
_GPU_MEM = {"pid_4242_luid_0x00000000_0x0000ABCD_phys_0": 300_000_000.0}
_DISK = {
    "0 C:": {"read": 2_000_000.0, "write": 900_000.0, "reads": 120.0, "writes": 40.0,
             "queue": 0.4, "idle": 82.0, "lat": 0.0035, "rlat": 0.003, "wlat": 0.005, "split": 1.0},
    "1 D:": {"read": 0.0, "write": 0.0, "reads": 0.0, "writes": 0.0, "queue": 0.0,
             "idle": 100.0, "lat": 0.0, "rlat": 0.0, "wlat": 0.0, "split": 0.0},
    "_Total": {"read": 2_000_000.0, "write": 900_000.0, "reads": 120.0, "writes": 40.0,
               "queue": 0.4, "idle": 91.0, "lat": 0.0035, "rlat": 0.003, "wlat": 0.005, "split": 1.0},
}
_DISK_KEY = {"Disk Read Bytes/sec": "read", "Disk Write Bytes/sec": "write",
             "Disk Reads/sec": "reads", "Disk Writes/sec": "writes",
             "Current Disk Queue Length": "queue", "% Idle Time": "idle",
             "Avg. Disk sec/Transfer": "lat", "Avg. Disk sec/Read": "rlat",
             "Avg. Disk sec/Write": "wlat", "Split IO/Sec": "split"}
_SCALARS = {
    r"\Processor Information(_Total)\% Processor Utility": 23.5,
    r"\Processor Information(_Total)\% Processor Performance": 118.0,
    r"\Processor Information(_Total)\Processor Frequency": 2600.0,
    r"\Processor Information(_Total)\% Privileged Time": 5.0,
    r"\Processor Information(_Total)\% Interrupt Time": 0.4,
    r"\Processor Information(_Total)\% DPC Time": 0.2,
    r"\Processor Information(_Total)\% User Time": 18.0,
    r"\System\Processor Queue Length": 3.0,
    r"\System\Context Switches/sec": 25000.0,
    r"\System\System Calls/sec": 90000.0,
    r"\System\Processes": 5.0,
    r"\System\Threads": 296.0,
    r"\Memory\Available MBytes": 6000.0,
    r"\Memory\Committed Bytes": 12_000_000_000.0,
    r"\Memory\Commit Limit": 32_000_000_000.0,
    r"\Memory\Pages/sec": 12.5,
    r"\Memory\Pages Input/sec": 10.0,
    r"\Memory\Pages Output/sec": 2.5,
    r"\Memory\Page Faults/sec": 4000.0,
    r"\Memory\Cache Bytes": 2_000_000_000.0,
    r"\Memory\Pool Nonpaged Bytes": 300_000_000.0,
    r"\Memory\Pool Paged Bytes": 500_000_000.0,
    r"\Paging File(_Total)\% Usage": 3.2,
    r"\Cache\Dirty Pages": 120.0,
}
_PERCORE = {"0,0": 30.0, "0,1": 17.0, "0,2": 40.0, "0,3": 7.0, "0,_Total": 23.5, "_Total": 23.5}


def _make_win32pdh():
    m = types.ModuleType("win32pdh")
    m.PDH_FMT_DOUBLE, m.PDH_FMT_LARGE, m.PDH_FMT_LONG, m.PDH_FMT_NOCAP100 = 0x200, 0x400, 0x100, 0x8000
    counters: dict[int, str] = {}
    state = {"next": 1, "collected": 0}

    def OpenQuery():
        return 1

    def CloseQuery(_h):
        return None

    def AddCounter(_query, path):
        if "Thermal Zone" in path:
            raise Exception((0xC0000BB8, "PdhAddCounter", "The specified object was not found on the computer."))
        handle = state["next"]; state["next"] += 1
        counters[handle] = path
        return handle

    def CollectQueryData(_q):
        state["collected"] += 1

    def GetFormattedCounterValue(handle, _flag):
        path = counters[handle]
        if path not in _SCALARS:
            raise Exception((0x800007D5, "PdhGetFormattedCounterValue", "PDH_INVALID_DATA"))
        return (0, _SCALARS[path])

    def GetFormattedCounterArray(handle, _flag):
        path = counters[handle]
        if path.startswith("\\Process V2(*)\\"):
            key = _PROC_COUNTER_KEY[path.split("\\")[-1]]
            return {inst: vals[key] for inst, vals in _PROC_V2.items()}
        if path.startswith(r"\GPU Engine(*)"):
            return dict(_GPU_ENGINE)
        if path.startswith(r"\GPU Process Memory(*)\Dedicated"):
            return dict(_GPU_MEM)
        if path.startswith(r"\GPU Process Memory(*)\Shared"):
            return {k: 50_000_000.0 for k in _GPU_MEM}
        if path.startswith(r"\GPU Adapter Memory(*)"):
            return {"luid_0x00000000_0x0000ABCD_phys_0": 1_000_000_000.0}
        if path.startswith(r"\PhysicalDisk(*)"):
            key = _DISK_KEY[path.split("\\")[-1]]
            return {inst: vals[key] for inst, vals in _DISK.items()}
        if path.startswith(r"\Processor Information(*)"):
            return dict(_PERCORE)
        return {}

    def ExpandCounterPath(_path):
        return []

    m.OpenQuery, m.CloseQuery, m.AddCounter = OpenQuery, CloseQuery, AddCounter
    m.CollectQueryData = CollectQueryData
    m.GetFormattedCounterValue = GetFormattedCounterValue
    m.GetFormattedCounterArray = GetFormattedCounterArray
    m.ExpandCounterPath = ExpandCounterPath
    return m


# ------------------------------------------------------------------ WMI
_WMI_ROWS = {
    "Win32_Processor": [{"Name": "Intel(R) Core(TM) i7-1265U", "MaxClockSpeed": 2700,
                         "NumberOfCores": 10, "NumberOfLogicalProcessors": 12,
                         "L2CacheSize": 6656, "L3CacheSize": 12288, "Manufacturer": "GenuineIntel",
                         "VirtualizationFirmwareEnabled": True}],
    "Win32_VideoController": [{"Name": "Intel(R) Iris(R) Xe Graphics", "AdapterRAM": 1073741824,
                               "DriverVersion": "31.0.101.4502", "DriverDate": "20231110000000.000000-000",
                               "VideoProcessor": "Intel(R) Iris(R) Xe Graphics Family",
                               "CurrentHorizontalResolution": 1920, "CurrentVerticalResolution": 1200,
                               "CurrentRefreshRate": 60, "Status": "OK"}],
    "Win32_ComputerSystem": [{"Name": "WIN-DEV", "Domain": "corp.example", "Workgroup": None,
                              "PartOfDomain": True, "Manufacturer": "Dell Inc.", "Model": "Latitude 5530",
                              "TotalPhysicalMemory": 34000000000, "SystemType": "x64-based PC",
                              "DomainRole": 1, "NumberOfProcessors": 1, "HypervisorPresent": False}],
    "Win32_BIOS": [{"SerialNumber": "ABC123", "SMBIOSBIOSVersion": "1.14.0",
                    "ReleaseDate": "20240101000000.000000+000", "Manufacturer": "Dell Inc."}],
    "Win32_BaseBoard": [{"Product": "0ABCDE", "Manufacturer": "Dell Inc."}],
    "Win32_DiskDrive": [{"DeviceID": r"\\.\PHYSICALDRIVE0", "Index": 0, "Model": "NVMe KXG80ZNV1T02",
                         "InterfaceType": "SCSI", "MediaType": "Fixed hard disk media",
                         "Size": 1024000000000, "SerialNumber": "0000_1234", "Status": "OK",
                         "Partitions": 4, "FirmwareRevision": "AGHA0102"}],
    "MSStorageDriver_FailurePredictStatus": [],
    "MSFT_PhysicalDisk": [{"DeviceId": "0", "MediaType": 4}],
    "Win32_LogicalDiskToPartition": [{"Antecedent": 'Win32_DiskPartition.DeviceID="Disk #0, Partition #2"',
                                      "Dependent": 'Win32_LogicalDisk.DeviceID="C:"'}],
    "Win32_PageFileUsage": [{"Name": r"C:\pagefile.sys", "AllocatedBaseSize": 4864, "CurrentUsage": 120}],
    "Win32_IP4RouteTable": [{"InterfaceIndex": 12, "Metric1": 25}],
    "Win32_NetworkAdapterConfiguration": [{"Description": "Intel(R) Wi-Fi 6E AX211 160MHz",
                                           "IPAddress": ("192.168.1.50", "fe80::1"),
                                           "IPSubnet": ("255.255.255.0", "64"),
                                           "DefaultIPGateway": ("192.168.1.1",),
                                           "DNSServerSearchOrder": ("192.168.1.1",),
                                           "DHCPEnabled": True, "DHCPServer": "192.168.1.1",
                                           "MACAddress": "AA:BB:CC:DD:EE:FF", "DNSDomain": "corp.example",
                                           "InterfaceIndex": 12}],
}


def _make_win32com():
    m = types.ModuleType("win32com")
    client = types.ModuleType("win32com.client")

    class _Item:
        def __init__(self, row):
            self.__dict__.update(row)

    class _Service:
        def ExecQuery(self, wql):
            table = wql.split(" FROM ")[-1].split(" WHERE")[0].strip()
            return [_Item(r) for r in _WMI_ROWS.get(table, [])]

    client.GetObject = lambda _ns: _Service()
    m.client = client
    sys.modules["win32com.client"] = client
    return m


def _make_pythoncom():
    m = types.ModuleType("pythoncom")
    m.CoInitialize = lambda: None
    return m


# ------------------------------------------------------------- registry
_REG = {
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"): {
        "ProductName": "Windows 10 Pro", "DisplayVersion": "23H2", "CurrentBuildNumber": "22631",
        "UBR": 4317, "EditionID": "Professional", "InstallationType": "Client",
        "InstallDate": 1700000000},
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"): {
        "GDIProcessHandleQuota": 10000, "USERProcessHandleQuota": 10000},
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"): {
        "ActivePowerScheme": "381b4222-f694-41f0-9685-ff5bb260df2e"},
    ("HKLM", r"SOFTWARE\Microsoft\Cryptography"): {"MachineGuid": "11111111-2222-3333-4444-555555555555"},
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"): {},
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager"): {
        "PendingFileRenameOperations": [r"\??\C:\old.dll", "", r"\??\C:\x.dll", r"\??\C:\y.dll"]},
    ("HKCU", r"Software\Microsoft\OneDrive\Accounts"): {},
    ("HKCU", r"Software\Microsoft\OneDrive\Accounts\Business1"): {
        "UserFolder": os.getcwd(), "DisplayName": "Contoso", "Business": 1,
        "UserEmail": "user@contoso.example", "cid": "abc"},
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"): {
        "Desktop": os.getcwd(), "Personal": os.path.join(os.getcwd(), "OneDrive - Contoso", "Documents")},
}
_SUBKEYS = {("HKCU", r"Software\Microsoft\OneDrive\Accounts"): ["Business1"]}


def _make_winreg():
    m = types.ModuleType("winreg")
    m.HKEY_LOCAL_MACHINE, m.HKEY_CURRENT_USER = "HKLM", "HKCU"

    class _Key:
        def __init__(self, hive, path):
            self.hive, self.path = hive, path
            self.values = _REG[(hive, path)]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def OpenKey(root, path):
        if isinstance(root, _Key):
            root, path = root.hive, root.path + "\\" + path
        if (root, path) not in _REG:
            raise FileNotFoundError(2, "no such key")
        return _Key(root, path)

    def QueryValueEx(key, name):
        if name not in key.values:
            raise FileNotFoundError(2, "no such value")
        return (key.values[name], 1)

    def EnumValue(key, index):
        items = list(key.values.items())
        if index >= len(items):
            raise OSError(259, "no more data")
        return (items[index][0], items[index][1], 1)

    def EnumKey(key, index):
        subs = _SUBKEYS.get((key.hive, key.path), [])
        if index >= len(subs):
            raise OSError(259, "no more data")
        return subs[index]

    m.OpenKey, m.QueryValueEx, m.EnumValue, m.EnumKey = OpenKey, QueryValueEx, EnumValue, EnumKey
    return m


# ------------------------------------------------------------ event log
_EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="{provider}"/><EventID>{eid}</EventID><Level>{level}</Level>
<TimeCreated SystemTime="{when}"/><EventRecordID>{rec}</EventRecordID>
<Computer>WIN-DEV</Computer><Security UserID="S-1-5-21-1-2-3-1001"/></System>
<EventData>{data}</EventData></Event>"""


def _stamp(seconds_ago):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(NOW - seconds_ago, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def _named(**kv):
    return "".join(f'<Data Name="{k}">{v}</Data>' for k, v in kv.items())


def _positional(*vals):
    return "".join(f"<Data>{v}</Data>" for v in vals)


_EVENTS = {
    ("System", 1001): (("Microsoft-Windows-WER-SystemErrorReporting", 2, 500,
                        _positional("0x000000d1 (0x1, 0x2, 0x3, 0x4)", "C:\\Windows\\Minidump\\x.dmp", "abc")),),
    ("System", 41): (("Microsoft-Windows-Kernel-Power", 1, 380, _named(BugcheckCode=209)),),
    ("System", 6008): (("EventLog", 2, 381, _positional("12:00:00", "1/1/2026")),),
    ("System", 6006): (("EventLog", 4, 400, ""),),
    ("System", 6005): (("EventLog", 4, 380, ""),),
    ("System", 1074): (("USER32", 4, 420, _positional("C:\\Windows\\system32\\shutdown.exe (WIN-DEV)", "WIN-DEV",
                                                     "Other (Planned)", "0x80000000", "restart", "", "CORP\\olai")),),
    ("System", 7034): (("Service Control Manager", 2, 5000, _positional("Print Spooler", "3")),),
    ("System", 7031): (("Service Control Manager", 2, 4000, _positional("Print Spooler", "2", "60000", "1", "Restart the service")),),
    ("System", 129): (("stornvme", 3, 7000, _named(Device="\\Device\\RaidPort0")),),
    ("System", 2004): (("Microsoft-Windows-Resource-Exhaustion-Detector", 3, 600,
                        _named(Process1Name="chrome.exe", Process1Id=4242, Process1Bytes=9000000000)),),
    ("System", 19): (("Microsoft-Windows-WindowsUpdateClient", 4, 5400,
                      _named(updateTitle="2026-01 Cumulative Update for Windows 11 (KB5000001)", errorCode="0x0")),),
    ("System", 1014): (("Microsoft-Windows-DNS-Client", 3, 800, _named(QueryName="example.com")),),
    ("Application", 1000): (("Application Error", 2, 6000,
                             _positional("notepad.exe", "10.0.22621.1", "abcdef", "ntdll.dll", "10.0.22621.1",
                                         "0", "c0000005", "0x0004b70", "0x1420", "01dc000", "C:\\Windows\\notepad.exe",
                                         "C:\\Windows\\SYSTEM32\\ntdll.dll", "guid", "", "")),),
    ("Application", 1002): (("Application Hang", 2, 6100,
                             _positional("Excel.EXE", "16.0.1", "1f40", "01dc", "4250", "C:\\Excel.EXE",
                                         "", "", "", "Unknown")),),
    ("Security", 4624): (("Microsoft-Windows-Security-Auditing", 0, 7200,
                          _named(TargetUserName="olai", TargetDomainName="CORP", TargetLogonId="0x3e7",
                                 LogonType=2, ProcessName="C:\\Windows\\System32\\svchost.exe",
                                 WorkstationName="WIN-DEV", IpAddress="-")),),
    ("Security", 4647): (("Microsoft-Windows-Security-Auditing", 0, 3600,
                          _named(TargetUserName="olai", TargetDomainName="CORP", TargetLogonId="0x3e7")),),
    ("Security", 4800): (("Microsoft-Windows-Security-Auditing", 0, 5000,
                          _named(TargetUserName="olai", TargetLogonId="0x3e7")),),
    ("Security", 4625): (("Microsoft-Windows-Security-Auditing", 0, 900,
                          _named(TargetUserName="admin", TargetDomainName="CORP", Status="0xc000006d",
                                 SubStatus="0xc000006a", IpAddress="10.0.0.9")),),
    # Task Scheduler Operational: 100 opens an instance, 102 closes the same
    # one, which is what gives a scheduled task a measured duration.
    ("Microsoft-Windows-TaskScheduler/Operational", 100): (
        ("Microsoft-Windows-TaskScheduler", 4, 3600,
         _named(TaskName="\\Backup\\Nightly", InstanceId="{inst-1}", UserContext="SYSTEM")),
        ("Microsoft-Windows-TaskScheduler", 4, 90000,
         _named(TaskName="\\Maintenance\\Reindex", InstanceId="{inst-2}", UserContext="SYSTEM")),),
    ("Microsoft-Windows-TaskScheduler/Operational", 102): (
        ("Microsoft-Windows-TaskScheduler", 4, 3000,
         _named(TaskName="\\Backup\\Nightly", InstanceId="{inst-1}")),),
    ("Microsoft-Windows-User Profile Service/Operational", 2): (
        ("Microsoft-Windows-User Profile Service", 4, 7100, _named(Session=1)),),
}


# `schtasks /query /v /fo csv` as Windows prints it (trimmed to the columns
# the collector reads), with times generated from NOW so they line up with the
# Task Scheduler events above: Nightly's last run IS the instance the log
# paired, and Reindex's is newer than the stale 100 the log still holds.
def _task_stamp(ago):
    return time.strftime("%m/%d/%Y %I:%M:%S %p", time.localtime(NOW - ago))


SCHTASKS_CSV = (
    '"HostName","TaskName","Next Run Time","Status","Last Run Time","Last Result",'
    '"Task To Run","Run As User"\r\n'
    f'"WIN-DEV","\\Backup\\Nightly","{_task_stamp(-82800)}","Ready",'
    f'"{_task_stamp(3600)}","0","C:\\backup\\run.cmd","SYSTEM"\r\n'
    f'"WIN-DEV","\\Maintenance\\Reindex","{_task_stamp(-79200)}","Ready",'
    f'"{_task_stamp(1800)}","2147942402","C:\\tools\\reindex.exe","SYSTEM"\r\n'
)


def fake_run(real):
    """windows.run with schtasks answered from the canned CSV."""
    def run(argv, timeout=10.0):
        if argv and str(argv[0]) == "schtasks":
            return SCHTASKS_CSV
        return real(argv, timeout)
    return run


def _make_win32evtlog(elevated=True):
    m = types.ModuleType("win32evtlog")
    m.EvtQueryReverseDirection = 0x200
    m.EvtRenderEventXml = 1
    import re

    class _Query:
        def __init__(self, records):
            self.records = records

    def EvtQuery(channel, _flags, xpath, _x):
        if channel == "Security" and not elevated:
            raise Exception((5, "EvtQuery", "Access is denied."))
        ids = [int(i) for i in re.findall(r"EventID=(\d+)", xpath)]
        match = re.search(r"timediff\(@SystemTime\) <= (\d+)", xpath)
        window = int(match.group(1)) / 1000 if match else 10 ** 9
        records = []
        for (chan, eid), rows in _EVENTS.items():
            if chan != channel or (ids and eid not in ids):
                continue
            for provider, level, ago, data in rows:
                if ago > window:
                    continue
                records.append((ago, _EVENT_XML.format(provider=provider, eid=eid, level=level,
                                                       when=_stamp(ago), rec=eid * 10, data=data)))
        records.sort()
        return _Query([xml for _, xml in records])

    def EvtNext(query, count):
        batch, query.records = query.records[:count], query.records[count:]
        return batch

    def EvtRender(raw, _kind):
        return raw

    m.EvtQuery, m.EvtNext, m.EvtRender = EvtQuery, EvtNext, EvtRender
    return m


# ------------------------------------------------------------ GUI / WTS / SCM
def _make_win32gui():
    m = types.ModuleType("win32gui")
    m.IsWindowVisible = lambda h: True
    m.IsHungAppWindow = lambda h: h == 77
    m.GetWindowText = lambda h: "Book1 - Excel" if h == 77 else "Untitled"
    m.EnumWindows = lambda cb, ctx: [cb(h, ctx) for h in (77, 78)]
    m.GetGuiResources = lambda handle, flag: 9000 if flag == 0 else 400
    return m


def _make_win32process():
    m = types.ModuleType("win32process")
    m.GetWindowThreadProcessId = lambda h: (1, 5151 if h == 77 else 4242)
    return m


def _make_win32api():
    m = types.ModuleType("win32api")
    m.OpenProcess = lambda access, inherit, pid: 1000 + pid
    m.CloseHandle = lambda h: None
    m.GetVolumeInformation = lambda mount: ("Windows", 123, 255, 0, "NTFS")
    return m


def _make_win32con():
    m = types.ModuleType("win32con")
    m.PROCESS_QUERY_INFORMATION, m.PROCESS_QUERY_LIMITED_INFORMATION = 0x400, 0x1000
    m.PROCESS_SET_QUOTA, m.PROCESS_TERMINATE = 0x100, 0x1
    return m


def _make_win32ts():
    m = types.ModuleType("win32ts")
    m.WTS_CURRENT_SERVER_HANDLE = 0
    m.WTSUserName, m.WTSDomainName, m.WTSClientName, m.WTSClientProtocolType = 5, 7, 10, 16
    m.WTSEnumerateSessions = lambda h: [{"SessionId": 0, "WinStationName": "Services", "State": 4},
                                        {"SessionId": 1, "WinStationName": "Console", "State": 0},
                                        {"SessionId": 2, "WinStationName": "RDP-Tcp#3", "State": 0}]

    def query(_h, sid, kind):
        if sid == 0:
            return ""
        table = {5: "olai" if sid == 1 else "admin", 7: "CORP", 10: "" if sid == 1 else "LAPTOP-9",
                 16: 0 if sid == 1 else 2}
        return table.get(kind)

    m.WTSQuerySessionInformation = query
    m.ProcessIdToSessionId = lambda pid: 2
    return m


def _make_win32service():
    m = types.ModuleType("win32service")
    m.SC_MANAGER_CONNECT, m.SERVICE_QUERY_STATUS, m.SERVICE_QUERY_CONFIG = 1, 4, 1
    m.SERVICE_RUNNING, m.SERVICE_STOPPED = 4, 1
    m.OpenSCManager = lambda a, b, c: 1
    m.OpenService = lambda scm, name, access: name
    m.CloseServiceHandle = lambda h: None
    m.QueryServiceStatusEx = lambda name: {"CurrentState": 1 if name == "Spooler" else 4,
                                           "ProcessId": 0 if name == "Spooler" else 1300,
                                           "Win32ExitCode": 1066 if name == "Spooler" else 0,
                                           "ServiceSpecificExitCode": 5 if name == "Spooler" else 0}
    m.QueryServiceConfig = lambda name: (16, 2, 1, "C:\\x.exe", None, 0, ["RPCSS", "http"] if name == "Spooler" else [], None, "Print Spooler")
    return m


def _make_win32serviceutil():
    m = types.ModuleType("win32serviceutil")
    m.StartService = lambda name: None
    m.StopService = lambda name: None
    m.WaitForServiceStatus = lambda name, state, timeout: None
    return m


def _make_win32job():
    m = types.ModuleType("win32job")
    m.JobObjectCpuRateControlInformation = 15
    m.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, m.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 1, 4

    class _Job:
        pass

    m.CreateJobObject = lambda sec, name: _Job()
    m.AssignProcessToJobObject = lambda job, handle: None
    m.QueryInformationJobObject = lambda job, cls: {"ControlFlags": 0, "CpuRate": 0}
    m.SetInformationJobObject = lambda job, cls, info: None
    return m


def _make_win32security():
    m = types.ModuleType("win32security")
    m.ConvertStringSidToSid = lambda text: text
    m.LookupAccountSid = lambda host, sid: ("olai", "CORP", 1)
    return m


# ------------------------------------------------------------- psutil bits
class _FakeService:
    def __init__(self, row):
        self._row = row

    def as_dict(self):
        return dict(self._row)


_SERVICES = [
    {"name": "Spooler", "display_name": "Print Spooler", "status": "stopped", "start_type": "automatic",
     "pid": None, "username": "LocalSystem", "binpath": "C:\\Windows\\System32\\spoolsv.exe",
     "description": "Manages print jobs"},
    {"name": "Dnscache", "display_name": "DNS Client", "status": "running", "start_type": "automatic",
     "pid": 1300, "username": "NT AUTHORITY\\NetworkService", "binpath": "svchost.exe -k NetworkService",
     "description": "Caches DNS"},
    {"name": "W32Time", "display_name": "Windows Time", "status": "running", "start_type": "manual",
     "pid": 1300, "username": "LocalService", "binpath": "svchost.exe -k LocalService",
     "description": "Time sync"},
    {"name": "wuauserv", "display_name": "Windows Update", "status": "stopped", "start_type": "automatic",
     "pid": None, "username": "LocalSystem", "binpath": "svchost.exe", "description": "Updates"},
]


def install(elevated: bool = True) -> None:
    """Put the fake modules where `import win32pdh` etc. will find them."""
    for name, maker in (("win32pdh", _make_win32pdh), ("win32evtlog", lambda: _make_win32evtlog(elevated)),
                        ("win32gui", _make_win32gui), ("win32process", _make_win32process),
                        ("win32service", _make_win32service), ("win32serviceutil", _make_win32serviceutil),
                        ("win32ts", _make_win32ts), ("win32job", _make_win32job),
                        ("win32api", _make_win32api), ("win32security", _make_win32security),
                        ("win32con", _make_win32con), ("winreg", _make_winreg),
                        ("win32com", _make_win32com), ("pythoncom", _make_pythoncom)):
        sys.modules[name] = maker()
    import psutil

    psutil.win_service_iter = lambda: [_FakeService(r) for r in _SERVICES]

    class _LogonUI:
        pid = 999_999
        info = {"name": "LogonUI.exe"}

    real_iter = psutil.process_iter

    def process_iter(attrs=None, ad_value=None):
        yield from real_iter(attrs, ad_value)
        if attrs and "name" in attrs:
            yield _LogonUI()

    psutil.process_iter = process_iter
    # The collectors ask windows.is_elevated(); in fake mode the box is an
    # administrator's, so the Security log answers.
    import culprit.windows as windows
    import culprit.util as util
    windows.is_elevated = lambda: elevated
    windows.IS_WINDOWS = True
    util.is_elevated.cache_clear()
    for name in ("IDLE_PRIORITY_CLASS", "BELOW_NORMAL_PRIORITY_CLASS", "NORMAL_PRIORITY_CLASS",
                 "ABOVE_NORMAL_PRIORITY_CLASS", "HIGH_PRIORITY_CLASS", "REALTIME_PRIORITY_CLASS"):
        if not hasattr(psutil, name):
            setattr(psutil, name, {"IDLE_PRIORITY_CLASS": 0x40, "BELOW_NORMAL_PRIORITY_CLASS": 0x4000,
                                   "NORMAL_PRIORITY_CLASS": 0x20, "ABOVE_NORMAL_PRIORITY_CLASS": 0x8000,
                                   "HIGH_PRIORITY_CLASS": 0x80, "REALTIME_PRIORITY_CLASS": 0x100}[name])
