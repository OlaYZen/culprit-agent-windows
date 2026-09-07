# culprit-agent-windows

The **Windows** agent for [culprit](https://github.com/OlaYZen/culprit): a
self-contained, report-only node. Clone this repo onto any Windows 10/11 or
Windows Server machine you want to watch; it carries its own copy of the
runnable `culprit` package, so at runtime it needs nothing from the host repo.
It samples the machine and pushes reports to the culprit host; it runs no
dashboard and **opens no listening ports**.

The Linux agent lives in [culprit-agent](https://github.com/OlaYZen/culprit-agent).
This one reports the same payload shapes to the same host, so a fleet can mix
both, and the dashboard shows what a Windows box can and cannot say.

## Deploy

```powershell
git clone https://github.com/OlaYZen/culprit-agent-windows.git
cd culprit-agent-windows
.\agent.ps1          # or double-click agent.cmd
```

That is the whole install. `agent.ps1` creates a venv (psutil + pywin32)
outside the checkout, **asks** for the culprit host's URL and this node's token
(get the token from the host dashboard: Nodes > "Generate token"; it looks like
`<name>.<secret>`), checks that the host is reachable and accepts the token,
saves both to `agent.json` so nothing is typed again, and offers to set the
agent up as a **scheduled task** that starts on boot and restarts on failure.

From an **Administrator** PowerShell the task runs as SYSTEM at boot, which is
what reads the Security event log (sign-ins, lock/unlock, failed sign-ins),
other users' processes and the drive failure-prediction bit; the venv, config
and flight recorder live under `%ProgramData%\culprit-agent`. Unelevated, the
task runs as you at sign-in, the files live in your profile
(`%LOCALAPPDATA%\culprit-agent`, `%APPDATA%\culprit-agent`), and it sees your
own processes fully and other users' partly -- but it can see your windows, so
**"not responding" detection works**, which the SYSTEM task cannot do
(services have no desktop).

Other ways to run it:

```powershell
.\agent.ps1 -Run                                          # foreground, using the saved config
.\agent.ps1 -Run -Host http://192.168.1.1:8787 -Token web-01.<secret>   # ...or with the values given
.\agent.ps1 -Configure                                    # change the host or token, then restart the task
.\agent.ps1 -InstallOnly                                  # venv only, no prompts (CI, images)
.\agent.ps1 -Host https://hub:8787 -Token web-01.<secret> -Insecure     # self-signed TLS
```

`agent.cmd` is the double-clickable equivalent for when PowerShell's execution
policy is in the way; it bypasses the policy for that one run and changes no
machine setting. Needs Python 3.10+ from python.org (the Microsoft Store build
restricts venv).

## What it reports

The same sections as the Linux agent, from Windows sources:

| | Source |
|---|---|
| **Processor** | `% Processor Utility` (frequency-aware, what Task Manager shows), per core, the run-queue depth, clock and turbo ratio, interrupt + DPC time, the active power plan |
| **Memory** | In use, available, **commit charge against its limit** (enforced on Windows, so it is a real ceiling), hard-fault rate, paged/non-paged pool, page files |
| **GPU** | Per-adapter and **per-process** utilisation and VRAM by engine (3D, copy, video decode/encode) from the `GPU Engine` counters -- every WDDM adapter, integrated Intel/AMD included, no vendor library |
| **Disk** | Per-physical-drive throughput, **queue depth and per-transfer latency**, volume capacity with a fill forecast, drive model/bus/firmware and the SMART failure-prediction bit |
| **Network** | Per-adapter throughput, errors and drops, adapter config (IP/DNS/gateway/DHCP), the socket table mapped to its processes, VPN and WAN-exit detection, reachability probes |
| **Processes** | Every process with CPU, memory, private bytes, disk I/O, GPU, threads, handles, page-fault rate, uptime -- from one `Process V2` counter collect (~100 ms for 450 processes) -- plus **"not responding"** windows |
| **Services** | All of them from the Service Control Manager, the auto-start ones that are not running called out, scheduled tasks as the timer list |
| **Events** | Bluescreens with decoded stop codes, app crashes with the faulting module and exception meaning, hangs, disk errors, service failures, WHEA hardware errors, low-memory diagnoses, Windows Update failures, Group Policy, time-sync and domain-connectivity problems, minidumps, pending reboot |
| **Sessions** | Who is signed in now (console/RDP, locked or not), sign-in/sign-out history, lock/unlock and failed sign-ins (elevated), boots and clean shutdowns |
| **Sync** | OneDrive: queue, failures, conflicts, stall flags, Known Folder Move health, per account |
| **Ports** | What is listening on each port and the process behind it, with the host's End task |
| **Outage Doctor** | Automatic services that are stopped (walked to the dependency that stopped first), services the SCM keeps restarting, a service running but no longer listening, expiring TLS certificates, the clock unsynchronised, DNS failing, a volume gone read-only, storage errors, a pending reboot -- each with a fix and the Restart / Start verb |
| **Coroner** | After a crash or power loss: the shutdown record (who asked, and why), the bugcheck's stop code, WHEA and disk errors, the low-memory event, Windows Update installs just before |

The **Lag Doctor** runs the same two-stage model as on Linux, in its derived
mode (Windows has no PSI): a 0..1 pressure per resource from the run queue,
hard faults and disk latency, then each process scored by its share of a
pressured resource. A not-responding window is scored ungated and raised as its
own finding, because it is the one signal that means "you are being made to
wait" regardless of any counter.

## What Windows cannot say

Every one of these is reported as **"Not capable in Windows"** with the reason,
never as a blank panel or a zero:

- **PSI** (pressure stall information): a Linux kernel interface. Pressure is
  derived from counters and the dashboard says so.
- **Per-service resource attribution** (cgroups): no per-service CPU, memory or
  stall accounting. The process table names what each `svchost` hosts.
- **Load average, D-state, run delay, kernel threads, wchan**: no Windows
  equivalents. The run-queue depth and the hung-window count play their part.
- **Software RAID and per-core IRQ rates** (`kernel` section).
- **Containers**: Windows containers are not identified in this port.
- **Deleted-but-open files** and the truncate verb: Windows refuses to delete
  an open file, so the situation cannot arise.
- **Per-file write rates and per-volume writers**: naming a process's open files
  costs ~250 ms per process on Windows.
- **inotify watch exhaustion** and **conntrack** limits.
- **Per-connection RTT / retransmits** (`tcp_info`): needs ESTATS and elevation.
- **Accept-queue overflow** ("turned-away clients"): not exposed per listener.
- **The OOM killer's ranking**: Windows has no OOM killer; the memory forecast
  is the equivalent answer.
- **`reset-failed`** for services: the SCM keeps no failed state to reset.

## Actions the host can relay

End task, priority (Windows priority classes: idle, below normal, normal,
above normal, high -- never realtime), **Throttle** (a Job Object CPU rate
cap: half or a quarter of the machine, reversible), Restart / Start for the
Outage Doctor's items, and the **remote update** (a `git reset` to the branch
the host names, then the task restarts it -- capable only when started by the
scheduled task, so something brings it back up). All are gated by the agent's
own `allow_process_actions`, and the guards refuse PID 0/4, csrss, lsass,
services.exe, the agent itself, and the services Windows cannot run without.

## Verifying a change

There is no Windows machine in the dev loop, so the shape checker stands in:

```bash
python tools/check_shapes.py            # both modes
python tools/check_shapes.py --mode fake --dump
```

It runs every collector twice -- **bare** (no pywin32: every source must
degrade to `available: False` with a reason) and **fake** (with
`tools/fakewin.py`'s stand-ins for PDH, the event log, WMI, the registry,
WTS and the SCM, so the parsing and aggregation paths run on canned data) --
and checks every dotted path in the host's frontend contract
(`../culprit/tools/check_contract.py`, read live) against what came out.
What it cannot prove is that the real Windows APIs behave as the fakes do;
that was measured on a real machine in the original Windows build this port
descends from, and needs a real machine again after any change to the PDH or
event-log code.

## Versioning and updates

`version.json` is the version; the host compares it against what this
repository's `main` (or the configured branch) publishes, and the remote
update is a `git reset --hard` plus `pip install`, so the checkout must be a
real clone with an `origin` remote and a clean tree.
