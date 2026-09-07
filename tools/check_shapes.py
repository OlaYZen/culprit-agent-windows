#!/usr/bin/env python3
"""Every collector, twice, against the host's frontend contract.

There is no Windows machine in the dev loop, so this is what stands between
a field rename and a dashboard that silently shows dashes. It runs the
collectors the way the sampler does:

  1. **bare** -- as on this (Linux) box with no pywin32: every source must
     degrade to `available: False` + a reason, never raise, and every key the
     host reads must still be present (None, not missing).
  2. **fake** -- with tools/fakewin.py's stand-ins for win32pdh, win32evtlog,
     winreg, WMI, WTS and the SCM installed first: the parsing and aggregation
     paths run on canned data, the Lag Doctor scores a hung window, the
     Outage Doctor walks a stopped service to its root, the forensics read a
     synthetic previous boot.

In both modes every dotted path in the host's CONTRACT map (read live from a
sibling ../culprit checkout's tools/check_contract.py, so it cannot drift) is
checked against the produced sections, with the same OPTIONAL allowances.

    python tools/check_shapes.py            # both modes
    python tools/check_shapes.py --mode fake --dump   # print the payload too
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST_CONTRACT = ROOT.parent / "culprit" / "tools" / "check_contract.py"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

# Sections the sampler publishes, and which contract endpoints read them.
# "node:" is the whole snapshot; "node:<section>" one section.
_SNAPSHOT_KEYS = ("cpu", "memory", "psi", "gpu", "disk", "network", "pressures",
                  "system", "process_table", "diagnosis", "volumes", "services",
                  "network_detail", "ports", "sync", "events", "cgroups", "kernel",
                  "changes", "ceilings", "outage")
# Contract paths the HOST adds to a section after ingest (Expectations
# annotate the diagnosis), so the agent never produces them.
_HOST_ADDED = {"expected_count"}
# Linux-only paths a Windows agent legitimately answers with None: they are
# present (None) so the contract passes; listed here so the report says
# which ones are honest blanks rather than measured.
_EXPECTED_NONE = {
    "cpu.iowait", "cpu.steal", "cpu.blocked", "cpu.load_1", "system.container",
    "system.machine.bios_version",
}


def _load_contract():
    if not HOST_CONTRACT.exists():
        return None, None
    spec = importlib.util.spec_from_file_location("check_contract", HOST_CONTRACT)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(HOST_CONTRACT.parent))
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    finally:
        sys.path.pop(0)
    return module.CONTRACT, module.OPTIONAL


def _dig(payload, path: str):
    node = payload
    for part in path.split("."):
        if part.endswith("[]"):
            key = part[:-2]
            if key:
                if not isinstance(node, dict) or key not in node:
                    return False, None
                node = node[key]
            if not isinstance(node, list):
                return False, None
            if not node:
                return None, None
            node = node[0]
        else:
            if not isinstance(node, dict) or part not in node:
                return False, None
            node = node[part]
    return True, node


def run_collectors(mode: str) -> dict:
    """The sampler's four ticks, once each (proc twice for rates), in order."""
    from culprit import config as config_module
    from culprit.collectors import ceilings, cgroups, disks, events, gpu, kernel, memtrend
    from culprit.collectors import network, outage, ports, processes, services, sync, sysinfo
    from culprit.collectors.changes import ChangeLog
    from culprit.collectors.cpu_mem import CpuMemoryCollector
    from culprit.collectors.lag import LagAnalyzer
    from culprit.collectors import forensics, recorder

    config_module.load()
    cfg = config_module.get()
    lag = LagAnalyzer()
    timings: dict[str, float] = {}

    def timed(name, fn):
        started = time.perf_counter()
        out = fn()
        timings[name] = round((time.perf_counter() - started) * 1000, 1)
        return out

    system = timed("sysinfo", sysinfo.collect)
    cpu_mem = CpuMemoryCollector()
    gpu_c = gpu.GpuCollector(system.get("gpus") or [])
    disk_c = disks.DiskCollector()
    net_c = network.NetworkRateCollector()
    proc_c = processes.ProcessCollector(logical_cores=(system.get("cpu") or {}).get("logical_cores"))
    changes = ChangeLog(boot_time=system.get("boot_time"))
    time.sleep(0.3)

    sample = timed("fast", cpu_mem.sample)
    sample["gpu"] = timed("gpu", gpu_c.sample)
    sample["disk"] = timed("disk", disk_c.sample)
    sample["network"] = timed("network", net_c.sample)
    pressures = lag.pressures(sample, cfg)
    snapshot = {"cpu": sample["cpu"], "memory": sample["memory"], "psi": sample["psi"],
                "gpu": sample["gpu"], "disk": sample["disk"], "network": sample["network"],
                "pressures": pressures, "system": system, "ts": time.time()}

    for _ in range(2):
        result = timed("proc", lambda: proc_c.sample(gpu_per_pid=gpu_c.per_pid, limit=cfg.process_count))
    procs = result["processes"]
    lag.score_processes(procs, snapshot, pressures, cfg)
    cg = cgroups.CgroupCollector().sample(containers=proc_c.containers)
    kn = kernel.KernelCollector().sample()
    changes.observe_processes(procs)
    changes.observe_cgroups(cg)
    trend = memtrend.MemoryTrend()
    trend.observe(time.time(), snapshot["memory"], procs)
    forecast = trend.forecast(time.time(), total_ram=snapshot["memory"].get("total"))

    # Slow tier first (the doctor reads volumes/ports/ceilings from it).
    vol_c, svc_c = disks.VolumeCollector(), services.ServiceCollector()
    nd_c, ports_c, sync_c = network.NetworkDetailCollector(), ports.PortsCollector(), sync.SyncCollector()
    ceil_c, out_c = ceilings.CeilingCollector(), outage.OutageCollector()
    volumes = timed("volumes", lambda: vol_c.sample(processes=procs))
    svcs = timed("services", svc_c.sample)
    net_detail = timed("network_detail", lambda: nd_c.sample(processes=procs))
    unit_desc = {s["name"]: (s.get("display_name") or s["name"]) for s in (svcs.get("services") or [])}
    port_map = timed("ports", lambda: ports_c.sample(service_map=svcs.get("by_pid"), unit_desc=unit_desc))
    sync_p = timed("sync", sync_c.sample)
    ceil = timed("ceilings", lambda: ceil_c.sample(processes=procs))
    ev = timed("events", lambda: events.EventCollector().sample(lookback_days=cfg.event_lookback_days,
                                                                max_per_source=cfg.event_max_per_source))
    changes.observe_services(svcs); changes.observe_volumes(volumes)
    changes.observe_ports(port_map); changes.observe_network(net_detail)
    changes.observe_events(ev)
    outage_p = timed("outage", lambda: out_c.sample(svcs, port_map, volumes, ev, net_detail, system,
                                                    changes=changes))
    diagnosis = timed("diagnose", lambda: lag.diagnose(
        snapshot, procs, pressures, cfg, volumes=volumes.get("volumes") or [], cgroups=cg,
        kernel=kn, changes=changes, ceilings=ceil, ports=port_map, memory_forecast=forecast))
    service_map = svcs.get("by_pid") or {}
    for entry in procs:
        hosted = service_map.get(str(entry["pid"]))
        if hosted:
            entry["services"] = hosted[:8]
            entry["service_count"] = len(hosted)
    ranked = sorted(procs, key=lambda p: -float(p.get("lag_score") or 0))
    snapshot.update({
        "process_table": {"processes": ranked, "totals": result["totals"], "by_state": result["by_state"],
                          "sample_ms": result["sample_ms"], "cores": result["cores"], "mode": result["mode"],
                          "degraded_reason": result["degraded_reason"], "io_note": result["io_note"],
                          "container_note": result.get("container_note"), "truncated": 0, "ts": time.time()},
        "diagnosis": diagnosis, "cgroups": cg, "kernel": kn, "volumes": volumes, "services": svcs,
        "network_detail": net_detail, "ports": port_map, "sync": sync_p, "ceilings": ceil,
        "changes": changes.snapshot(), "outage": outage_p, "events": ev,
    })

    # The Coroner's inputs: a synthetic death and the forensics on it.
    death = {"kind": "machine", "died_at": time.time() - 395, "prev_boot_id": f"boot-{int(time.time() - 90000)}",
             "boot_id": recorder.boot_id(), "agent_pid": os.getpid()}
    snapshot["_forensics"] = timed("forensics", lambda: forensics.investigate(death))
    snapshot["_timings_ms"] = timings
    # Actions: every verb must answer without raising, in the {ok, reason} shape.
    from culprit.collectors import units
    snapshot["_actions"] = {
        "terminate_pid4": processes.terminate(4),
        "priority_bad": processes.set_priority(os.getpid(), "realtime"),
        "throttle_self": processes.throttle(os.getpid(), "half"),
        "throttle_parent": processes.throttle(os.getppid(), "half"),
        "truncate": processes.truncate_deleted(os.getpid(), r"C:\x"),
        "unit_refuse": units.refuse("RpcSs", "restart", "system"),
        "unit_reset": units.refuse("Spooler", "reset-failed", "system"),
        "unit_act": units.act("Spooler", "restart", "system") if mode == "fake" else None,
        "detail": proc_c.detail(os.getpid(), frozenset({"threads"})),
    }
    return snapshot


def check_contract(snapshot: dict, contract, optional) -> tuple[list[str], list[str], int]:
    missing, empty, checked = [], [], 0
    for view, endpoints in contract.items():
        for endpoint, paths in endpoints.items():
            if not endpoint.startswith("node:"):
                continue
            section = endpoint[len("node:"):]
            payload = snapshot if not section else snapshot.get(section)
            for path in paths:
                checked += 1
                found, _ = _dig(payload, path)
                if found is False:
                    if path in optional or path in _HOST_ADDED:
                        empty.append(f"{view}: {endpoint} {path} (optional, absent)")
                    else:
                        missing.append(f"{view}: {endpoint} has no {path!r}")
                elif found is None:
                    empty.append(f"{view}: {endpoint} -> {path} (list was empty)")
    return missing, empty, checked


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("bare", "fake", "both"), default="both")
    parser.add_argument("--dump", action="store_true", help="print the snapshot as JSON")
    parser.add_argument("--unelevated", action="store_true",
                        help="fake mode: the Security log answers access denied")
    args = parser.parse_args()
    if args.mode == "both":
        # Each mode needs a fresh interpreter: the fakes must be in place before
        # culprit.windows is imported, and the bare run must not see them.
        code = 0
        for mode in ("bare", "fake"):
            argv = [sys.executable, __file__, "--mode", mode] + (["--dump"] if args.dump else [])
            code |= subprocess.call(argv, cwd=str(ROOT))
        return code

    sys.path.insert(0, str(ROOT))
    if args.mode == "fake":
        sys.path.insert(0, str(ROOT / "tools"))
        import fakewin
        fakewin.install(elevated=not args.unelevated)
        os.environ["CULPRIT_AGENT_TASK"] = "culprit-agent"
    print(f"\n{args.mode} mode: running every collector" + (" on canned Windows data" if args.mode == "fake" else " with no pywin32 (degraded)"))
    print("-" * 70)
    snapshot = run_collectors(args.mode)
    if args.dump:
        print(json.dumps(snapshot, indent=1, default=str)[:200000])

    for name, ms in snapshot["_timings_ms"].items():
        print(f"  {DIM}{name:<16}{ms:>8.1f} ms{RESET}")

    # Every section present, every unavailable one with a reason.
    problems: list[str] = []
    for key in _SNAPSHOT_KEYS:
        section = snapshot.get(key)
        if key == "psi":
            if section is not None:
                problems.append("psi must be None on Windows")
            continue
        if not isinstance(section, dict):
            problems.append(f"section {key} is {type(section).__name__}, not a dict")
            continue
        if section.get("available") is False and not section.get("reason"):
            problems.append(f"section {key} is unavailable without a reason")

    contract, optional = _load_contract()
    if contract is None:
        print(f"{YELLOW}no host checkout at {HOST_CONTRACT}; contract check skipped{RESET}")
        missing, empty, checked = [], [], 0
    else:
        missing, empty, checked = check_contract(snapshot, contract, optional)

    # Mode-specific expectations: what the fakes must have produced.
    if args.mode == "fake":
        table = snapshot["process_table"]
        names = {p["name"]: p for p in table["processes"]}
        expect = [
            ("process table has the fake rows", {"chrome", "notepad", "svchost"} <= set(names)),
            ("chrome's CPU is per-machine (240%/cores)", 0 < names["chrome"]["cpu"] < 240),
            ("notepad is not responding", names["notepad"]["hung"] is True
             and names["notepad"]["state"] == "not responding"),
            ("hung_apps finding fires", any(f["key"] == "hung_apps" for f in
                                            snapshot["diagnosis"]["findings"])),
            ("GPU total from the engine array", (snapshot["gpu"].get("total") or 0) > 0),
            ("chrome carries its GPU share", names["chrome"]["gpu"] > 0),
            ("disk latency in ms", snapshot["disk"]["total"]["latency_ms"] == 3.5),
            ("commit percent from PDH", 30 < snapshot["memory"]["commit_percent"] < 45),
            ("commit enforced", snapshot["memory"]["commit_enforced"] is True),
            ("pressure mode is derived", snapshot["diagnosis"]["pressure_mode"] == "derived"),
            ("services from the SCM", snapshot["services"]["available"] and
             any(s["name"] == "Spooler" for s in snapshot["services"]["services"])),
            ("Spooler is a problem", any(p["name"] == "Spooler" for p in snapshot["services"]["problems"])),
            ("outage names Spooler", any(i["key"].endswith(":Spooler") for i in snapshot["outage"]["items"])),
            ("outage offers a restart", any(a["verb"] == "restart" for i in snapshot["outage"]["items"]
                                            for a in i.get("actions") or [])),
            ("bugcheck decoded", any(e.get("bugcheck", {}).get("name") == "DRIVER_IRQL_NOT_LESS_OR_EQUAL"
                                     for e in snapshot["events"]["crashes"]["events"])),
            ("low-memory event names chrome", any("chrome.exe" in str(e.get("detail")) for e in
                                                  snapshot["events"]["crashes"]["events"]
                                                  if e.get("source_key") == "low_memory")),
            ("sessions paired from the Security log", snapshot["events"]["sessions"]["source"] == "security"
             and snapshot["events"]["sessions"]["timeline"]),
            ("current sessions from WTS", len(snapshot["events"]["sessions"]["current"]) == 2
             and any(s["remote"] for s in snapshot["events"]["sessions"]["current"])),
            ("RDP session flagged locked (LogonUI)", any(s["locked"] for s in snapshot["events"]["sessions"]["current"])),
            ("pending reboot from the registry", snapshot["events"]["pending_reboot"]["pending"] is True),
            ("OneDrive account listed", snapshot["sync"]["available"] and snapshot["sync"]["clients"]),
            ("KFM break reported", any("redirection is broken" in p["title"] for p in snapshot["sync"]["problems"])),
            ("OS name fixed to Windows 11", snapshot["system"]["os"]["product"].startswith("Windows 11")),
            ("platform stamped", snapshot["system"]["platform"] == "windows"),
            ("GDI ceiling with holder", any(l["kind"] == "gdi_objects" for l in snapshot["ceilings"]["limits"])),
            ("handle leak ceiling names svchost", any(l["kind"] == "handles" and l["holder"]["name"] == "svchost"
                                                      for l in snapshot["ceilings"]["limits"])),
            ("forensics: shutdown request with who", any(m["kind"] == "shutdown_request" and m.get("who")
                                                         for m in snapshot["_forensics"]["markers"])),
            ("forensics: panic marker carries the stop code", any(m["kind"] == "panic" and m.get("stop_code")
                                                                  for m in snapshot["_forensics"]["markers"])),
            ("forensics: memory exhaustion names the consumer",
             any(m["kind"] == "memory_exhaustion" and m.get("victim") == "chrome.exe"
                 for m in snapshot["_forensics"]["markers"])),
            ("unit action ran", (snapshot["_actions"]["unit_act"] or {}).get("ok") is True),
            ("throttle refuses the agent itself", snapshot["_actions"]["throttle_self"].get("ok") is False),
            ("throttle via job object", snapshot["_actions"]["throttle_parent"].get("ok") is True),
        ]
    else:
        expect = [
            ("process table degraded to psutil", snapshot["process_table"]["mode"] == "psutil"),
            ("degraded reason names pywin32", "win32pdh" in str(snapshot["process_table"]["degraded_reason"])),
            ("GPU unavailable with reason", snapshot["gpu"]["available"] is False and snapshot["gpu"]["reason"]),
            ("services unavailable with reason", snapshot["services"]["available"] is False),
            ("events readable flag false", snapshot["events"]["journal"]["readable"] is False),
            ("throttle refused by name", snapshot["_actions"]["throttle_self"].get("ok") is False),
        ]
    expect += [
        ("PID 4 refused", snapshot["_actions"]["terminate_pid4"]["ok"] is False),
        ("realtime refused", snapshot["_actions"]["priority_bad"]["ok"] is False),
        ("truncate says not capable", "Not capable" in snapshot["_actions"]["truncate"]["reason"]),
        ("RpcSs protected", "cannot run without" in str(snapshot["_actions"]["unit_refuse"])),
        ("reset-failed not capable", "Not capable" in str(snapshot["_actions"]["unit_reset"])),
        ("detail answers", isinstance(snapshot["_actions"]["detail"], dict)),
        ("every row has the Linux keys", all(
            k in p for p in snapshot["process_table"]["processes"]
            for k in ("run_delay_ms", "major_faults_sec", "stuck", "is_kthread", "container", "unit",
                      "hung", "state", "lag_score"))),
    ]
    for label, ok in expect:
        print(f"  {GREEN + 'ok  ' if ok else RED + 'FAIL'}{RESET} {label}")
        if not ok:
            problems.append(label)

    print("-" * 70)
    for line in empty:
        print(f"{DIM}skip{RESET} {line}")
    for line in missing:
        print(f"{RED}FAIL{RESET} {line}")
    for line in problems:
        print(f"{RED}FAIL{RESET} {line}")
    if missing or problems:
        print(f"\n{RED}{len(missing)} contract field(s) missing, {len(problems)} check(s) failed "
              f"({args.mode} mode).{RESET}\n")
        return 1
    print(f"\n{GREEN}{args.mode}: all {checked} contract field(s) present; {len(expect)} checks passed.{RESET}"
          f"{f' {len(empty)} unverifiable.' if empty else ''}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
