"""The sampling engine: four independent loops at four cadences.

Why four loops and not one:

    fast   (1s)    cpu, memory, gpu, disk rate, net rate       ~25ms (PDH)
    proc   (2s)    the process table + lag scoring             ~75-120ms
    slow   (20s)   services, volumes, adapters, OneDrive       ~400ms
    events (120s)  event log, minidumps, pending reboot        ~2s

Polling a 200-unit systemd table or a 30-day journal window at 1Hz would burn
real CPU to re-answer questions whose answers change on a scale of minutes. A
monitoring tool that is itself a top-five process has failed at its job.

Every collector is blocking (psutil, PDH, WMI, the event log), so each loop
runs its work in a **single-threaded** executor of its own. Single-threaded
matters twice here: COM apartment state and PDH query handles stay on one
consistent thread per tier, and one slow tier can never starve another.

Loops are self-correcting rather than `sleep(interval)`: the next wake-up is
computed from the deadline, so a 400ms collection inside a 1s tick still yields
a 1s period instead of drifting out to 1.4s.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from . import config as config_module
from .collectors import disks as disks_mod
from .collectors import events as events_mod
from .collectors import gpu as gpu_mod
from .collectors import network as net_mod
from .collectors import ports as ports_mod
from .collectors import processes as proc_mod
from .collectors import services as svc_mod
from .collectors import ceilings as ceilings_mod
from .collectors import cgroups as cgroups_mod
from .collectors import kernel as kernel_mod
from .collectors import memtrend as memtrend_mod
from .collectors import outage as outage_mod
from .collectors.changes import ChangeLog
from .collectors.recorder import FlightRecorder
from .collectors import sync as sync_mod
from .collectors import sysinfo as sysinfo_mod
from .collectors.cpu_mem import CpuMemoryCollector
from .collectors.lag import LagAnalyzer
from .db import History, aggregate_window
from .state import Broker, Store

log = logging.getLogger("culprit.sampler")

# Metrics mirrored into the live ring buffer for the sparklines. Kept small on
# purpose -- the ring holds 900 of these by default.
LIVE_KEYS: tuple[str, ...] = (
    "cpu.total", "cpu.queue_per_core", "memory.percent", "memory.commit_percent",
    "memory.hard_faults_sec", "gpu.total", "disk.total.busy_percent",
    "disk.total.latency_ms", "disk.total.queue_length",
    "disk.total.read_bytes_sec", "disk.total.write_bytes_sec",
    "network.total.recv_bytes_sec", "network.total.sent_bytes_sec",
)

# Progressive warm-up messages. Startup genuinely takes a few seconds -- rate
# counters need two samples before they mean anything, and the first journal
# query against a cold page cache measured ~13s on a 1.3GB journal. The UI
# shows these instead of a bare spinner.
WARMUP_STAGES: tuple[str, ...] = (
    "Reading machine identity",
    "Opening performance counters",
    "Reading the process table",
    "Establishing rate baselines",
    "Querying services and volumes",
    "Reading the Windows event log",
    "Almost done",
)


class Sampler:
    def __init__(self, store: Store, broker: Broker, history: History,
                 recorder: FlightRecorder | None = None) -> None:
        self.store = store
        self.broker = broker
        self.history = history
        self.lag = LagAnalyzer()
        # The flight recorder (the Coroner's black box): fed by the fast and
        # proc tiers, flushed to disk every few seconds, marked clean on a
        # handled stop. The agent passes one; the host has nothing to record.
        self.recorder = recorder

        self._executors = {
            name: ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"tpc-{name}")
            for name in ("fast", "proc", "slow", "events")
        }
        self._tasks: list[asyncio.Task] = []
        self._stopping = asyncio.Event()

        # Collectors are created lazily on their own executor thread so that
        # stateful backends (NVML handles, rate baselines) live where they run.
        self.cpu_mem: CpuMemoryCollector | None = None
        self.gpu: gpu_mod.GpuCollector | None = None
        self.disk: disks_mod.DiskCollector | None = None
        self.net: net_mod.NetworkRateCollector | None = None
        self.proc: proc_mod.ProcessCollector | None = None
        self.volumes: disks_mod.VolumeCollector | None = None
        self.services: svc_mod.ServiceCollector | None = None
        self.net_detail: net_mod.NetworkDetailCollector | None = None
        self.ports: ports_mod.PortsCollector | None = None
        self.sync: sync_mod.SyncCollector | None = None
        self.events: events_mod.EventCollector | None = None
        # Per-unit pressure/limits and the kernel's own state ride on the
        # proc tick (cheap, and the Lag Doctor reads them). The change log is
        # fed by every tier and read by the doctor.
        self.cgroups: cgroups_mod.CgroupCollector | None = None
        self.kernel: kernel_mod.KernelCollector | None = None
        self.ceilings: ceilings_mod.CeilingCollector | None = None
        self.outage: outage_mod.OutageCollector | None = None
        self.changes: ChangeLog | None = None
        # The memory-fill forecast: MemAvailable and every process's RSS over
        # the last hour, fitted on the proc tick for the Lag Doctor.
        self.memtrend: memtrend_mod.MemoryTrend | None = None

        # Rollup accumulation.
        self._bucket_ts: int | None = None
        self._bucket: list[dict] = []
        self._bucket_worst = "ok"

        self._tick_counts = {"fast": 0, "proc": 0, "slow": 0, "events": 0}

    # ------------------------------------------------------------------ public
    async def start(self) -> None:
        cfg = config_module.get()
        loop = asyncio.get_running_loop()

        self.store.warmup_stage = WARMUP_STAGES[0]
        sysinfo = await loop.run_in_executor(
            self._executors["slow"], sysinfo_mod.collect
        )
        self.store.put("system", sysinfo)
        self.changes = ChangeLog(boot_time=(sysinfo or {}).get("boot_time"))

        # Build the fast-tier collectors before announcing readiness; the GPU
        # wildcard enumeration is the slow part and belongs in warm-up.
        self.store.warmup_stage = WARMUP_STAGES[1]
        await loop.run_in_executor(self._executors["fast"], self._init_fast, sysinfo)
        self.store.warmup_stage = WARMUP_STAGES[2]
        await loop.run_in_executor(self._executors["proc"], self._init_proc, sysinfo)

        self._tasks = [
            asyncio.create_task(self._loop("fast", self._tick_fast), name="tpc-fast"),
            asyncio.create_task(self._loop("proc", self._tick_proc), name="tpc-proc"),
            asyncio.create_task(self._loop("slow", self._tick_slow), name="tpc-slow"),
            asyncio.create_task(self._loop("events", self._tick_events),
                                name="tpc-events"),
        ]
        log.info("sampler started (fast=%.2fs proc=%.2fs slow=%.1fs events=%.0fs)",
                 cfg.interval_fast, cfg.interval_proc, cfg.interval_slow,
                 cfg.interval_events)

    async def stop(self) -> None:
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: B014
                pass
        self._tasks.clear()
        # Flush whatever is in the current bucket rather than losing it.
        try:
            self._flush_bucket(force=True)
        except Exception as exc:
            log.debug("final flush failed: %s", exc)
        if self.recorder is not None:
            # A handled stop is not a death: the next start must not read
            # this recording as one.
            try:
                self.recorder.mark_clean_stop()
            except Exception as exc:  # noqa: BLE001 -- shutdown must finish regardless
                log.debug("recorder clean-stop mark failed: %s", exc)
        for name, executor in self._executors.items():
            executor.submit(self._close_collectors, name)
            executor.shutdown(wait=True)
        self.history.close()
        log.info("sampler stopped")

    # ---------------------------------------------------------------- lifecycle
    def _init_fast(self, sysinfo: dict) -> None:
        self.cpu_mem = CpuMemoryCollector()
        self.gpu = gpu_mod.GpuCollector(sysinfo.get("gpus") or [])
        self.disk = disks_mod.DiskCollector()
        self.net = net_mod.NetworkRateCollector()

    def _init_proc(self, sysinfo: dict) -> None:
        cores = (sysinfo.get("cpu") or {}).get("logical_cores")
        self.proc = proc_mod.ProcessCollector(logical_cores=cores)

    def _close_collectors(self, tier: str) -> None:
        """Release backend handles (NVML) on the thread that opened them."""
        collectors = {
            "fast": (self.cpu_mem, self.gpu, self.disk),
            "proc": (self.proc,),
        }.get(tier, ())
        for collector in collectors:
            if collector is None:
                continue
            try:
                collector.close()  # type: ignore[union-attr]
            except Exception:
                pass

    # --------------------------------------------------------------- loop core
    async def _loop(self, name: str, tick) -> None:  # type: ignore[no-untyped-def]
        loop = asyncio.get_running_loop()
        executor = self._executors[name]
        # Stagger the tiers so their first (most expensive) runs do not collide.
        await asyncio.sleep({"fast": 0.0, "proc": 0.15, "slow": 0.4,
                             "events": 1.2}[name])
        deadline = loop.time()
        while not self._stopping.is_set():
            interval = self._interval(name)
            started = time.perf_counter()
            try:
                await loop.run_in_executor(executor, tick)
                self.store.set_error(name, None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # One failing tier must not take the dashboard down. Record it,
                # surface it in the UI, keep ticking.
                log.exception("%s tick failed", name)
                self.store.set_error(name, f"{type(exc).__name__}: {exc}")
            self.store.set_timing(name, (time.perf_counter() - started) * 1000)
            self._tick_counts[name] += 1

            # Deadline-based scheduling: a slow tick shortens the next sleep
            # instead of pushing the whole cadence later.
            deadline += interval
            now = loop.time()
            if deadline < now:
                # Fell far enough behind that catching up is pointless; resync.
                deadline = now + interval
            try:
                await asyncio.wait_for(self._stopping.wait(),
                                       timeout=max(0.01, deadline - now))
            except asyncio.TimeoutError:
                pass

    def _interval(self, name: str) -> float:
        cfg = config_module.get()
        interval = {
            "fast": cfg.interval_fast, "proc": cfg.interval_proc,
            "slow": cfg.interval_slow, "events": cfg.interval_events,
        }[name]
        if name == "proc" and self.proc is not None and \
                getattr(self.proc, "mode", "pdh") == "psutil":
            # The psutil fallback costs seconds per scan rather than ~100ms, so
            # a 2s cadence would leave the executor permanently saturated.
            interval = max(interval, 15.0)
        return interval

    # -------------------------------------------------------------- fast tick
    def _tick_fast(self) -> None:
        cfg = config_module.get()
        assert self.cpu_mem and self.gpu and self.disk and self.net

        sample = self.cpu_mem.sample()
        sample["gpu"] = self.gpu.sample()
        sample["disk"] = self.disk.sample()
        sample["network"] = self.net.sample()
        timestamp = time.time()
        sample["ts"] = timestamp

        pressures = self.lag.pressures(sample, cfg)
        sample["pressures"] = pressures

        if self.store.ring.window != cfg.live_window_seconds:
            self.store.ring.set_window(cfg.live_window_seconds)

        self.store.merge({
            "cpu": sample["cpu"], "memory": sample["memory"],
            "psi": sample.get("psi"),
            "gpu": sample["gpu"], "disk": sample["disk"],
            "network": sample["network"], "pressures": pressures,
            "ts": timestamp,
        })
        self.store.push_live(timestamp, sample)
        self._accumulate(timestamp, sample)
        if self.recorder is not None:
            self.recorder.observe_fast(sample)
            self.recorder.maybe_flush(timestamp)

        self.broker.publish("fast", {
            "ts": timestamp,
            "cpu": sample["cpu"], "memory": sample["memory"],
            "psi": sample.get("psi"),
            "gpu": sample["gpu"], "disk": sample["disk"],
            "network": sample["network"], "pressures": pressures,
        })

    # -------------------------------------------------------------- proc tick
    def _tick_proc(self) -> None:
        cfg = config_module.get()
        assert self.proc
        gpu_per_pid = self.gpu.per_pid if self.gpu else {}
        result = self.proc.sample(gpu_per_pid=gpu_per_pid, limit=cfg.process_count)

        snapshot = self.store.snapshot()
        pressures = snapshot.get("pressures") or self.lag.pressures(snapshot, cfg)
        processes = result["processes"]

        self.lag.score_processes(processes, snapshot, pressures, cfg)

        if self.cgroups is None:
            self.cgroups = cgroups_mod.CgroupCollector()
        if self.kernel is None:
            self.kernel = kernel_mod.KernelCollector()
        cgroups = self.cgroups.sample(containers=self.proc.containers)
        kernel = self.kernel.sample()
        if self.changes is not None:
            self.changes.observe_processes(processes)
            self.changes.observe_cgroups(cgroups)

        if self.memtrend is None:
            self.memtrend = memtrend_mod.MemoryTrend()
        now = time.time()
        self.memtrend.observe(now, snapshot.get("memory"), processes)
        memory_forecast = self.memtrend.forecast(
            now, total_ram=(snapshot.get("memory") or {}).get("total"))

        volumes = (self.store.get("volumes") or {}).get("volumes") or []
        diagnosis = self.lag.diagnose(snapshot, processes, pressures, cfg,
                                      volumes=volumes, cgroups=cgroups,
                                      kernel=kernel, changes=self.changes,
                                      ceilings=self.store.get("ceilings"),
                                      ports=self.store.get("ports"),
                                      memory_forecast=memory_forecast)

        # Annotate unit main processes with the units they belong to.
        service_map = (self.store.get("services") or {}).get("by_pid") or {}
        for entry in processes:
            hosted = service_map.get(str(entry["pid"]))
            if hosted:
                entry["services"] = hosted[:8]
                entry["service_count"] = len(hosted)

        ranked = sorted(processes, key=lambda p: -float(p.get("lag_score") or 0))
        trimmed = ranked[:cfg.process_count]
        if self.recorder is not None:
            self.recorder.observe_proc(ranked, diagnosis)

        self._bucket_worst = _worse(self._bucket_worst, str(diagnosis["severity"]))
        self._bucket_top = [
            {"pid": p["pid"], "name": p["name"], "cpu": p.get("cpu"),
             "working_set": p.get("working_set"),
             "io_bytes_sec": p.get("io_bytes_sec"), "gpu": p.get("gpu"),
             "lag_score": p.get("lag_score")}
            for p in ranked[:cfg.history_top_processes]
        ]

        payload = {
            "processes": trimmed,
            "totals": result["totals"],
            "by_state": result["by_state"],
            "sample_ms": result["sample_ms"],
            "cores": result["cores"],
            "mode": result["mode"],
            "degraded_reason": result["degraded_reason"],
            "io_note": result["io_note"],
            "container_note": result.get("container_note"),
            "truncated": len(ranked) - len(trimmed),
            "ts": time.time(),
        }
        self.store.put("process_table", payload)
        self.store.put("diagnosis", diagnosis)
        self.store.put("cgroups", cgroups)
        self.store.put("kernel", kernel)
        self.broker.publish("proc", payload)
        self.broker.publish("diagnosis", diagnosis)
        self.broker.publish("cgroups", cgroups)
        self.broker.publish("kernel", kernel)

    # -------------------------------------------------------------- slow tick
    def _tick_slow(self) -> None:
        if self.volumes is None:
            self.volumes = disks_mod.VolumeCollector()
        if self.services is None:
            self.services = svc_mod.ServiceCollector()
        if self.net_detail is None:
            self.net_detail = net_mod.NetworkDetailCollector()
        if self.ports is None:
            self.ports = ports_mod.PortsCollector()
        if self.sync is None:
            self.sync = sync_mod.SyncCollector()
        if self.ceilings is None:
            self.ceilings = ceilings_mod.CeilingCollector()
        if self.outage is None:
            self.outage = outage_mod.OutageCollector()

        # The volume collector names the processes writing to each mount
        # (open files under it) from the latest process table.
        table = (self.store.get("process_table") or {}).get("processes") or []
        volumes = self.volumes.sample(processes=table)
        services = self.services.sample()
        net_detail = self.net_detail.sample(processes=table)
        # The port map names the systemd unit behind each listener from the
        # process's own cgroup; the services list turns that unit name into its
        # human description (the blue tag). Both are best-effort and degrade.
        _svc_list = (services or {}).get("services") or []
        _unit_desc = {s["name"]: (s.get("display_name") or s["name"])
                      for s in _svc_list if s.get("name")}
        ports = self.ports.sample(service_map=(services or {}).get("by_pid"),
                                  unit_desc=_unit_desc)
        sync = self.sync.sample()
        system = sysinfo_mod.collect()  # cheap; refreshes uptime
        # Ceilings name their holders the way the process table does.
        ceilings = self.ceilings.sample(processes=table)

        payload = {
            "volumes": volumes, "services": services,
            "network_detail": net_detail, "ports": ports, "sync": sync,
            "system": system, "ceilings": ceilings, "ts": time.time(),
        }
        if self.changes is not None:
            # Diff against the previous slow tick; the log itself is what
            # the Lag Doctor asks "what changed before this began?".
            self.changes.observe_services(services)
            self.changes.observe_volumes(volumes)
            self.changes.observe_ports(ports)
            self.changes.observe_network(net_detail)
            payload["changes"] = self.changes.snapshot()
        # The Outage Doctor reads what this tick just produced (and the last
        # events tick), so it runs after the rest and never re-collects.
        payload["outage"] = self.outage.sample(
            services, ports, volumes, self.store.get("events"), net_detail,
            system, changes=self.changes)
        self.store.merge(payload)
        self.broker.publish("slow", payload)

    # ------------------------------------------------------------ events tick
    def _tick_events(self) -> None:
        cfg = config_module.get()
        if self.events is None:
            self.events = events_mod.EventCollector()
        payload = self.events.sample(
            lookback_days=cfg.event_lookback_days,
            max_per_source=cfg.event_max_per_source,
        )
        self.store.put("events", payload)
        if self.changes is not None:
            self.changes.observe_events(payload)

        if self.history.ready:
            everything = (
                list(payload["crashes"]["events"])
                + list(payload["updates"]["events"])
                + list(payload["policy"]["events"])
            )
            inserted = self.history.write_events(everything)
            if inserted:
                log.debug("stored %d new event(s)", inserted)
            self.history.prune(cfg.retention_days)

        self.broker.publish("events", payload)

    # ----------------------------------------------------------------- rollup
    def _accumulate(self, timestamp: float, sample: dict) -> None:
        cfg = config_module.get()
        if not (cfg.persist_history and self.history.ready):
            return
        width = max(1, int(cfg.rollup_seconds))
        bucket = int(timestamp // width) * width
        if self._bucket_ts is None:
            self._bucket_ts = bucket
        elif bucket != self._bucket_ts:
            self._flush_bucket()
            self._bucket_ts = bucket
        self._bucket.append(sample)

    def _flush_bucket(self, force: bool = False) -> None:
        if self._bucket_ts is None or not self._bucket:
            if force:
                self._bucket, self._bucket_ts = [], None
            return
        aggregate = aggregate_window(self._bucket, self._bucket_worst)
        top = getattr(self, "_bucket_top", [])
        findings = (self.store.get("diagnosis") or {}).get("findings") or []
        # Only persist findings that were actually actionable.
        keep = [f for f in findings if f.get("severity") in ("warn", "critical")]
        self.history.write_rollup(self._bucket_ts, aggregate, top, keep)
        self._bucket = []
        self._bucket_worst = "ok"

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, object]:
        return {
            "ticks": dict(self._tick_counts),
            "timings_ms": dict(self.store.timings),
            "errors": dict(self.store.errors),
            "subscribers": self.broker.count,
            "dropped_frames": self.broker.dropped,
            "ring_samples": len(self.store.ring),
            "intervals": {
                name: self._interval(name)
                for name in ("fast", "proc", "slow", "events")
            },
            "history": self.history.stats(),
            "recorder": self.recorder.status() if self.recorder is not None else None,
        }


_SEVERITY_RANK = {"ok": 0, "info": 1, "warn": 2, "critical": 3}


def _worse(current: str, candidate: str) -> str:
    return candidate if _SEVERITY_RANK.get(candidate, 0) > \
        _SEVERITY_RANK.get(current, 0) else current


async def warm_up(store: Store, sampler: Sampler) -> None:
    """Advance the warm-up messages until real data has landed.

    The dashboard's first paint is skeletons plus a progressive status line; this
    drives that line and flips `store.warm` once both the fast and process tiers
    have produced a sample.
    """
    index = 3  # start after the stages start() already walked through
    while not store.warm:
        if sampler._tick_counts["fast"] >= 2 and sampler._tick_counts["proc"] >= 1:
            store.warmup_stage = "Ready"
            store.warm = True
            break
        store.warmup_stage = WARMUP_STAGES[min(index, len(WARMUP_STAGES) - 1)]
        index += 1
        await asyncio.sleep(1.0)
