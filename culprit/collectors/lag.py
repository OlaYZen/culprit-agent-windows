"""Lag Doctor: turn raw counters into "here is what is making this machine slow".

The design principle is that **resource usage is not the same as a problem**. A
process holding 6 GB on a machine with 40 GB free is not hurting anyone, and
ranking processes by raw memory would put it at the top every time. What matters
is a process's contribution to a resource that is *currently under pressure*.

On Windows, pressure had to be approximated from utilisation, queue depth,
fault rates and latency. On Linux the kernel computes the real thing:
**PSI** (/proc/pressure/*) is the measured fraction of wall time tasks spent
stalled on CPU, memory or IO. Where PSI exists it drives the pressure values;
the derived model stays as the labelled fallback (and as sub-signals, because
they explain *which* underlying number is moving). One deliberate exception:
memory pressure also honours the low-available-RAM watermark even when PSI is
quiet, because MemAvailable exhaustion is the leading indicator -- PSI only
fires once reclaim has already started hurting.

Scoring stays two-stage:

1. A 0..1 pressure per resource (CPU, memory, disk, GPU).
2. Each process scored by its share of each resource, gated by that resource's
   pressure, with a 0.3 floor so the ranking stays meaningful on an idle box.

On Windows the kernel keeps no PSI, so the derived model *is* the model
(`pressure_mode: derived`), and the one signal Windows has that Linux does
not comes back: a window that has stopped pumping messages -- Task Manager's
"Not responding" -- is the most direct "you are being made to wait" evidence
there is, catching a process frozen at 0% CPU that no counter would ever
flag. It is scored ungated (`weight_hung`), the way the Linux agent scores
D-state, and raised as its own finding. The Linux-only inputs (`stuck`,
`run_delay_ms`, cgroups, the kernel section) are simply absent here and the
code paths that read them stay dormant; they are kept so the two agents'
doctors read the same.
"""

from __future__ import annotations

import time

from ..config import Config
from ..util import Sustain, clamp, safe_div

# Severity ladder, worst last. Used for ordering and for the overall verdict.
SEVERITY_ORDER = ("ok", "info", "warn", "critical")

# Below this, a resource's pressure gate stops shrinking. Keeps the "top
# consumers" ranking sane when the machine is idle.
_PRESSURE_FLOOR = 0.30

# Reference points for normalising process-level rates into a 0..1 share.
_DISK_REFERENCE_FLOOR = 20 * 1024 * 1024   # 20 MB/s -- a busy-ish disk
_FAULT_REFERENCE_FLOOR = 5_000.0           # page faults/sec
# run_delay is ms-waiting-per-second-of-wall-time; 250ms/s means the process
# spends a quarter of its life runnable but starved of a CPU.
_RUN_DELAY_REFERENCE = 250.0


# The memory forecast fires within this many hours of exhaustion. Shorter than
# the disk forecast's 24 h: memory moves faster, and an hour-long fit
# extrapolated a day ahead would be a guess dressed as a number.
_MEMORY_FORECAST_HORIZON_H = 4.0


class LagAnalyzer:
    def __init__(self) -> None:
        self._sustain = Sustain()
        self._prev_oom: int | None = None
        self._last_candidates: list[dict[str, object]] = []

    # ------------------------------------------------------------- pressure
    def pressures(self, snapshot: dict, cfg: Config) -> dict[str, float]:
        """Per-resource pressure in 0..1. 1.0 means "this is the bottleneck"."""
        cpu = snapshot.get("cpu") or {}
        memory = snapshot.get("memory") or {}
        disk = (snapshot.get("disk") or {}).get("total") or {}
        gpu = snapshot.get("gpu") or {}
        psi = snapshot.get("psi") or {}

        # --- derived sub-signals (always computed: they explain the number,
        # and they are the whole model when PSI is absent) ------------------
        cpu_util = _ratio(cpu.get("total"), cfg.cpu_high)
        cpu_queue = _ratio(cpu.get("queue_per_core"), cfg.cpu_queue_per_core)

        available = memory.get("available_mb")
        mem_low = (
            0.0 if available is None or cfg.mem_available_low_mb <= 0
            else clamp(1.0 - safe_div(float(available), cfg.mem_available_low_mb),
                       0.0, 1.0)
        )
        # Only meaningful under strict overcommit; the heuristic default lets
        # Committed_AS blow past CommitLimit on perfectly healthy machines.
        commit = (_ratio(memory.get("commit_percent"), cfg.mem_commit_high)
                  if memory.get("commit_enforced") else 0.0)
        thrash = _ratio(memory.get("hard_faults_sec"), cfg.hard_faults_high)

        disk_latency = _ratio(disk.get("latency_ms"), cfg.disk_latency_high_ms)
        disk_queue = _ratio(disk.get("queue_length"), cfg.disk_queue_high)
        disk_busy = _ratio(disk.get("busy_percent"), cfg.disk_busy_high)

        # --- PSI, scaled against configurable "this much stall is a real
        # problem" thresholds ----------------------------------------------
        psi_cpu = _psi_avg10(psi, "cpu", "some")
        psi_mem_some = _psi_avg10(psi, "memory", "some")
        psi_mem_full = _psi_avg10(psi, "memory", "full")
        psi_io_some = _psi_avg10(psi, "io", "some")
        psi_io_full = _psi_avg10(psi, "io", "full")
        psi_mode = psi_cpu is not None

        if psi_mode:
            cpu_pressure = _ratio(psi_cpu, cfg.psi_cpu_high)
            # `full` stalls (everyone blocked) are weighted double: they are
            # the whole-machine freeze people actually report.
            mem_pressure = max(
                _ratio(psi_mem_some, cfg.psi_memory_high),
                _ratio(psi_mem_full, cfg.psi_memory_high / 2),
                mem_low,  # leading indicator; see module docstring
            )
            disk_pressure = max(
                _ratio(psi_io_some, cfg.psi_io_high),
                _ratio(psi_io_full, cfg.psi_io_high / 2),
            )
        else:
            cpu_pressure = max(cpu_util, cpu_queue)
            mem_pressure = max(mem_low, commit, thrash)
            # Latency is the honest disk signal; busy% is the weakest and is
            # discounted (worse still on multi-queue NVMe).
            disk_pressure = max(disk_latency, disk_queue, disk_busy * 0.7)

        gpu_pressure = _ratio(gpu.get("total"), cfg.gpu_high)

        return {
            "cpu": round(cpu_pressure, 3),
            "memory": round(mem_pressure, 3),
            "disk": round(disk_pressure, 3),
            "gpu": round(gpu_pressure, 3),
            "mode": "psi" if psi_mode else "derived",
            # Components, so the UI can explain which sub-signal fired.
            "detail": {
                "psi_cpu": _round3(_ratio(psi_cpu, cfg.psi_cpu_high)),
                "psi_memory": _round3(max(
                    _ratio(psi_mem_some, cfg.psi_memory_high),
                    _ratio(psi_mem_full, cfg.psi_memory_high / 2))),
                "psi_io": _round3(max(
                    _ratio(psi_io_some, cfg.psi_io_high),
                    _ratio(psi_io_full, cfg.psi_io_high / 2))),
                "cpu_utilisation": round(cpu_util, 3),
                "cpu_queue": round(cpu_queue, 3),
                "memory_available": round(mem_low, 3),
                "memory_commit": round(commit, 3),
                "memory_thrash": round(thrash, 3),
                "disk_latency": round(disk_latency, 3),
                "disk_queue": round(disk_queue, 3),
                "disk_busy": round(disk_busy, 3),
            },
        }

    # -------------------------------------------------------------- scoring
    def score_processes(self, processes: list[dict], snapshot: dict,
                        pressures: dict[str, float], cfg: Config) -> None:
        """Attach `lag_score`, `lag_breakdown` and `lag_reasons` in place."""
        memory = snapshot.get("memory") or {}
        disk_total = (snapshot.get("disk") or {}).get("total") or {}
        system_faults = (memory.get("page_faults_sec") or 0.0)

        total_ram = float(memory.get("total") or 0) or 1.0
        disk_reference = max(
            float((disk_total.get("read_bytes_sec") or 0)
                  + (disk_total.get("write_bytes_sec") or 0)),
            _DISK_REFERENCE_FLOOR,
        )
        fault_reference = max(float(system_faults), _FAULT_REFERENCE_FLOOR)

        gate = {
            key: max(_PRESSURE_FLOOR, float(pressures.get(key, 0.0)))
            for key in ("cpu", "memory", "disk", "gpu")
        }
        # Anchor: a process consuming 100% of the CPU while the CPU is the
        # bottleneck scores 100. Anything piling more on top clamps there.
        anchor = cfg.weight_cpu or 1.0

        for proc in processes:
            if proc.get("is_kthread"):
                # Kernel threads do real work but attributing "lag" to e.g.
                # kswapd inverts cause and effect -- kswapd being busy is a
                # *symptom* of memory pressure caused by someone else.
                proc["lag_score"] = 0.0
                proc["lag_breakdown"] = {}
                # Say what the thread *is* ("writeback for device 252:0")
                # rather than the bare fact that it is a kernel thread.
                explained = proc.get("kernel") or {}
                proc["lag_reasons"] = (
                    [f"kernel: {explained['role']}"] if explained.get("role")
                    else ["kernel thread"] if float(proc.get("cpu") or 0) > 0.5
                    else [])
                continue

            # Blend instantaneous with the rolling mean: sustained load should
            # outrank a one-tick spike, but a real spike should still surface.
            cpu_now = float(proc.get("cpu") or 0.0)
            cpu_avg = float(proc.get("cpu_avg") or 0.0)
            cpu_share = clamp((0.6 * cpu_now + 0.4 * cpu_avg) / 100.0, 0.0, 1.0)
            # Scheduler run delay: direct evidence this process wants CPU it
            # is not getting. Folded into the CPU term because it is the same
            # resource seen from the victim's side.
            delay_share = clamp(float(proc.get("run_delay_ms") or 0.0)
                                / _RUN_DELAY_REFERENCE, 0.0, 1.0)
            cpu_term_share = max(cpu_share, delay_share * 0.8)

            mem_share = clamp(float(proc.get("working_set") or 0) / total_ram, 0.0, 1.0)
            io_share = clamp(float(proc.get("io_bytes_sec") or 0) / disk_reference,
                             0.0, 1.0)
            gpu_share = clamp(float(proc.get("gpu") or 0.0) / 100.0, 0.0, 1.0)
            fault_share = clamp(float(proc.get("page_faults_sec") or 0.0)
                                / fault_reference, 0.0, 1.0)

            terms = {
                "cpu": cfg.weight_cpu * cpu_term_share * gate["cpu"],
                "memory": cfg.weight_memory * mem_share * gate["memory"],
                "disk": cfg.weight_disk * io_share * gate["disk"],
                "gpu": cfg.weight_gpu * gpu_share * gate["gpu"],
                # Faults ride on memory pressure -- soft faults alone are normal.
                "faults": cfg.weight_faults * fault_share * gate["memory"],
                # Ungated: a process stuck in uninterruptible sleep is being
                # made to wait no matter what the aggregate counters say.
                "stuck": cfg.weight_stuck if proc.get("stuck") else 0.0,
                # Ungated too: a window that stopped answering is the wait
                # itself, whatever the counters show.
                "hung": getattr(cfg, "weight_hung", 2.0) if proc.get("hung") else 0.0,
            }

            raw = sum(terms.values())
            proc["lag_score"] = round(clamp(100.0 * raw / anchor, 0.0, 100.0), 1)
            proc["lag_breakdown"] = {
                key: round(clamp(100.0 * value / anchor, 0.0, 100.0), 1)
                for key, value in terms.items() if value > 0.0005
            }
            proc["lag_reasons"] = _reasons(proc, mem_share)

    # ------------------------------------------------------------- verdicts
    def diagnose(self, snapshot: dict, processes: list[dict],
                 pressures: dict[str, float], cfg: Config,
                 volumes: list[dict] | None = None,
                 cgroups: dict | None = None, kernel: dict | None = None,
                 changes: object = None,
                 ceilings: dict | None = None,
                 ports: dict | None = None,
                 memory_forecast: dict | None = None) -> dict[str, object]:
        """Build the sustained-pressure findings and attribute them to processes.

        `cgroups` (per-unit pressure and limits), `kernel` (mdstat, per-core
        interrupts), `changes` (a ChangeLog), `ceilings` and `ports` (the port
        map with its accept queues) and `memory_forecast` (memtrend's fit of
        MemAvailable and per-process RSS) are optional: without them the
        machine-level findings are exactly what they were.
        """
        cpu = snapshot.get("cpu") or {}
        memory = snapshot.get("memory") or {}
        disk_total = (snapshot.get("disk") or {}).get("total") or {}
        gpu = snapshot.get("gpu") or {}
        psi = snapshot.get("psi") or {}
        now = time.time()

        candidates: list[dict[str, object]] = []
        self._last_candidates = candidates

        def consider(key: str, active: bool, severity: str, title: str,
                     detail: str, resource: str, evidence: dict[str, object],
                     blame: str | None = None,
                     unit: dict[str, object] | None = None) -> None:
            streak = self._sustain.feed(key, active, now)
            if active and streak >= cfg.sustain_ticks:
                finding: dict[str, object] = {
                    "key": key, "severity": severity, "title": title,
                    "detail": detail, "resource": resource,
                    "evidence": evidence, "sustained_ticks": streak,
                    # When the condition began (first sample of the streak),
                    # so the UI can say "since 14:02" and the change log can
                    # be asked what happened just before.
                    "since": self._sustain.since(key),
                }
                if unit:
                    # The finding is about one unit / container; culprits
                    # are ranked among *its* processes only.
                    finding["unit"] = unit
                if blame:
                    # "Nobody on this machine is at fault": the cause is
                    # outside the process table (hypervisor, cooling, the
                    # swap device, a file server). No culprits are listed,
                    # because ranking processes under it would invent blame.
                    finding["external"] = True
                    finding["blame"] = blame
                candidates.append(finding)

        # --- PSI: the kernel's own stall measurements ----------------------
        psi_cpu = _psi_avg10(psi, "cpu", "some")
        if psi_cpu is not None:
            consider(
                "psi_cpu", psi_cpu >= cfg.psi_cpu_high,
                "critical" if psi_cpu >= cfg.psi_cpu_high * 1.8 else "warn",
                "Tasks stalled waiting for CPU",
                f"The kernel measured runnable tasks waiting for a CPU "
                f"{psi_cpu:.0f}% of the time (10s average). This is stall "
                "time, not utilisation -- it is the delay people feel.",
                "cpu", {"psi_some_avg10": round(psi_cpu, 1)},
            )
        psi_mem_full = _psi_avg10(psi, "memory", "full")
        if psi_mem_full is not None:
            active = psi_mem_full >= cfg.psi_memory_high / 2
            consider(
                "psi_memory", active,
                "critical" if psi_mem_full >= cfg.psi_memory_high else "warn",
                "Whole system stalled on memory",
                f"Every non-idle task was blocked on memory reclaim "
                f"{psi_mem_full:.1f}% of the time. This is the freeze that "
                "precedes OOM kills.",
                "memory", {"psi_full_avg10": round(psi_mem_full, 2)},
            )
        psi_io_full = _psi_avg10(psi, "io", "full")
        if psi_io_full is not None:
            consider(
                "psi_io", psi_io_full >= cfg.psi_io_high / 2,
                "critical" if psi_io_full >= cfg.psi_io_high else "warn",
                "System stalled on storage",
                f"All non-idle tasks were blocked on IO {psi_io_full:.1f}% of "
                "the time (10s average). Storage is holding everything up.",
                "disk", {"psi_full_avg10": round(psi_io_full, 2)},
            )

        # --- CPU -----------------------------------------------------------
        cpu_total = float(cpu.get("total") or 0.0)
        consider(
            "cpu_saturated", cpu_total >= cfg.cpu_high,
            "critical" if cpu_total >= 95 else "warn",
            "CPU saturated",
            f"CPU has held {cpu_total:.0f}% (threshold {cfg.cpu_high:.0f}%). "
            "Everything runnable is competing for cores.",
            "cpu", {"cpu_percent": round(cpu_total, 1)},
        )
        queue_per_core = float(cpu.get("queue_per_core") or 0.0)
        consider(
            "cpu_queue", queue_per_core >= cfg.cpu_queue_per_core,
            "critical" if queue_per_core >= cfg.cpu_queue_per_core * 3 else "warn",
            "Threads waiting for CPU",
            f"{queue_per_core:.1f} runnable threads per core are queued. This is "
            "what makes a machine feel unresponsive even below 100% CPU.",
            "cpu", {"queue_per_core": round(queue_per_core, 2),
                    "queue_length": cpu.get("queue_length")},
        )
        steal = float(cpu.get("steal") or 0.0)
        consider(
            "cpu_steal", steal >= 10.0,
            "critical" if steal >= 30.0 else "warn",
            "Hypervisor stealing CPU time",
            f"{steal:.0f}% of CPU time was taken by the hypervisor for other "
            "guests. This VM is slow because of its neighbours, not its own "
            "workload -- nothing inside the guest can fix it. Ask the "
            "platform for a less contended host, or reserve CPU for this VM.",
            "cpu", {"steal_percent": round(steal, 1)},
            blame="the hypervisor (noisy neighbours), not a process here",
        )
        thermal = cpu.get("thermal") or {}
        if thermal.get("available"):
            events = float(thermal.get("throttle_events_sec") or 0.0)
            ratio = thermal.get("clock_ratio")
            consider(
                "thermal_throttle", events >= 1.0,
                "critical" if events >= 20.0 else "warn",
                "CPU throttled by its thermal or power limit",
                f"The CPU logged {events:.0f} throttle events/s: it is cutting "
                "its own clock to stay within a temperature or power limit"
                + (f" (running at {float(ratio) * 100:.0f}% of its maximum "
                   "frequency)" if isinstance(ratio, (int, float)) else "")
                + ". Everything runs slower and no process caused it -- look "
                "at cooling, dust, airflow, or the power profile.",
                "cpu", {"throttle_events_sec": round(events, 1),
                        "clock_ratio": ratio,
                        "frequency_mhz": cpu.get("frequency_mhz")},
                blame="the CPU's cooling or power limit, not a process",
            )

        # --- Memory --------------------------------------------------------
        available_mb = memory.get("available_mb")
        if available_mb is not None:
            low = float(available_mb) <= cfg.mem_available_low_mb
            consider(
                "memory_low", low,
                "critical" if float(available_mb) <= cfg.mem_available_low_mb / 2
                else "warn",
                "Low available memory",
                f"Only {float(available_mb):,.0f} MB available (MemAvailable). "
                "The kernel is reclaiming caches and will start swapping or "
                "OOM-killing next.",
                "memory", {"available_mb": round(float(available_mb))},
            )
        commit_percent = float(memory.get("commit_percent") or 0.0)
        consider(
            "commit_high",
            bool(memory.get("commit_enforced"))
            and commit_percent >= cfg.mem_commit_high,
            "critical" if commit_percent >= 97 else "warn",
            "Commit charge near limit",
            f"Committed_AS is at {commit_percent:.0f}% of CommitLimit under "
            "strict overcommit (vm.overcommit_memory=2) -- allocations start "
            "failing here.",
            "memory", {"commit_percent": round(commit_percent, 1)},
        )
        hard_faults = float(memory.get("hard_faults_sec") or 0.0)
        consider(
            "thrashing", hard_faults >= cfg.hard_faults_high,
            "critical" if hard_faults >= cfg.hard_faults_high * 4 else "warn",
            "Paging from disk",
            f"{hard_faults:,.0f} major faults/sec. Memory is being served from "
            "disk instead of RAM -- the classic cause of whole-system stutter.",
            "memory", {"hard_faults_sec": round(hard_faults)},
        )
        swap_pages = (float(memory.get("swap_in_sec") or 0.0)
                      + float(memory.get("swap_out_sec") or 0.0))
        if memory.get("swap_rotational") is True:
            slow_devices = ", ".join(
                str(d.get("path")) for d in (memory.get("swap_devices") or [])
                if isinstance(d, dict) and d.get("rotational"))
            consider(
                "swap_slow", swap_pages >= 100.0,
                "critical" if swap_pages >= 2000.0 else "warn",
                "Swapping to a spinning disk",
                f"{swap_pages:,.0f} pages/s are moving to or from swap on a "
                f"rotational disk ({slow_devices}). Every page brought back "
                "costs a seek, so this stalls the whole machine far harder "
                "than the same paging on an SSD would. The fix is hardware: "
                "move swap to solid-state storage, or add RAM.",
                "memory", {"swap_in_sec": memory.get("swap_in_sec"),
                           "swap_out_sec": memory.get("swap_out_sec"),
                           "swap_device": slow_devices},
                blame="the swap device (a rotational disk), not a process",
            )

        # --- Memory-fill forecast: not out yet, but will be ---------------
        # The disk forecast's sibling: MemAvailable fitted over the last
        # hour, and the processes whose RSS grew meanwhile named as the
        # growers -- which is a different question from "who is largest"
        # (memory_low ranks that) and from "whom the OOM killer takes"
        # (the kernel's own ranking, attached below as next_victims).
        forecast = memory_forecast if isinstance(memory_forecast, dict) else {}
        eta = forecast.get("seconds_to_exhaust")
        if isinstance(eta, (int, float)) and forecast.get("trend") == "shrinking":
            hours = float(eta) / 3600
            r2 = float(forecast.get("r2") or 0)
            steadiness = ("steadily" if r2 >= 0.9 else "unevenly" if r2 >= 0.5 else "erratically")
            growers = [g for g in (forecast.get("growers") or []) if isinstance(g, dict)]
            newcomers = [n for n in (forecast.get("newcomers") or []) if isinstance(n, dict)]
            who = ""
            if growers:
                top = growers[0]
                share = top.get("share_of_loss")
                who = (f" {top.get('name')} (pid {top.get('pid')}) grew by "
                       f"{_mb(top.get('growth_bytes'))} over the same window"
                       + (f", {float(share) * 100:.0f}% of what the machine lost"
                          if isinstance(share, (int, float)) else "") + ".")
            elif newcomers:
                top = newcomers[0]
                who = (f" No process grew steadily enough to name, but {top.get('name')} "
                       f"(pid {top.get('pid')}) appeared {_minutes_text(float(top.get('elapsed_seconds') or 0) / 60)} "
                       f"ago holding {_mb(top.get('working_set'))}.")
            else:
                who = " No single process accounts for it: the growth is spread, or in the kernel (slab, page tables)."
            victim = None
            if isinstance(ceilings, dict):
                nxt = ((ceilings.get("oom") or {}).get("next") or [])
                victim = nxt[0] if nxt and isinstance(nxt[0], dict) else None
            if growers and victim and victim.get("pid") != growers[0].get("pid"):
                who += (f" That is not what the OOM killer would take first -- its own "
                        f"ranking says {victim.get('name')} (pid {victim.get('pid')}).")
            consider(
                "memory_forecast", hours <= _MEMORY_FORECAST_HORIZON_H,
                "critical" if hours <= 0.5 else "warn" if hours <= 2 else "info",
                f"Available memory runs out in about {_hours_text(hours)}",
                f"MemAvailable has fallen {steadiness} by {_mb(-float(forecast.get('delta_bytes') or 0))} "
                f"over the last {float(forecast.get('window_seconds') or 0) / 60:.0f} min "
                f"({_mb(-float(forecast.get('bytes_per_hour') or 0))}/h); {_mb(forecast.get('available_bytes'))} "
                f"is left. At this rate it is gone in about {_hours_text(hours)}"
                + (" -- an extrapolation of an uneven trend, so treat the time as rough"
                   if r2 < 0.9 else "")
                + ", and the kernel starts reclaiming, swapping, then killing." + who,
                "memory", {"available_bytes": forecast.get("available_bytes"),
                           "rate_bytes_hour": forecast.get("bytes_per_hour"),
                           "hours_to_exhaust": round(hours, 1), "r2": r2},
            )
            for candidate in reversed(candidates):
                if candidate.get("key") == "memory_forecast":
                    candidate["growers"] = growers
                    candidate["newcomers"] = newcomers
                    break
        else:
            consider("memory_forecast", False, "info", "", "", "memory", {})

        # --- Inside one unit: what the machine-wide numbers hide -----------
        unit_oom = self._unit_findings(cgroups, consider, candidates, cfg, now,
                                       psi_cpu, psi_mem_full, psi_io_full)

        # OOM kills: an event, not a level, so it bypasses the sustain window.
        # When a unit's own counter explains it, that finding names the unit
        # and this machine-wide one stays quiet (same kill, counted twice).
        oom_total = memory.get("oom_kills_total")
        if isinstance(oom_total, int):
            if self._prev_oom is not None and oom_total > self._prev_oom \
                    and not unit_oom:
                candidates.append({
                    "key": "oom_kill", "severity": "critical",
                    "title": "The kernel killed a process (OOM)",
                    "detail": f"{oom_total - self._prev_oom} process(es) were "
                              "killed by the out-of-memory killer since the "
                              "last sample. See the Events view for which.",
                    "resource": "memory",
                    "evidence": {"oom_kills_total": oom_total},
                    "sustained_ticks": cfg.sustain_ticks, "since": now,
                })
            self._prev_oom = oom_total

        # --- The kernel itself: RAID rebuilds, interrupt-bound cores, disk
        # encryption, a device being reset -- causes with no process behind them
        self._kernel_findings(kernel, processes, pressures, consider, cfg)

        # --- Ceilings: a hard limit about to be reached, with its holder ----
        self._ceiling_findings(ceilings, cgroups, consider, cfg)

        # --- Turned-away clients: a listener whose accept queue overflows --
        self._port_findings(ports, consider)

        # --- Disk ----------------------------------------------------------
        latency_ms = disk_total.get("latency_ms")
        if latency_ms is not None:
            value = float(latency_ms)
            consider(
                "disk_latency", value >= cfg.disk_latency_high_ms,
                "critical" if value >= cfg.disk_latency_high_ms * 3 else "warn",
                "Disk latency high",
                f"{value:.0f} ms average per request. Anything above "
                f"{cfg.disk_latency_high_ms:.0f} ms is felt directly as file "
                "operations and app launches hanging.",
                "disk", {"latency_ms": round(value, 1)},
            )
        queue_length = disk_total.get("queue_length")
        if queue_length is not None:
            value = float(queue_length)
            consider(
                "disk_queue", value >= cfg.disk_queue_high,
                "critical" if value >= cfg.disk_queue_high * 4 else "warn",
                "Disk queue backing up",
                f"{value:.1f} requests in flight. The storage stack cannot keep "
                "up with what is being asked of it. (On multi-queue NVMe this "
                "number is less meaningful -- trust latency first.)",
                "disk", {"queue_length": round(value, 2)},
            )
        busy = disk_total.get("busy_percent")
        if busy is not None:
            value = float(busy)
            # Busy alone is only informational -- an SSD can sit at 100% busy
            # with 0.3ms latency and nobody notices.
            consider(
                "disk_busy", value >= cfg.disk_busy_high, "info",
                "Disk busy",
                f"Disk active {value:.0f}% of the time. Not a problem on its own "
                "unless latency or PSI is also elevated -- and on multi-queue "
                "NVMe, active-time is close to meaningless.",
                "disk", {"busy_percent": round(value, 1)},
            )

        # --- GPU -----------------------------------------------------------
        if gpu.get("available"):
            gpu_total = float(gpu.get("total") or 0.0)
            consider(
                "gpu_saturated", gpu_total >= cfg.gpu_high, "warn",
                "GPU saturated",
                f"GPU at {gpu_total:.0f}%. On integrated graphics this also "
                "steals memory bandwidth from the CPU.",
                "gpu", {"gpu_percent": round(gpu_total, 1)},
            )

        # --- Volumes (checked on the slow tick, no sustain needed) ---------
        for volume in volumes or []:
            mount = str(volume.get("mountpoint"))
            free_pct = 100.0 - float(volume.get("percent") or 0.0)
            writers = [w for w in (volume.get("writers") or []) if isinstance(w, dict)]
            held = [h for h in (volume.get("held_deleted") or []) if isinstance(h, dict)]
            held_bytes = sum(int(h.get("size") or 0) for h in held)
            held_text = ""
            if held:
                top = held[0]
                held_text = (f" {_mb(held_bytes)} of it is held by deleted files still "
                             f"open ({top.get('name')} holds {_mb(top.get('size'))} of "
                             f"{str(top.get('path'))[-60:]}): restarting that process, or "
                             "truncating the file through /proc/<pid>/fd, frees it "
                             "without a reboot.")
            if free_pct <= cfg.disk_space_low_pct:
                candidates.append({
                    "key": f"space_{mount}",
                    "severity": "critical" if free_pct <= 3 else "warn",
                    "title": f"{mount} nearly full",
                    "detail": f"{free_pct:.1f}% free for users (ext4 reserves "
                              "~5% for root on top of this). Full filesystems "
                              "fail writes, break package upgrades, and "
                              "journald starts dropping history." + held_text,
                    "resource": "storage",
                    "evidence": {"mountpoint": mount,
                                 "free": volume.get("free"),
                                 "percent_used": volume.get("percent"),
                                 "held_by_deleted": held_bytes or None},
                    "sustained_ticks": cfg.sustain_ticks,
                    "writers": writers, "mount": mount,
                    # The deleted-but-open files themselves, so the card can
                    # offer to free them (truncate through the holder's fd).
                    "held": held[:3],
                })
            # Fill forecast: not full yet, but will be. The rate is a
            # least-squares slope over the last hour; erratic growth (a
            # burst then a plateau) is said to be erratic, not given an ETA
            # to the minute.
            forecast = volume.get("forecast") or {}
            eta = forecast.get("seconds_to_full") if isinstance(forecast, dict) else None
            key = f"space_forecast:{mount}"
            active = (isinstance(eta, (int, float)) and float(eta) <= 24 * 3600
                      and forecast.get("trend") == "growing" and free_pct > cfg.disk_space_low_pct)
            if isinstance(eta, (int, float)):
                hours = float(eta) / 3600
                r2 = float(forecast.get("r2") or 0)
                steadiness = ("steadily" if r2 >= 0.9 else "unevenly" if r2 >= 0.5 else "erratically")
                consider(
                    key, active,
                    "critical" if hours <= 1 else "warn" if hours <= 6 else "info",
                    f"{mount} will be full in about {_hours_text(hours)}",
                    f"Used space has grown {steadiness} by {_mb(forecast.get('delta_bytes'))} "
                    f"over the last {float(forecast.get('window_seconds') or 0) / 60:.0f} min "
                    f"({_mb(forecast.get('rate_bytes_sec'))}/s, "
                    f"{_mb(forecast.get('bytes_per_day'))}/day); {_mb(volume.get('free'))} "
                    f"is left for users. At this rate it is full in about "
                    f"{_hours_text(hours)}"
                    + (" -- an extrapolation of an uneven trend, so treat the time as rough"
                       if r2 < 0.9 else "")
                    + ". The processes below are the ones writing there now."
                    + held_text,
                    "storage", {"mountpoint": mount, "free": volume.get("free"),
                                "rate_bytes_sec": forecast.get("rate_bytes_sec"),
                                "hours_to_full": round(hours, 1), "r2": r2,
                                "held_by_deleted": held_bytes or None},
                )
                for candidate in reversed(candidates):
                    if candidate.get("key") == key:
                        candidate["writers"] = writers
                        candidate["mount"] = mount
                        candidate["held"] = held[:3]
                        break
            else:
                consider(key, False, "info", "", "", "storage", {})

        # --- Stuck processes (uninterruptible sleep) -----------------------
        stuck = [p for p in processes if p.get("stuck")]
        if stuck:
            names = ", ".join(sorted({str(p["name"]) for p in stuck})[:4])
            wchans = sorted({str(p.get("wchan")) for p in stuck if p.get("wchan")})
            plural = "es" if len(stuck) != 1 else ""
            # The kernel function they are blocked in says *what* they wait
            # on. A cluster of NFS/SMB/FUSE waits is a file server (or the
            # network to it) stalling, not anything on this machine.
            remote = _remote_storage_cluster(wchans)
            finding = {
                "key": "stuck_procs", "severity": "critical",
                "title": f"{len(stuck)} process{plural} stuck in "
                         "uninterruptible sleep",
                "detail": f"{names} have sat in D-state for several consecutive "
                          "samples -- blocked inside the kernel, almost always "
                          "on dead storage or an unreachable network mount. "
                          "They cannot be killed until the IO completes."
                          + (f" Blocked in: {', '.join(wchans[:3])}." if wchans
                             else ""),
                "resource": "responsiveness",
                "evidence": {"pids": [p["pid"] for p in stuck],
                             "wchan": ", ".join(wchans[:3]) or None},
                "sustained_ticks": cfg.sustain_ticks,
            }
            if remote:
                finding["title"] = (f"{len(stuck)} process{plural} stuck waiting "
                                    f"on {remote}")
                finding["detail"] = (
                    f"{names} are blocked inside the kernel's {remote} client "
                    f"({', '.join(wchans[:3])}). The processes listed are the "
                    "victims, not the cause: the server on the other end (or "
                    "the network path to it) is not answering. Killing them "
                    "does nothing until the mount responds -- check the "
                    "server, then the mount options (soft/hard, timeo).")
                finding["external"] = True
                finding["blame"] = f"the {remote} server or the network to it"
                finding["victims"] = True
            candidates.append(finding)

        # --- Not responding (Windows: a window stopped pumping messages) ---
        hung = [p for p in processes if p.get("hung")]
        if hung:
            names = ", ".join(sorted({str(p["name"]) for p in hung})[:4])
            candidates.append({
                "key": "hung_apps", "severity": "critical",
                "title": f"{len(hung)} window{'s' if len(hung) != 1 else ''} not responding",
                "detail": f"{names} stopped processing window messages. A frozen "
                          "window usually means blocking I/O (a network share, a "
                          "slow disk) or a deadlock, not CPU load -- the process "
                          "sits at 0% while the user waits.",
                "resource": "responsiveness",
                "evidence": {"pids": [p["pid"] for p in hung],
                             "titles": [str(p.get("hung_title") or "")[:80] for p in hung][:4]},
                "sustained_ticks": cfg.sustain_ticks,
                "hung": True,
            })

        # Attribute each finding to the processes actually driving that resource.
        # An external finding lists no culprits -- unless the listed processes
        # are its *victims* (D-state), which the finding then says outright.
        # A per-unit finding ranks only the processes inside that unit.
        for finding in candidates:
            if finding.get("external") and not finding.get("victims"):
                finding["culprits"] = []
            elif finding.get("mount"):
                # Storage findings name the processes writing to *that*
                # mount (open files under it), not the machine's top writers
                # -- when nothing could be attributed, no culprits, and the
                # payload's writers_note names the unlock.
                finding["culprits"] = [
                    {**_culprit_of(w, "storage"),
                     "share": (f"{_mb(w.get('write_bytes_sec'))}/s"
                               + (" (by working directory)" if w.get("by_cwd") else "")),
                     "paths": w.get("paths") or [],
                     # The file it is writing fastest, with the rate its
                     # descriptor advanced -- the name, not just the process.
                     "file": _fastest_path(w.get("paths") or [])}
                    for w in (finding.pop("writers", None) or [])
                    if isinstance(w, dict) and w.get("pid") is not None
                ]
            elif finding.get("growers") is not None:
                # The memory forecast ranks the processes that *grew*, by
                # their growth rate, not the largest ones: a leak is a
                # slope. Nothing grew -> no culprits, and the detail says
                # where else to look.
                by_pid = {p.get("pid"): p for p in processes}
                finding["culprits"] = [
                    {**_culprit_of(by_pid.get(g.get("pid")) or _row_from_grower(g), "memory"),
                     "share": _growth_text(g), "growth_bytes": g.get("growth_bytes"),
                     "rate_bytes_sec": g.get("rate_bytes_sec")}
                    for g in finding["growers"] if isinstance(g, dict)
                ]
            elif "listeners" in finding:
                # A turned-away finding names the process(es) holding the
                # listening socket -- the ones not calling accept() fast
                # enough -- and nothing else. An empty list stays empty: when
                # no queue was full at sampling time there is no name to give.
                pids = set(finding.pop("listeners") or [])
                finding["culprits"] = [
                    {**_culprit_of(p, "network"), "share": "holds the listening socket"}
                    for p in processes if p.get("pid") in pids
                ]
            elif finding.get("holder"):
                # A ceiling has exactly one holder; ranking anything else
                # under it would be invention.
                holder = finding["holder"]
                row = next((p for p in processes if p.get("pid") == holder.get("pid")), None)  # type: ignore[union-attr]
                finding["culprits"] = ([_culprit_of(row, str(finding["resource"]))]
                                       if row else [])
            elif finding.get("unit"):
                unit_name = (finding["unit"] or {}).get("name")  # type: ignore[union-attr]
                inside = [p for p in processes if p.get("unit") == unit_name]
                finding["culprits"] = (_culprits(inside, str(finding["resource"]))
                                       if inside else [])
            else:
                finding["culprits"] = _culprits(processes, str(finding["resource"]))
            # Which units are hurting most under a machine-wide stall: the
            # victims' side of the same measurement, from their own cgroups.
            if str(finding["key"]) in ("psi_cpu", "psi_memory", "psi_io"):
                finding["suffering"] = _suffering(cgroups, str(finding["key"]))
            # Memory findings say who the OOM killer would take first: the
            # kernel's own ranking, so the "what happens next" is concrete.
            if str(finding.get("resource")) == "memory" and isinstance(ceilings, dict):
                victims = ((ceilings.get("oom") or {}).get("next") or [])[:3]
                if victims:
                    finding["next_victims"] = victims
            # What changed in the minutes before it began -- coincidence,
            # labelled as such; the reader draws the line.
            since = finding.get("since")
            if changes is not None and isinstance(since, (int, float)):
                try:
                    finding["changes"] = changes.around(float(since))  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001 -- never let the log break a diagnosis
                    finding["changes"] = []

        candidates.sort(key=lambda f: (
            -SEVERITY_ORDER.index(str(f["severity"])),
            -float(f.get("sustained_ticks") or 0),
        ))

        worst = candidates[0]["severity"] if candidates else "ok"
        ranked = sorted(processes, key=lambda p: -float(p.get("lag_score") or 0))

        return {
            "status": _overall(worst),
            "severity": worst,
            "headline": _headline(worst, candidates),
            "findings": candidates,
            "pressures": pressures,
            "pressure_mode": pressures.get("mode", "derived"),
            "offenders": [_slim(p) for p in ranked[:12] if float(p.get("lag_score") or 0) > 1],
            # Where MemAvailable is heading (memtrend): rendered under the
            # memory gauge whether or not it has become a finding.
            "memory_forecast": (memory_forecast if isinstance(memory_forecast, dict)
                                else {"available": False, "reason": "not computed"}),
        }


    # ----------------------------------------------------------- per unit
    def _unit_findings(self, cgroups: dict | None, consider, candidates: list,
                       cfg: Config, now: float, machine_cpu: float | None,
                       machine_mem: float | None, machine_io: float | None) -> bool:
        """Throttled by its own quota, at its own memory limit, or stalled
        inside while the machine is quiet. Returns True when a unit-confined
        OOM kill was reported (so the machine-wide one is not repeated)."""
        keys: set[str] = set()
        unit_oom = False
        units = (cgroups or {}).get("units") if isinstance(cgroups, dict) \
            and cgroups.get("available") else None
        for unit in units or []:
            if not isinstance(unit, dict):
                continue
            cgroup = str(unit.get("cgroup") or "")
            label = _unit_label(unit)
            ref = {
                "name": unit.get("unit"), "cgroup": cgroup,
                "manager": unit.get("manager"), "kind": unit.get("kind"),
                "container": unit.get("container"),
                "runtime_cap": bool(unit.get("runtime_cap")),
            }
            psi_unit = unit.get("psi") or {}
            quota = unit.get("cpu_quota_pct")

            # 1. Hitting its CPU quota: slow because of a cap, not the box.
            key = f"unit_throttled:{cgroup}"
            keys.add(key)
            throttled = unit.get("throttled_pct")
            if quota is not None and isinstance(throttled, (int, float)):
                machine_pct = unit.get("cpu_quota_machine_pct")
                cap = (f"{float(quota):.0f}% of one core"
                       + (f" ({float(machine_pct):.0f}% of this machine)"
                          if isinstance(machine_pct, (int, float)) else ""))
                if unit.get("runtime_cap"):
                    origin = (" The cap was set at runtime (a `systemctl "
                              "set-property --runtime` drop-in, which is what "
                              "Culprit's Throttle creates) and lasts until the "
                              "unit is released or the machine reboots: if "
                              "nobody meant to keep it, release it from the "
                              "process dialog.")
                else:
                    origin = (" The cap comes from the unit's own configuration "
                              "(CPUQuota=, or the container's --cpus); raise it "
                              "there if the work matters.")
                consider(
                    key, float(throttled) >= 25.0,
                    "critical" if float(throttled) >= 75.0 else "warn",
                    f"{label} is hitting its CPU quota",
                    f"The unit wanted more CPU than its cap allows in "
                    f"{float(throttled):.0f}% of scheduling periods "
                    f"({float(unit.get('throttled_ms_sec') or 0):.0f} ms/s "
                    f"spent throttled). Its cap is {cap}. Everything in it "
                    "runs slower because of the cap, not because the machine "
                    "is busy." + origin,
                    "cpu", {"throttled_pct": round(float(throttled), 1),
                            "cpu_quota_pct": quota,
                            "throttled": f"{float(unit.get('throttled_ms_sec') or 0):.0f} ms/s",
                            "processes": unit.get("pids")},
                    unit=ref)

            # 2. At its memory limit: the box has RAM, the unit does not.
            key = f"unit_memlimit:{cgroup}"
            keys.add(key)
            mem_max = unit.get("memory_max")
            pct = unit.get("memory_limit_pct")
            hits = (float(unit.get("limit_hits_sec") or 0)
                    + float(unit.get("high_hits_sec") or 0))
            if isinstance(mem_max, int) and mem_max > 0:
                stall = psi_unit.get("memory_full")
                active = (isinstance(pct, (int, float)) and float(pct) >= 95.0) or hits > 0
                consider(
                    key, bool(active),
                    "critical" if (isinstance(pct, (int, float)) and float(pct) >= 99.0)
                    or (isinstance(stall, (int, float)) and float(stall) >= cfg.psi_memory_high)
                    else "warn",
                    f"{label} is at its memory limit",
                    f"Using {_mb(unit.get('memory_bytes'))} of its {_mb(mem_max)} "
                    f"limit"
                    + (f" ({float(pct):.0f}%)" if isinstance(pct, (int, float)) else "")
                    + (f"; the kernel hit that limit {hits:.1f} times/s and is "
                       "reclaiming inside the unit" if hits > 0 else "")
                    + (f", and its tasks were stalled on memory {float(stall):.0f}% "
                       "of the time" if isinstance(stall, (int, float)) and stall >= 1 else "")
                    + ". This is the unit's own ceiling (memory.max, or the "
                    "container's --memory), not the machine running out of RAM. "
                    "What comes next is an OOM kill confined to the unit.",
                    "memory", {"memory_limit_pct": pct,
                               "limit_mb": round(mem_max / 1024 ** 2),
                               "used_mb": round(float(unit.get("memory_bytes") or 0) / 1024 ** 2),
                               "limit_hits_sec": round(hits, 2),
                               "unit_stall_pct": stall},
                    unit=ref)

            # 2b. An OOM kill confined to the unit: an event, no sustain.
            new_kills = int(unit.get("oom_kills_new") or 0)
            if new_kills > 0:
                unit_oom = True
                candidates.append({
                    "key": f"unit_oom:{cgroup}", "severity": "critical",
                    "title": f"The kernel killed a process inside {label}",
                    "detail": f"{new_kills} process(es) in this unit were killed "
                              "for exceeding the unit's own memory limit"
                              + (f" ({_mb(mem_max)})" if isinstance(mem_max, int) else "")
                              + ". The machine as a whole was not out of memory; "
                              "the unit was. See the Events view for which process.",
                    "resource": "memory", "unit": ref,
                    "evidence": {"oom_kills": unit.get("oom_kills"),
                                 "limit_mb": (round(mem_max / 1024 ** 2)
                                              if isinstance(mem_max, int) else None)},
                    "sustained_ticks": cfg.sustain_ticks, "since": now,
                })

            # 3. Stalled inside while the machine is quiet.
            for resource, kind, machine, threshold, word, hint in (
                ("cpu", "some", machine_cpu, cfg.psi_cpu_high, "CPU",
                 (f"It has a CPU quota of {float(quota):.0f}% of one core -- "
                  "see whether it is being throttled." if quota is not None else
                  "Its threads compete with each other for the CPU share this "
                  "unit is allowed (cpu.weight, cpuset), or it wants more cores "
                  "than it can reach.")),
                ("memory", "full", machine_mem, cfg.psi_memory_high / 2, "memory",
                 ("Reclaim is happening inside the unit: it is near its own "
                  "memory limit." if isinstance(mem_max, int) else
                  "Reclaim is happening inside the unit (memory.high, or its "
                  "own working set thrashing).")),
                ("io", "full", machine_io, cfg.psi_io_high / 2, "storage",
                 "Its IO is slower than the machine's average: it may sit on a "
                 "slower device (a network mount, a USB disk, a loop image) or "
                 "be limited by io.max / io.weight."),
            ):
                key = f"unit_stalled:{resource}:{cgroup}"
                keys.add(key)
                value = psi_unit.get(f"{resource}_{kind}")
                if not isinstance(value, (int, float)):
                    continue
                machine_val = float(machine or 0.0)
                active = float(value) >= threshold and machine_val < float(value) / 2
                consider(
                    key, active,
                    "critical" if float(value) >= threshold * 2 else "warn",
                    f"{label} is stalled on {word}",
                    f"Tasks in this unit were stalled waiting for {word} "
                    f"{float(value):.0f}% of the time (10 s average) while the "
                    f"machine as a whole was at {machine_val:.0f}%: the problem "
                    "is inside the unit, not the box. " + hint,
                    {"cpu": "cpu", "memory": "memory", "io": "disk"}[resource],
                    {"unit_stall_pct": round(float(value), 1),
                     "machine_stall_pct": round(machine_val, 1)},
                    unit=ref)
        self._sustain.prune("unit_", keys)
        # A parent (user@1000.service, a slice-like manager) aggregates its
        # children's stall; when a child already carries a finding, the
        # parent's "stalled" is the same fact one level up -- drop it.
        carrying = [str((c.get("unit") or {}).get("cgroup") or "")
                    for c in candidates if c.get("unit")]
        candidates[:] = [
            c for c in candidates
            if not (str(c.get("key", "")).startswith("unit_stalled:")
                    and any(other != (c.get("unit") or {}).get("cgroup")
                            and other.startswith(str((c.get("unit") or {}).get("cgroup")) + "/")
                            for other in carrying))
        ]
        # Machine-wide CPU stall counts throttled tasks as stalled; when
        # units are hitting their quota, say how much of the machine's
        # number is that, instead of letting it read as a saturated box.
        throttled = [str((c.get("unit") or {}).get("name") or "?") for c in candidates
                     if str(c.get("key", "")).startswith("unit_throttled:")]
        if throttled:
            for finding in candidates:
                if finding.get("key") == "psi_cpu":
                    finding["detail"] = (
                        str(finding["detail"]) + " Part of this stall is quota "
                        f"throttling inside {', '.join(throttled[:3])}: tasks "
                        "waiting on their own cgroup's CPU cap count as stalled, "
                        "so this can read as a saturated machine while the cores "
                        "sit idle -- check the per-unit findings first.")
                    finding.setdefault("evidence", {})["throttled_units"] = ", ".join(throttled[:3])
        return unit_oom

    # ------------------------------------------------------------ ceilings
    def _ceiling_findings(self, ceilings: dict | None, cgroups: dict | None,
                          consider, cfg: Config) -> None:
        """A hard limit at >=80% of its ceiling, with the process (or the
        machine) holding it. Nothing is slow yet; the next call fails."""
        keys: set[str] = set()
        entries = (ceilings or {}).get("limits") if isinstance(ceilings, dict) \
            and ceilings.get("available") else None
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            pct = float(entry.get("pct") or 0)
            holder = entry.get("holder") if isinstance(entry.get("holder"), dict) else None
            kind = str(entry.get("kind"))
            key = f"ceiling:{kind}" + (f":{holder.get('pid')}" if holder and kind == "fds" else "")
            keys.add(key)
            who = (f"{holder.get('name')} (pid {holder.get('pid')})" if holder else "this machine")
            share = entry.get("holder_share")
            held = (f" {who} holds {int(share):,} of them." if holder and share else
                    f" The holder is {who}." if holder and kind != "fds" else "")
            lower = " The count is a lower bound: some processes' descriptors are not readable at this privilege level." \
                if entry.get("partial") else ""
            consider(
                key, pct >= 80.0, "critical" if pct >= 95.0 else "warn",
                f"{entry.get('label')} at {pct:.0f}% of the limit",
                f"{int(entry.get('current') or 0):,} of {int(entry.get('max') or 0):,} in use."
                f"{held} At the ceiling the next request fails outright (EMFILE, "
                "a dropped connection, a watch that is never registered) rather "
                f"than slowing down. Fix: {entry.get('fix') or 'raise the limit'}.{lower}",
                "limits", {"current": entry.get("current"), "max": entry.get("max"),
                           "pct": pct},
            )
            # consider() has no holder parameter; attach it to the candidate
            # it just appended, if it did.
            if holder:
                for candidate in reversed(self._last_candidates):
                    if candidate.get("key") == key:
                        candidate["holder"] = holder
                        break
        # Per-unit task ceilings come from the cgroup walk (pids.max).
        units = (cgroups or {}).get("units") if isinstance(cgroups, dict) \
            and cgroups.get("available") else None
        for unit in units or []:
            if not isinstance(unit, dict):
                continue
            pids, pids_max = unit.get("pids"), unit.get("pids_max")
            if not isinstance(pids, int) or not isinstance(pids_max, int) or pids_max <= 0:
                continue
            key = f"ceiling:unit_pids:{unit.get('cgroup')}"
            keys.add(key)
            pct = 100.0 * pids / pids_max
            consider(
                key, pct >= 80.0, "critical" if pct >= 95.0 else "warn",
                f"{_unit_label(unit)} is near its task limit ({pct:.0f}%)",
                f"{pids:,} of {pids_max:,} tasks (TasksMax / pids.max). At the "
                "ceiling, fork() and thread creation inside the unit fail with "
                "EAGAIN while the rest of the machine is fine. Fix: TasksMax= "
                "in the unit, or DefaultTasksMax= in system.conf.",
                "limits", {"tasks": pids, "tasks_max": pids_max, "pct": round(pct, 1)},
                unit={"name": unit.get("unit"), "cgroup": unit.get("cgroup"),
                      "manager": unit.get("manager"), "kind": unit.get("kind"),
                      "container": unit.get("container"), "runtime_cap": False},
            )
        self._sustain.prune("ceiling:", keys)

    # ------------------------------------------------------ turned away
    def _port_findings(self, ports: dict | None, consider) -> None:
        """A listener refusing clients: its accept queue is full while the
        kernel's ListenOverflows counter ticks. The symptom side of "does it
        matter" -- the service is up and may look idle, and clients time out.

        The overflow counter is machine-wide (per network namespace) and only
        a full queue can overflow, so a port is named only when its queue is
        at its backlog at sampling time. Overflows with no full queue become
        one unnamed finding that says the burst had drained, with no culprits
        -- guessing the port would be invention.
        """
        keys: set[str] = set()
        backlog = (ports or {}).get("backlog") if isinstance(ports, dict) \
            and ports.get("available") else None
        rate = backlog.get("overflows_sec") if isinstance(backlog, dict) \
            and backlog.get("available") else None
        if not isinstance(rate, (int, float)):
            self._sustain.prune("turned_away", keys)
            return
        interval = backlog.get("interval")  # type: ignore[union-attr]
        window = f"{float(interval):.0f} s" if isinstance(interval, (int, float)) else "the last interval"
        cookies = backlog.get("syn_cookies_sec")  # type: ignore[union-attr]
        cookie_text = (f" The SYN queue overflowed too ({float(cookies):.1f} SYN cookies/s): "
                       "either a SYN flood or the same service failing to accept."
                       if isinstance(cookies, (int, float)) and cookies > 0 else "")
        named = 0
        for entry in (ports.get("ports") if isinstance(ports, dict) else None) or []:  # type: ignore[union-attr]
            if not isinstance(entry, dict) or not entry.get("turned_away"):
                continue
            queue = entry.get("accept_queue")
            if not isinstance(queue, dict):
                continue
            port = entry.get("port")
            key = f"turned_away:{port}"
            keys.add(key)
            named += 1
            procs = [p for p in (entry.get("processes") or []) if isinstance(p, dict)]
            primary = procs[0] if procs else None
            unit = primary.get("unit") if primary else None
            owners = entry.get("owners") or []
            who = (f"{primary.get('name')} (pid {primary.get('pid')})" if primary
                   else f"{', '.join(map(str, owners))}'s process" if owners
                   else "a process this agent cannot see (needs CAP_SYS_PTRACE or root to name it)")
            label = f"Port {port}" + (f" ({unit})" if unit else f" ({primary.get('name')})" if primary else "")
            consider(
                key, True, "critical" if float(rate) >= 10 else "warn",
                f"{label} is turning clients away",
                f"Its accept queue is full: {int(queue.get('current') or 0):,} completed "
                f"connections are waiting for {who} to accept() them, against a listen "
                f"backlog of {int(queue.get('max') or 0):,}, and the kernel dropped "
                f"{float(rate):.1f} connection attempts/s over {window} (ListenOverflows). "
                "Clients see timeouts and resets, not slowness -- the service never "
                "sees them. It is not accepting fast enough: blocked, busy on one "
                "thread, or out of workers. Fix: more workers or a faster accept "
                "loop in the service; raising its listen backlog and "
                f"net.core.somaxconn only buys time.{cookie_text}",
                "network", {"port": port, "queue": queue.get("current"),
                            "backlog": queue.get("max"),
                            "overflows_sec": round(float(rate), 2),
                            "syn_cookies_sec": cookies},
            )
            for candidate in reversed(self._last_candidates):
                if candidate.get("key") == key:
                    candidate["port"] = port
                    candidate["unit_name"] = unit
                    candidate["listeners"] = [p.get("pid") for p in procs if p.get("pid")]
                    break
        if float(rate) > 0 and not named:
            key = "turned_away"
            keys.add(key)
            consider(
                key, True, "warn",
                f"Clients turned away: {float(rate):.1f} connection attempts/s dropped",
                (backlog.get("note") if isinstance(backlog, dict) and backlog.get("note") else  # type: ignore[union-attr]
                 f"The kernel dropped {float(rate):.1f} connection attempts/s over {window} "
                 "for a full accept queue (ListenOverflows), but no listener's queue was "
                 "full at the moment the port map was sampled -- the burst had drained.")
                + " Nobody is named: the port can only be told by a queue that is full "
                "when it is looked at. The Ports view shows each listener's queue against "
                f"its backlog; the one that fills in bursts is the one to watch.{cookie_text}",
                "network", {"overflows_sec": round(float(rate), 2),
                            "listen_drops_sec": backlog.get("drops_sec"),  # type: ignore[union-attr]
                            "syn_cookies_sec": cookies},
            )
            for candidate in reversed(self._last_candidates):
                if candidate.get("key") == key:
                    candidate["listeners"] = []
                    break
        self._sustain.prune("turned_away", keys)

    # ----------------------------------------------------------- the kernel
    def _kernel_findings(self, kernel: dict | None, processes: list[dict],
                         pressures: dict[str, float], consider, cfg: Config) -> None:
        kn = kernel if isinstance(kernel, dict) and kernel.get("available") else {}
        md = kn.get("mdstat") or {}
        arrays = md.get("arrays") if isinstance(md, dict) else None
        keys: set[str] = set()
        for array in arrays or []:
            if not isinstance(array, dict):
                continue
            name = str(array.get("name"))
            sync = array.get("sync")
            key = f"raid_sync:{name}"
            keys.add(key)
            if isinstance(sync, dict):
                op = str(sync.get("op"))
                pct = float(sync.get("percent") or 0)
                finish = sync.get("finish_minutes")
                speed = sync.get("speed_kb_sec")
                eta = (f", about {_minutes_text(float(finish))} left"
                       if isinstance(finish, (int, float)) else "")
                rate = (f" at {float(speed) / 1024:.0f} MB/s"
                        if isinstance(speed, (int, float)) else "")
                consider(
                    key, True,
                    "warn" if float(pressures.get("disk") or 0) >= 0.5 else "info",
                    f"RAID {op} running on {name} ({pct:.0f}%)",
                    f"The software-RAID array {name} ({array.get('level')}) is in "
                    f"a {op}{rate}{eta}. It reads and writes every member disk "
                    f"({', '.join(str(m) for m in array.get('members') or [])}) "
                    "until it finishes, and competes with everything else "
                    "using those disks. No process caused it; "
                    "/proc/sys/dev/raid/speed_limit_max slows it down if the "
                    "foreground work matters more.",
                    "disk", {"array": name, "operation": op, "percent": pct,
                             "finish_minutes": finish, "speed_kb_sec": speed},
                    blame=f"the RAID {op} on {name}, not a process")
            else:
                consider(key, False, "info", "", "", "disk", {})
            key = f"raid_degraded:{name}"
            keys.add(key)
            consider(
                key, bool(array.get("degraded")) and not isinstance(sync, dict),
                "critical", f"RAID array {name} is degraded",
                f"{name} ({array.get('level')}) is running with "
                f"{array.get('members_active')} of {array.get('members_expected')} "
                "members and no rebuild in progress. One more disk failure "
                "loses the array. Replace the failed member and add it back "
                "(mdadm --add) so a recovery starts.",
                "disk", {"array": name, "members_active": array.get("members_active"),
                         "members_expected": array.get("members_expected"),
                         "failed_members": array.get("failed_members")},
                blame=f"a failed member disk of {name}, not a process")
        self._sustain.prune("raid_", keys)

        cores = {int(c.get("core")): c for c in ((kn.get("irq") or {}).get("cores") or [])
                 if isinstance(c, dict) and isinstance(c.get("core"), int)}
        crypt_cpu = 0.0
        eh_active: list[str] = []
        soft_keys: set[str] = set()
        for proc in processes:
            if not proc.get("is_kthread"):
                continue
            name = str(proc.get("name") or "")
            cpu_raw = float(proc.get("cpu_raw") or 0.0)
            if name.startswith("ksoftirqd/"):
                try:
                    core = int(name.split("/", 1)[1])
                except ValueError:
                    continue
                key = f"softirq_core:{core}"
                soft_keys.add(key)
                info = cores.get(core) or {}
                top = (info.get("top") or [None])[0]
                soft = info.get("softirq") or {}
                device = (f"irq {top['irq']} ({top['name']}, {top['rate']:,}/s)"
                          if isinstance(top, dict) else "no single device stands out")
                which = (f"{soft.get('name')} softirqs" if soft.get("name")
                         else "softirqs")
                consider(
                    key, cpu_raw >= 30.0,
                    "critical" if cpu_raw >= 70.0 else "warn",
                    f"Core {core} is busy servicing interrupts",
                    f"ksoftirqd/{core} used {cpu_raw:.0f}% of core {core} draining "
                    f"{which}; the busiest interrupt on that core is {device}. "
                    "Interrupt work is not a process: it cannot be reniced or "
                    "killed, and the tasks scheduled on that core are what "
                    "stall. Spread it with irqbalance, the device's RSS/RPS "
                    "queues, or by moving that IRQ's affinity to another core.",
                    "cpu", {"core": core, "ksoftirqd_pct": round(cpu_raw, 1),
                            "softirq": soft.get("name"),
                            "irq": top.get("irq") if isinstance(top, dict) else None,
                            "irq_device": top.get("name") if isinstance(top, dict) else None,
                            "irq_rate_sec": top.get("rate") if isinstance(top, dict) else None},
                    blame=f"interrupt handling on core {core}"
                          + (f" for {top['name']}" if isinstance(top, dict) else "")
                          + ", not a process")
            elif name.startswith(("kcryptd", "dmcrypt_write")):
                crypt_cpu += cpu_raw
            elif name.startswith("scsi_eh_") and (cpu_raw >= 1.0 or proc.get("stuck")):
                eh_active.append(name)
        self._sustain.prune("softirq_", soft_keys)
        consider(
            "dmcrypt_cpu", crypt_cpu >= 50.0,
            "warn", "Disk encryption is consuming CPU",
            f"The dm-crypt threads (kcryptd, dmcrypt_write) used {crypt_cpu:.0f}% "
            "of a core: every block read from or written to an encrypted "
            "volume is encrypted here, charged to the kernel rather than to "
            "the process doing the IO. The processes below are the ones "
            "generating that IO. AES-NI (cpuinfo flag `aes`) makes this several "
            "times cheaper if it is not already in use.",
            "disk", {"dmcrypt_cpu_pct": round(crypt_cpu, 1)})
        consider(
            "scsi_recovery", bool(eh_active), "critical",
            "A storage device is being reset by the SCSI error handler",
            f"{', '.join(sorted(eh_active))} became active: the SCSI layer is "
            "aborting commands and resetting a device that stopped answering. "
            "Everything queued on that device waits meanwhile. This is a disk, "
            "controller or cable problem -- dmesg / the Events view names the "
            "device (I/O error, task abort, reset), and its SMART data is the "
            "next thing to read.",
            "disk", {"handlers": ", ".join(sorted(eh_active)) or None},
            blame="a storage device that stopped answering, not a process")


# --------------------------------------------------------------------- helpers
def _unit_label(unit: dict) -> str:
    """'nginx.service', or the container's name when the unit is one."""
    where = unit.get("container")
    if isinstance(where, dict):
        if where.get("name"):
            return f"container {where['name']}"
        if where.get("id"):
            return f"container {str(where['id'])[:12]}"
    return str(unit.get("unit") or unit.get("cgroup") or "unit")


def _suffering(cgroups: dict | None, key: str) -> list[dict[str, object]]:
    """Units stalled hardest under a machine-wide stall: the victims' view."""
    if not isinstance(cgroups, dict) or not cgroups.get("available"):
        return []
    field = {"psi_cpu": "cpu_some", "psi_memory": "memory_full",
             "psi_io": "io_full"}[key]
    ranked = []
    for unit in cgroups.get("units") or []:
        if not isinstance(unit, dict):
            continue
        value = (unit.get("psi") or {}).get(field)
        if isinstance(value, (int, float)) and value >= 5.0:
            ranked.append((float(value), unit))
    ranked.sort(key=lambda item: -item[0])
    return [{"name": _unit_label(unit), "unit": unit.get("unit"),
             "stall_pct": round(value, 1), "container": unit.get("container")}
            for value, unit in ranked[:3]]


def _hours_text(hours: float) -> str:
    if hours < 1:
        return f"{hours * 60:.0f} min"
    if hours < 48:
        return f"{hours:.1f} h"
    return f"{hours / 24:.1f} days"


def _minutes_text(minutes: float) -> str:
    if minutes >= 90:
        return f"{minutes / 60:.1f} h"
    return f"{minutes:.0f} min"


def _ratio(value: object, threshold: float) -> float:
    """How far `value` has gone toward `threshold`, capped at 1.0."""
    if value is None or threshold <= 0:
        return 0.0
    try:
        return clamp(float(value) / threshold, 0.0, 1.0)
    except (TypeError, ValueError):
        return 0.0


def _psi_avg10(psi: dict, resource: str, kind: str) -> float | None:
    block = (psi or {}).get(resource) or {}
    values = block.get(kind) or {}
    value = values.get("avg10")
    return float(value) if isinstance(value, (int, float)) else None


def _round3(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


_RESOURCE_SORT = {
    "cpu": lambda p: -float(p.get("cpu") or 0),
    "memory": lambda p: -float(p.get("working_set") or 0),
    "disk": lambda p: -float(p.get("io_bytes_sec") or 0),
    "gpu": lambda p: -float(p.get("gpu") or 0),
    "storage": lambda p: -float(p.get("write_bytes_sec") or 0),
    "responsiveness": lambda p: (0 if (p.get("stuck") or p.get("hung")) else 1,
                                 -float(p.get("lag_score") or 0)),
}


def _culprits(processes: list[dict], resource: str) -> list[dict[str, object]]:
    """The processes most responsible for one resource being under pressure."""
    key = _RESOURCE_SORT.get(resource, _RESOURCE_SORT["cpu"])
    candidates = [p for p in processes if not p.get("is_kthread")]
    if resource == "responsiveness":
        candidates = [p for p in candidates if p.get("stuck") or p.get("hung")] or candidates
    if resource in ("disk", "storage"):
        # Per-process IO is permission-gated; blaming a process whose IO we
        # cannot read would be invention. Only measured, non-zero IO counts --
        # and when nothing qualifies, the finding shows no culprits rather
        # than a made-up ranking.
        candidates = [p for p in candidates
                      if (p.get("io_bytes_sec") or 0) > 0]
    if resource == "cpu":
        # For CPU, a starved victim is not the culprit; sort out the ones
        # merely suffering (high run delay, low usage).
        candidates = [p for p in candidates if float(p.get("cpu") or 0) > 0.1] \
            or candidates
    ranked = sorted(candidates, key=key)[:5]
    return [_culprit_of(p, resource) for p in ranked]


def _culprit_of(p: dict, resource: str) -> dict[str, object]:
    return {
        "pid": p["pid"], "name": p["name"], "username": p.get("username"),
        "cpu": p.get("cpu"), "working_set": p.get("working_set"),
        "io_bytes_sec": p.get("io_bytes_sec"), "gpu": p.get("gpu"),
        "stuck": p.get("stuck"), "hung": p.get("hung"), "lag_score": p.get("lag_score"),
        "share": _share_text(p, resource),
        "container": p.get("container"),
    }


# wchan prefixes that mean "waiting on a remote filesystem". The kernel
# function name is the only evidence there is, and it is specific enough.
_REMOTE_WCHAN = (
    (("nfs", "rpc_", "__nfs", "xprt_"), "NFS"),
    (("cifs", "smb", "SMB"), "SMB/CIFS"),
    (("fuse_", "request_wait_answer"), "FUSE"),
    (("ceph_", "rbd_"), "Ceph"),
    (("glusterfs", "gf_"), "GlusterFS"),
)


def _remote_storage_cluster(wchans: list[str]) -> str | None:
    """The remote filesystem the stuck processes are waiting on, when every
    known wait function points at the same one (a mixed bag is not a verdict)."""
    if not wchans:
        return None
    labels: set[str] = set()
    for wchan in wchans:
        for prefixes, label in _REMOTE_WCHAN:
            if wchan.startswith(prefixes):
                labels.add(label)
                break
        else:
            return None   # a local wait in the mix: not a remote-storage verdict
    return labels.pop() if len(labels) == 1 else None


def _share_text(proc: dict, resource: str) -> str:
    if resource == "cpu":
        return f"{float(proc.get('cpu') or 0):.1f}% CPU"
    if resource == "memory":
        return f"{_mb(proc.get('working_set'))} resident"
    if resource in ("disk", "storage"):
        io = proc.get("io_bytes_sec")
        return "I/O not readable" if io is None else f"{_mb(io)}/s I/O"
    if resource == "gpu":
        return f"{float(proc.get('gpu') or 0):.0f}% GPU"
    if resource == "responsiveness":
        if proc.get("hung"):
            return "not responding"
        return "D-state" if proc.get("stuck") else ""
    if resource == "limits":
        handles = proc.get("handles")
        return f"{int(handles):,} open files" if isinstance(handles, int) else "holder"
    return ""


def _reasons(proc: dict, mem_share: float) -> list[str]:
    """Short, specific phrases the UI shows under a process's score.

    Thresholds are low on purpose. An earlier version only spoke up at 15% CPU
    or 5% of RAM, which left processes scoring 6 or 7 with an empty explanation
    -- a number with no reason next to it is exactly the kind of thing that
    makes a dashboard untrustworthy. If nothing clears a threshold, the dominant
    term from the score breakdown is described instead, so every scored process
    can always say why.
    """
    out: list[str] = []
    if proc.get("hung"):
        title = str(proc.get("hung_title") or "")
        out.append("Not responding" + (f" - {title[:60]}" if title else ""))
    if proc.get("stuck"):
        wchan = proc.get("wchan")
        out.append("Stuck in uninterruptible sleep"
                   + (f" ({wchan})" if wchan else ""))

    cpu_avg = float(proc.get("cpu_avg") or 0)
    cpu_now = float(proc.get("cpu") or 0)
    if cpu_avg >= 4:
        out.append(f"{cpu_avg:.1f}% CPU sustained")
    elif cpu_now >= 12:
        out.append(f"{cpu_now:.0f}% CPU spike")

    delay = float(proc.get("run_delay_ms") or 0)
    if delay >= 50:
        out.append(f"waiting {delay:.0f} ms/s for a CPU")

    if mem_share >= 0.02:
        out.append(f"{_mb(proc.get('working_set'))} RAM ({mem_share * 100:.0f}% of total)")

    io = float(proc.get("io_bytes_sec") or 0)
    if io >= 512 * 1024:
        out.append(f"{_mb(io)}/s disk I/O")

    gpu = float(proc.get("gpu") or 0)
    if gpu >= 3:
        out.append(f"{gpu:.0f}% GPU")

    majflt = float(proc.get("major_faults_sec") or 0)
    if majflt >= 20:
        out.append(f"{majflt:,.0f} major faults/s (paging)")

    threads = int(proc.get("threads") or 0)
    if threads >= 150:
        out.append(f"{threads} threads")

    if out:
        return out

    # Nothing crossed a threshold, but the process still scored. Explain the
    # largest contributing term rather than showing a bare number.
    breakdown = proc.get("lag_breakdown") or {}
    if breakdown:
        top = max(breakdown.items(), key=lambda item: item[1])[0]
        faults = float(proc.get("page_faults_sec") or 0)
        described = {
            "cpu": f"{cpu_now:.1f}% CPU",
            "memory": f"{_mb(proc.get('working_set'))} resident",
            "disk": f"{_mb(io)}/s disk I/O",
            "gpu": f"{gpu:.1f}% GPU",
            "faults": f"{faults:,.0f} page faults/s",
            "stuck": "uninterruptible sleep",
            "hung": "not responding",
        }.get(top)
        if described:
            out.append(f"mostly {described}")
    return out


def _slim(proc: dict) -> dict[str, object]:
    return {
        key: proc.get(key) for key in (
            "pid", "ppid", "name", "username", "cpu", "cpu_avg", "cpu_raw",
            "working_set", "private", "io_bytes_sec", "read_bytes_sec",
            "write_bytes_sec", "gpu", "vram", "threads", "page_faults_sec",
            "major_faults_sec", "run_delay_ms", "state", "stuck", "wchan",
            "hung", "hung_title",
            "lag_score", "lag_breakdown", "lag_reasons", "exe", "container",
            "unit", "kernel",
        )
    }


def _overall(severity: str) -> str:
    if severity == "ok":
        return "healthy"
    if severity == "info":
        return "nominal"
    if severity == "warn":
        return "strained"
    return "struggling"


def _headline(severity: str, findings: list[dict]) -> str:
    if not findings:
        return "No sustained resource pressure detected."
    top = findings[0]
    culprits = top.get("culprits") or []
    if top.get("external"):
        return f"{top['title']} - outside this machine: {top.get('blame')}."
    if culprits:
        lead = culprits[0]
        where = lead.get("container") or {}
        inside = f" in {where['name']}" if where.get("name") else ""
        return f"{top['title']} - {lead['name']}{inside} ({lead['share']}) leads."
    return str(top["title"])


def _fastest_path(paths: list) -> dict[str, object] | None:
    best = None
    for entry in paths:
        if not isinstance(entry, dict):
            continue
        rate = entry.get("rate_bytes_sec")
        if isinstance(rate, (int, float)) and rate > 0 and \
                (best is None or rate > float(best.get("rate_bytes_sec") or 0)):
            best = entry
    if best is None:
        return None
    return {"path": best.get("path"), "rate_bytes_sec": best.get("rate_bytes_sec"),
            "deleted": bool(best.get("deleted"))}


def _row_from_grower(grower: dict) -> dict:
    """A process row for a grower that has just left the table (exited
    between the fit and this tick): what memtrend remembered of it."""
    return {"pid": grower.get("pid"), "name": grower.get("name"),
            "username": grower.get("username"), "working_set": grower.get("working_set"),
            "container": grower.get("container"), "unit": grower.get("unit")}


def _growth_text(grower: dict) -> str:
    text = (f"+{_mb(grower.get('growth_bytes'))} in "
            f"{_minutes_text(float(grower.get('window_seconds') or 0) / 60)}")
    share = grower.get("share_of_loss")
    if isinstance(share, (int, float)):
        text += f" ({float(share) * 100:.0f}% of the loss)"
    return text


def _mb(value: object) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return "0 MB"
    if number >= 1024 ** 3:
        return f"{number / 1024 ** 3:.1f} GB"
    if number < 1024 ** 2:
        # "0 MB/s" next to a ranked culprit reads as a lie; say what it is.
        return f"{number / 1024:.0f} KB"
    return f"{number / 1024 ** 2:.0f} MB"
