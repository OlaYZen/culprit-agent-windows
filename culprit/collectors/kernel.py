"""The kernel explained: what a busy kernel thread *is*, and the two kernel-side
causes that have no process behind them (RAID rebuilds, interrupt handling).

Windows had no equivalent problem: `System` was one opaque process and the
per-driver attribution needed ETW. Linux names every kernel thread, which is
better and worse -- `kworker/u8:3+flush-252:0` at 40% is a precise fact that
means nothing to most people, and the reflex is to try to kill it. So this
module turns each name into a sentence (what it does, what it being busy is a
symptom of, where to look), and the Lag Doctor uses the same table to say when
the culprit is not a process at all.

Two live sources ride along, both sub-millisecond on the target:

- `/proc/mdstat` -- a resync / check / recovery / reshape in progress, with
  percent, ETA and speed. That is a nobody-at-fault cause of disk pressure
  and the one people most often chase for an hour before looking here.
- `/proc/interrupts` + `/proc/softirqs` -- per-core interrupt and softirq
  rates, so when `ksoftirqd/2` is pinned the finding can name the device
  whose interrupt lands on that core instead of just the thread.
"""

from __future__ import annotations

import re
import time

from .. import linux

# ----------------------------------------------------------------- explain
# (regex on the comm, role, what it means when busy, where to look). Order
# matters: first match wins, so specific workqueue names precede the generic
# kworker entry. `symptom_of` names the resource whose *real* culprits the UI
# should point at, when the thread is a symptom rather than a cause.
_EXPLAIN: list[tuple[re.Pattern[str], dict[str, str | None]]] = [
    (re.compile(r"^kswapd\d*$"), {
        "role": "memory reclaim",
        "why": "The kernel is freeing pages because free memory fell below its "
               "watermark. Busy kswapd is a symptom of memory pressure, not a "
               "cause: something else is using the RAM.",
        "look_at": "the memory culprits; adding RAM or trimming the largest "
                   "resident process is the fix, not this thread",
        "symptom_of": "memory"}),
    (re.compile(r"^kcompactd\d*$"), {
        "role": "memory compaction",
        "why": "Free memory is fragmented and the kernel is shuffling pages to "
               "build contiguous blocks (huge pages, DMA buffers). Common after "
               "days of uptime with a large page cache.",
        "look_at": "transparent huge pages (khugepaged) and long-running "
                   "allocators; dropping caches or a reboot defragments it",
        "symptom_of": "memory"}),
    (re.compile(r"^khugepaged$"), {
        "role": "huge-page collapsing",
        "why": "Transparent huge pages are being assembled in the background. "
               "Sustained activity costs CPU and can cause latency spikes for "
               "databases.",
        "look_at": "/sys/kernel/mm/transparent_hugepage/enabled (databases "
                   "usually want madvise or never)",
        "symptom_of": None}),
    (re.compile(r"^ksmd$"), {
        "role": "same-page merging",
        "why": "KSM is scanning memory for identical pages to share, usually "
               "for virtual machines. It trades CPU for RAM.",
        "look_at": "/sys/kernel/mm/ksm/ (pages_to_scan, sleep_millisecs)",
        "symptom_of": None}),
    (re.compile(r"^oom_reaper$"), {
        "role": "OOM victim cleanup",
        "why": "The kernel is tearing down the memory of a process the OOM "
               "killer just chose.",
        "look_at": "the Events view for which process was killed",
        "symptom_of": "memory"}),
    (re.compile(r"^jbd2/(?P<dev>.+)-\d+$"), {
        "role": "ext4 journal commit for {dev}",
        "why": "The filesystem journal on {dev} is committing transactions. It "
               "is busy because processes are writing or fsync-ing on that "
               "filesystem: metadata-heavy work (many small files, databases) "
               "drives it hardest.",
        "look_at": "the processes writing to {dev}; mount options "
                   "(commit=, data=) shape how often it runs",
        "symptom_of": "disk"}),
    (re.compile(r"^ext4-rsv-conver"), {
        "role": "ext4 extent conversion",
        "why": "Unwritten extents from preallocation are being converted after "
               "writes -- normal for files created with fallocate.",
        "look_at": "the writers on that filesystem", "symptom_of": "disk"}),
    (re.compile(r"^xfsaild/(?P<dev>.+)$"), {
        "role": "XFS log push for {dev}",
        "why": "XFS is pushing its in-memory log to disk for {dev}, driven by "
               "the write and metadata load on that filesystem.",
        "look_at": "the writers on {dev}", "symptom_of": "disk"}),
    (re.compile(r"^btrfs-(cleaner|transaction)"), {
        "role": "btrfs housekeeping",
        "why": "btrfs is committing transactions or cleaning deleted subvolumes "
               "and snapshots. Deleting a large snapshot keeps this busy for a "
               "long time.",
        "look_at": "recent snapshot deletions; btrfs balance / scrub status",
        "symptom_of": "disk"}),
    (re.compile(r"^(z_|zvol|txg_sync|arc_(reclaim|prune|evict)|l2arc_feed|dbuf_evict|spl_)"), {
        "role": "ZFS",
        "why": "ZFS pipeline work: transaction group syncs, ARC eviction, "
               "compression and checksumming happen in these threads, so they "
               "carry the CPU cost of every write to the pool.",
        "look_at": "zpool iostat, the ARC size against RAM, and the pool's "
                   "writers",
        "symptom_of": "disk"}),
    (re.compile(r"^md\d+_(resync|recovery|reshape|check)$"), {
        "role": "RAID rebuild",
        "why": "A software-RAID array is resyncing, checking or reshaping. It "
               "reads and writes every member disk and will keep storage busy "
               "until it finishes.",
        "look_at": "/proc/mdstat for progress; "
                   "/proc/sys/dev/raid/speed_limit_max to throttle it",
        "symptom_of": None}),
    (re.compile(r"^md\d+_raid\d+$"), {
        "role": "RAID parity",
        "why": "The software-RAID thread computing parity and dispatching IO to "
               "member disks. Busy on every write to a RAID-5/6 array; very "
               "busy during a rebuild.",
        "look_at": "/proc/mdstat, and the writers to the array",
        "symptom_of": "disk"}),
    (re.compile(r"^(kcryptd|kcryptd_io|dmcrypt_write)"), {
        "role": "disk encryption (dm-crypt)",
        "why": "Every block written to or read from an encrypted volume is "
               "encrypted here. This is the CPU price of LUKS, charged to the "
               "kernel rather than to the process doing the IO.",
        "look_at": "the processes doing the disk IO; AES-NI support "
                   "(cpuinfo flag aes) makes a large difference",
        "symptom_of": "disk"}),
    (re.compile(r"^dm-|^kdmflush|^kcopyd|^dm_bufio"), {
        "role": "device-mapper",
        "why": "LVM / thin-pool / snapshot work: copying blocks for snapshots "
               "or thin provisioning. Snapshots of busy volumes cost a copy per "
               "first write.",
        "look_at": "lvs for snapshot usage and thin-pool fullness",
        "symptom_of": "disk"}),
    (re.compile(r"^loop\d+$"), {
        "role": "loop device backing IO",
        "why": "IO to a loop-mounted image (snap packages, ISO mounts, disk "
               "images) is served by this thread from the backing file.",
        "look_at": "losetup -a for which file; snap refreshes are a common "
                   "source",
        "symptom_of": "disk"}),
    (re.compile(r"^scsi_eh_\d+$"), {
        "role": "SCSI error handler",
        "why": "The SCSI layer is recovering a device that stopped answering: "
               "aborting commands, resetting the device or the bus. Anything "
               "active here means a disk, controller or cable is failing or "
               "timing out.",
        "look_at": "dmesg / the Events view for the failing device (I/O error, "
                   "task abort, reset); SMART data for the disk",
        "symptom_of": None}),
    (re.compile(r"^usb-storage"), {
        "role": "USB storage",
        "why": "IO to a USB disk is serviced here; USB 2 tops out around "
               "35 MB/s and stalls everything queued behind it.",
        "look_at": "the processes writing to the USB device", "symptom_of": "disk"}),
    (re.compile(r"^nfsd$|^nfsd\d*$|^lockd$"), {
        "role": "NFS server",
        "why": "This machine is serving NFS clients; the work is theirs, not a "
               "local process's.",
        "look_at": "the clients (nfsstat -s); their IO lands on this box's disks",
        "symptom_of": None}),
    (re.compile(r"^(rpciod|nfsiod|xprtiod)"), {
        "role": "NFS client",
        "why": "RPC transport for NFS mounts on this machine. Busy during heavy "
               "traffic to a file server; stuck when the server is not "
               "answering.",
        "look_at": "the processes using the NFS mounts, and the server",
        "symptom_of": None}),
    (re.compile(r"^cifs"), {
        "role": "SMB/CIFS client",
        "why": "Transport for SMB mounts. Busy on heavy traffic, stuck when the "
               "file server stops answering.",
        "look_at": "the processes using the SMB mounts, and the server",
        "symptom_of": None}),
    (re.compile(r"^ksoftirqd/(?P<core>\d+)$"), {
        "role": "softirq handling on core {core}",
        "why": "Deferred interrupt work (network receive/transmit, block "
               "completions, timers) overflowed into this thread on core "
               "{core}. High use means a device's interrupts are landing on "
               "one core faster than it can drain them -- typically a busy "
               "NIC without receive-side scaling.",
        "look_at": "/proc/interrupts for the device on core {core}; irqbalance, "
                   "RSS/RPS, or moving that IRQ's affinity",
        "symptom_of": None}),
    (re.compile(r"^irq/\d+-(?P<dev>.+)$"), {
        "role": "interrupt thread for {dev}",
        "why": "A threaded interrupt handler for {dev}. Busy means the device "
               "is interrupting at a high rate.",
        "look_at": "the driver for {dev}; its interrupt rate in "
                   "/proc/interrupts",
        "symptom_of": None}),
    (re.compile(r"^migration/(?P<core>\d+)$"), {
        "role": "task migration on core {core}",
        "why": "Moves tasks between cores for load balancing and CPU hotplug. "
               "Noticeable use points at constant rebalancing (many threads, "
               "cpuset changes) or a stop-machine storm.",
        "look_at": "processes with very many runnable threads", "symptom_of": "cpu"}),
    (re.compile(r"^rcu[_c]|^rcub|^rcuog|^rcuop"), {
        "role": "RCU callbacks",
        "why": "Read-copy-update grace periods and callbacks: memory freed by "
               "the kernel is reclaimed here. Busy after mass frees (closing "
               "many files, exiting large processes).",
        "look_at": "processes churning file descriptors or threads",
        "symptom_of": None}),
    (re.compile(r"^kworker/[u]?\d+:\d+[+-]flush-(?P<dev>[\d:]+)$"), {
        "role": "writeback for device {dev}",
        "why": "Dirty page cache is being flushed to the block device with "
               "major:minor {dev}. Busy because something wrote a lot recently; "
               "this thread is the write reaching the disk, later than the "
               "process that did it.",
        "look_at": "the processes with the highest write rate; "
                   "vm.dirty_ratio / dirty_background_ratio",
        "symptom_of": "disk"}),
    (re.compile(r"^kworker/[u]?\d+:\d+[+-](?P<wq>events_unbound|events|events_highpri|events_long|events_freezable|mm_percpu_wq)$"), {
        "role": "generic kernel work ({wq})",
        "why": "General-purpose deferred work: driver housekeeping, timers, "
               "memory accounting flushes. Its name does not say which "
               "subsystem queued it.",
        "look_at": "perf top or /sys/kernel/debug/tracing (workqueue events) "
                   "to see which work items run",
        "symptom_of": None}),
    (re.compile(r"^kworker/[u]?\d+:\d+[+-](?P<wq>kblockd|nvme-wq|nvme-delete-wq|scsi_tmf_\d+|blkcg_punt_bio)$"), {
        "role": "block layer work ({wq})",
        "why": "Block-device completion and plumbing work for the storage "
               "stack: NVMe/SCSI command completions and requeues.",
        "look_at": "disk latency and the processes doing the IO",
        "symptom_of": "disk"}),
    (re.compile(r"^kworker/[u]?\d+:\d+[+-](?P<wq>xfs-[\w-]+|ext4-[\w-]+|btrfs-[\w-]+|dio/[\w:]+)$"), {
        "role": "filesystem work ({wq})",
        "why": "Filesystem background work (log, conversion, discard, direct "
               "IO completion) for {wq}.",
        "look_at": "the processes writing to that filesystem", "symptom_of": "disk"}),
    (re.compile(r"^kworker/[u]?\d+:\d+[+-](?P<wq>.+)$"), {
        "role": "kernel work: {wq}",
        "why": "A kernel workqueue thread currently running work for {wq}.",
        "look_at": "the subsystem named in the workqueue", "symptom_of": None}),
    (re.compile(r"^kworker/R-(?P<wq>.+)$"), {
        "role": "rescuer for {wq}",
        "why": "The emergency worker for the {wq} workqueue, used only when the "
               "kernel cannot create workers -- itself a sign of memory "
               "pressure.",
        "look_at": "memory pressure", "symptom_of": "memory"}),
    (re.compile(r"^kworker/"), {
        "role": "idle kernel worker",
        "why": "A kernel workqueue thread between work items. It shows what it "
               "last ran after the dash in its name.",
        "look_at": "nothing -- it is idle", "symptom_of": None}),
    (re.compile(r"^vhost-\d+$"), {
        "role": "virtio backend for a VM",
        "why": "Network or disk IO for a KVM guest is handled here on the host's "
               "behalf; the guest's traffic is the cause.",
        "look_at": "the VM whose QEMU process has this thread's PID as parent",
        "symptom_of": None}),
    (re.compile(r"^kvm-"), {
        "role": "KVM housekeeping",
        "why": "Hypervisor-side work for the virtual machines on this host.",
        "look_at": "the VMs (qemu processes)", "symptom_of": None}),
    (re.compile(r"^kauditd$"), {
        "role": "audit log writer",
        "why": "Audit records are being written; a chatty audit rule set makes "
               "this a constant cost.",
        "look_at": "auditctl -l for the rules generating events", "symptom_of": None}),
    (re.compile(r"^khungtaskd$|^watchdog/\d+$|^kthreadd$|^kdevtmpfs$|^psimon"), {
        "role": "kernel housekeeping",
        "why": "Watchdogs, thread spawning and the PSI monitor; negligible by "
               "design.",
        "look_at": "nothing unless it is stuck", "symptom_of": None}),
    (re.compile(r"^zswap|^kzswap"), {
        "role": "compressed swap",
        "why": "Pages are being compressed into or out of the zswap pool -- "
               "cheaper than disk swap, but it is still swapping.",
        "look_at": "memory pressure and the largest resident processes",
        "symptom_of": "memory"}),
]


def explain(name: str) -> dict[str, object] | None:
    """A kernel thread's job in one sentence, or None for an unknown name."""
    for pattern, template in _EXPLAIN:
        match = pattern.match(name)
        if not match:
            continue
        groups = {k: v for k, v in match.groupdict().items() if v is not None}
        out: dict[str, object] = {}
        for key, value in template.items():
            out[key] = value.format(**groups) if isinstance(value, str) else value
        return out
    return None


# ------------------------------------------------------------------ mdstat
_MD_HEADER = re.compile(r"^(?P<name>md\d+)\s*:\s*(?P<state>\w+)\s+(?:\((?P<flags>[^)]*)\)\s+)?(?P<level>\S+)\s+(?P<devs>.*)$")
_MD_MEMBER = re.compile(r"^(?P<dev>[\w/-]+)\[(?P<slot>\d+)\](?P<flags>(?:\([A-Z]\))*)")
_MD_SYNC = re.compile(
    r"(?P<op>resync|recovery|reshape|check|repair)\s*=\s*(?P<pct>[\d.]+)%"
    r"(?:\s*\((?P<done>\d+)/(?P<total>\d+)\))?"
    r"(?:.*?finish=(?P<finish>[\d.]+)min)?(?:.*?speed=(?P<speed>\d+)K/sec)?")
_MD_STATUS = re.compile(r"\[(?P<n>\d+)/(?P<ok>\d+)\]\s+\[(?P<map>[U_]+)\]")


def parse_mdstat(text: str) -> list[dict[str, object]]:
    """Software-RAID arrays with their sync operation, if one is running."""
    arrays: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in text.splitlines():
        header = _MD_HEADER.match(line)
        if header:
            members = []
            failed = 0
            for token in header.group("devs").split():
                member = _MD_MEMBER.match(token)
                if member:
                    members.append(member.group("dev"))
                    if "(F)" in member.group("flags"):
                        failed += 1
            current = {
                "name": header.group("name"), "state": header.group("state"),
                "level": header.group("level"), "members": members,
                "failed_members": failed, "degraded": False, "sync": None,
                "readonly": "read-only" in (header.group("flags") or ""),
            }
            arrays.append(current)
            continue
        if current is None:
            continue
        status = _MD_STATUS.search(line)
        if status:
            current["degraded"] = "_" in status.group("map")
            current["members_expected"] = int(status.group("n"))
            current["members_active"] = int(status.group("ok"))
        sync = _MD_SYNC.search(line)
        if sync:
            finish = sync.group("finish")
            speed = sync.group("speed")
            current["sync"] = {
                "op": sync.group("op"),
                "percent": float(sync.group("pct")),
                "finish_minutes": float(finish) if finish else None,
                "speed_kb_sec": int(speed) if speed else None,
            }
    return arrays


# -------------------------------------------------------------- interrupts
def _parse_counts(text: str, name_from: str) -> tuple[int, dict[str, tuple[str, list[int]]]]:
    """/proc/interrupts or /proc/softirqs -> (cores, {id: (label, per-core)})."""
    lines = text.splitlines()
    if not lines:
        return 0, {}
    cores = len(lines[0].split())
    out: dict[str, tuple[str, list[int]]] = {}
    for line in lines[1:]:
        head, sep, rest = line.partition(":")
        if not sep:
            continue
        ident = head.strip()
        fields = rest.split()
        counts: list[int] = []
        for field in fields[:cores]:
            try:
                counts.append(int(field))
            except ValueError:
                break
        if len(counts) != cores:
            continue    # ERR / MIS rows carry a single total
        if name_from == "tail":
            # The device name is the last token(s); the chip / trigger type
            # precede it. "PCI-MSI ... 0-edge  virtio0-input.0" -> device.
            tail = fields[cores:]
            label = tail[-1] if tail else ident
            # A name can carry spaces ("uhci_hcd:usb1, i801_smbus"); keep
            # everything after the trigger-type token.
            for index, token in enumerate(tail):
                if token.endswith(("-edge", "-fasteoi", "-level")) or token.endswith("edge") \
                        or token.endswith("fasteoi") or token.endswith("level"):
                    if index + 1 < len(tail):
                        label = " ".join(tail[index + 1:])
                    break
        else:
            label = ident
        out[ident] = (label, counts)
    return cores, out


class KernelCollector:
    """mdstat state and per-core interrupt / softirq rates."""

    def __init__(self) -> None:
        self._prev_irq: tuple[float, dict[str, tuple[str, list[int]]]] | None = None
        self._prev_soft: tuple[float, dict[str, tuple[str, list[int]]]] | None = None

    def sample(self) -> dict[str, object]:
        started = time.perf_counter()
        out: dict[str, object] = {
            "available": True, "reason": None,
            "mdstat": self._mdstat(),
            "irq": self._interrupts(),
        }
        out["sample_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return out

    def _mdstat(self) -> dict[str, object]:
        text = linux.read_text("/proc/mdstat")
        if text is None:
            return {"available": False, "reason": "/proc/mdstat not readable "
                    "(no md module loaded)", "arrays": []}
        arrays = parse_mdstat(text)
        return {"available": True, "reason": None, "arrays": arrays,
                "syncing": [a for a in arrays if a.get("sync")]}

    def _interrupts(self) -> dict[str, object]:
        now = time.monotonic()
        irq_text = linux.read_text("/proc/interrupts")
        soft_text = linux.read_text("/proc/softirqs")
        if not irq_text or not soft_text:
            return {"available": False,
                    "reason": "/proc/interrupts or /proc/softirqs not readable"}
        cores, irqs = _parse_counts(irq_text, "tail")
        _, softs = _parse_counts(soft_text, "head")
        prev_irq, prev_soft = self._prev_irq, self._prev_soft
        self._prev_irq, self._prev_soft = (now, irqs), (now, softs)
        if prev_irq is None or prev_soft is None or now - prev_irq[0] <= 0:
            return {"available": True, "reason": None, "cores": [],
                    "top": [], "warming": True}
        dt = now - prev_irq[0]

        per_core: list[dict[str, object]] = []
        machine_top: dict[str, dict[str, object]] = {}
        for core in range(cores):
            best: list[tuple[float, str, str]] = []
            total = 0.0
            for ident, (label, counts) in irqs.items():
                if not ident.isdigit():
                    # LOC / CAL / RES / TLB: the architecture's own ticks and
                    # IPIs, never a device -- they would top every core.
                    continue
                old = prev_irq[1].get(ident)
                if not old or len(old[1]) <= core:
                    continue
                rate = max(0.0, (counts[core] - old[1][core]) / dt)
                if rate <= 0:
                    continue
                total += rate
                best.append((rate, ident, label))
                entry = machine_top.setdefault(ident, {"irq": ident, "name": label, "rate": 0.0})
                entry["rate"] = float(entry["rate"]) + rate
            best.sort(reverse=True)
            soft_best: tuple[float, str] | None = None
            for ident, (label, counts) in softs.items():
                old = prev_soft[1].get(ident)
                if not old or len(old[1]) <= core:
                    continue
                rate = max(0.0, (counts[core] - old[1][core]) / dt)
                if ident == "TIMER" or ident == "SCHED" or ident == "RCU":
                    continue    # background ticks, never the story
                if soft_best is None or rate > soft_best[0]:
                    soft_best = (rate, ident)
            per_core.append({
                "core": core,
                "irq_rate": round(total),
                "top": [{"irq": ident, "name": label, "rate": round(rate)}
                        for rate, ident, label in best[:3]],
                "softirq": ({"name": soft_best[1], "rate": round(soft_best[0])}
                            if soft_best and soft_best[0] > 0 else None),
            })
        top = sorted(machine_top.values(), key=lambda e: -float(e["rate"]))[:8]
        for entry in top:
            entry["rate"] = round(float(entry["rate"]))
        return {"available": True, "reason": None, "cores": per_core, "top": top,
                "warming": False}
