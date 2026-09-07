"""Runtime configuration.

Defaults live here; `config.json` in the project root overrides them and is
written back by the Settings panel. The file is created on first save rather
than on first run, so a fresh clone has nothing to clean up.
"""

from __future__ import annotations

import json
import logging
import re
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from . import trust

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("culprit.config")

CONFIG_PATH = ROOT / "config.json"
WEB_DIR = ROOT / "web"
DEFAULT_DB_PATH = ROOT / "data" / "culprit.db"


@dataclass
class Config:
    # --- server ---
    host: str = "127.0.0.1"
    port: int = 8787
    open_browser: bool = True

    # --- sampling cadences, in seconds ---
    # Four tiers rather than one loop: polling services or the event log at 1Hz
    # would burn CPU for data that changes on a scale of minutes.
    interval_fast: float = 1.0      # cpu / memory / gpu / disk+net throughput
    interval_proc: float = 2.0      # process table (the expensive one)
    interval_slow: float = 20.0     # services, volumes, adapters, sync
    interval_events: float = 120.0  # journal, crash files, pending reboot

    # --- history ---
    persist_history: bool = True
    retention_days: int = 7
    # One row per rollup_seconds, aggregated from the fast ring buffer.
    rollup_seconds: int = 60
    # Per-rollup, only the N heaviest processes are stored. Keeps the DB small
    # while still answering "what was pinning the CPU at 14:20?".
    history_top_processes: int = 8
    db_path: str = ""  # "" -> DEFAULT_DB_PATH

    # --- in-memory ring buffer (drives the live sparklines) ---
    live_window_seconds: int = 900

    # --- process table ---
    process_count: int = 250
    # Roll child processes up under their parent by image name in the tree view.
    tree_grouping: bool = True

    # --- pressure thresholds -----------------------------------------------
    # These drive the Lag Doctor verdicts. Tuned for a general-purpose laptop;
    # a build server would want cpu_high much closer to 100.
    cpu_high: float = 85.0            # % busy, sustained
    cpu_queue_per_core: float = 1.0   # runnable threads per core before it hurts
    mem_available_low_mb: float = 1024.0
    mem_commit_high: float = 90.0     # % of CommitLimit
    hard_faults_high: float = 500.0   # major faults/sec -- actual disk paging
    disk_queue_high: float = 2.0
    disk_latency_high_ms: float = 25.0
    disk_busy_high: float = 85.0      # % of time the device had IO in flight
    disk_space_low_pct: float = 10.0
    gpu_high: float = 85.0
    # PSI avg10 (% of wall time stalled) that counts as full pressure. These
    # only apply when /proc/pressure exists; otherwise the derived signals
    # above carry the model. 'full' stalls are gated at half these values.
    psi_cpu_high: float = 50.0        # % of time some task waited for a CPU
    psi_memory_high: float = 10.0     # memory stalls hurt much earlier
    psi_io_high: float = 40.0
    # A pressure state must hold for this many consecutive fast ticks before it
    # is reported, so a single 100% spike from opening a menu is not an alert.
    sustain_ticks: int = 5

    # --- lag score weights -------------------------------------------------
    # Relative contribution of each resource to a process's lag score. Values
    # are normalised, so only the ratios matter.
    weight_cpu: float = 1.0
    weight_memory: float = 0.55
    weight_disk: float = 0.85
    weight_gpu: float = 0.6
    weight_faults: float = 0.5
    # Sustained D-state (uninterruptible sleep): the process is being made to
    # wait inside the kernel regardless of what any usage counter says.
    weight_stuck: float = 2.0
    # A window that has stopped pumping messages (Task Manager's "Not
    # responding"): the most direct "you are being made to wait" signal
    # Windows has, and it catches a process frozen at 0% CPU that no usage
    # counter would ever flag. Ungated, like weight_stuck on Linux.
    weight_hung: float = 2.0

    # --- events ---
    event_lookback_days: int = 30
    event_max_per_source: int = 200

    # --- actions ---
    # End-task / priority changes from the UI. On by default because "find what
    # is lagging the system" is only half a job if you cannot then stop it, but
    # every call goes through a confirmation modal and is refused for PID 0/4
    # and the critical-service allowlist. Set false for a read-only install.
    allow_process_actions: bool = True
    # Remote git-pull + restart, gated the same way as allow_process_actions:
    # an agent honours its own copy of this field (hand-edited in its local
    # config.json), so one machine can opt out of remote updates even though
    # it is otherwise capable (systemd, a clean git checkout, not Docker).
    allow_remote_update: bool = True

    # --- agent deployment -------------------------------------------------
    # Shape the deploy command the Nodes view shows for a freshly enrolled or
    # rotated agent. `deploy_host` overrides the address the command tells the
    # agent to report to (blank = the address the dashboard was reached on);
    # `agent_command` is what runs the bundle -- set it to "sudo ./agent.sh" to
    # run the agent as root, which unlocks full port/process attribution.
    deploy_host: str = ""            # e.g. "192.168.1.1:8787" or "https://hub:8787"
    agent_command: str = "./agent.sh"

    # --- agent auto-update (host only) -------------------------------------
    # The host decides *when*; the agent is only ever told "update now" (same
    # CommandBroker channel as a process action), never handed this schedule
    # itself. Fires at most once a day per node, and only for a node whose
    # last report says it is update_capable and update_available.
    auto_update_enabled: bool = False
    auto_update_hour: int = 3        # 0-23, host-local time
    # The branch of the agent repository agents are moved to and measured
    # against: the published version is read from it, Patch notes and the
    # version picker list it, and every update command names it so an agent
    # on another branch switches. "main" is the release line; "dev" follows
    # unreleased work. The repository itself is never configurable here: an
    # agent only ever pulls from its own origin remote.
    agent_update_branch: str = "main"

    # --- network trust ----------------------------------------------------
    # Reverse proxies are refused until declared: a request that carries a
    # forwarding header (X-Forwarded-For, Forwarded, X-Real-IP, ...) from a
    # peer not listed here gets a 400, because honouring the header would let
    # any client pick the address the login limiter keys on, and ignoring it
    # would hide an undeclared proxy (everyone behind it sharing one limiter
    # bucket). IPs or CIDR ranges; `--trust-proxy` adds to this for one run.
    trusted_proxies: list[str] = field(default_factory=list)
    # Host header allow-list. Empty = any Host accepted (a wrong list locks
    # the operator out from the network, so this is opt-in); loopback names
    # always pass so a shell on the machine can fix it. Names, `*.domain`
    # wildcards, or IP literals -- no ports, the port is never compared.
    trusted_hosts: list[str] = field(default_factory=list)

    # --- notifications (host only) ----------------------------------------
    # Only *findings* are ever sent -- diagnoses that survived the sustain
    # window -- never a raw threshold. Empty = channel off. See notify.py.
    notify_ntfy_url: str = ""          # e.g. https://ntfy.sh/my-topic
    notify_webhook_url: str = ""       # any endpoint accepting a JSON POST
    notify_smtp_host: str = ""
    notify_smtp_port: int = 587
    notify_smtp_user: str = ""
    notify_smtp_password: str = ""     # never returned by the API
    notify_smtp_from: str = ""
    notify_smtp_to: str = ""
    notify_smtp_tls: bool = True       # STARTTLS (port 465 uses implicit TLS)
    notify_min_severity: str = "warn"  # "warn" or "critical"
    notify_resolved: bool = True       # send a follow-up when a finding clears
    notify_offline: bool = True        # send when an agent stops reporting

    # --- ui ---
    ui: dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers
    @property
    def resolved_db_path(self) -> Path:
        return Path(self.db_path) if self.db_path else DEFAULT_DB_PATH

    @property
    def effective_port(self) -> int:
        """The port actually bound, which may be a one-off command-line override.

        Kept separate from `self.port` on purpose. An earlier version wrote the
        environment override straight into the dataclass, and since `update()`
        persists the whole object, running `run.ps1 -Port 9000` once and then
        changing any unrelated setting pinned 9000 into config.json for good.
        The file keeps what the user chose; this reports what is in use.
        """
        raw = os.environ.get("CULPRIT_PORT")
        if raw:
            try:
                return int(raw)
            except ValueError:
                pass
        return self.port

    @property
    def effective_host(self) -> str:
        return os.environ.get("CULPRIT_HOST") or self.host

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_lock = threading.Lock()
_current = Config()

# Fields the Settings panel may write. Deliberately excludes host/port/db_path:
# changing those needs a restart, and letting a browser rewrite a filesystem
# path on a monitoring daemon is not a trade worth making.
EDITABLE = {
    "interval_fast", "interval_proc", "interval_slow", "interval_events",
    "persist_history", "retention_days", "history_top_processes",
    "live_window_seconds", "process_count", "tree_grouping",
    "cpu_high", "cpu_queue_per_core", "mem_available_low_mb", "mem_commit_high",
    "hard_faults_high", "disk_queue_high", "disk_latency_high_ms",
    "disk_busy_high", "disk_space_low_pct", "gpu_high", "sustain_ticks",
    "psi_cpu_high", "psi_memory_high", "psi_io_high",
    "weight_cpu", "weight_memory", "weight_disk", "weight_gpu",
    "weight_faults", "weight_stuck", "weight_hung",
    "event_lookback_days", "event_max_per_source",
    "allow_process_actions", "allow_remote_update", "open_browser", "ui",
    "deploy_host", "agent_command",
    "auto_update_enabled", "auto_update_hour", "agent_update_branch",
    "trusted_proxies", "trusted_hosts",
    "notify_ntfy_url", "notify_webhook_url", "notify_smtp_host",
    "notify_smtp_port", "notify_smtp_user", "notify_smtp_password",
    "notify_smtp_from", "notify_smtp_to", "notify_smtp_tls",
    "notify_min_severity", "notify_resolved", "notify_offline",
}

# Text fields with a shape: the validator returns the cleaned value or
# raises ValueError with a message the Settings form shows inline.
def _url_or_empty(value: str) -> str:
    value = value.strip()
    if value and not value.startswith(("http://", "https://")):
        raise ValueError("must start with http:// or https://")
    if len(value) > 512:
        raise ValueError("too long")
    return value


def _severity(value: str) -> str:
    value = value.strip().lower()
    if value not in ("warn", "critical"):
        raise ValueError("expected 'warn' or 'critical'")
    return value


def _short_text(value: str) -> str:
    value = value.strip()
    if len(value) > 256:
        raise ValueError("too long")
    if any(c in value for c in "\r\n"):
        raise ValueError("must be a single line")
    return value


_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


def _branch_name(value: str) -> str:
    """A git branch name: what `git check-ref-format --branch` accepts,
    minus the exotic. It is only ever interpolated into a raw GitHub URL
    and handed to the agent, which checks origin actually has it."""
    if not value:
        raise ValueError("a branch name is required (main is the release line)")
    if not _BRANCH.match(value) or ".." in value or value.endswith(("/", ".", ".lock")) or "//" in value:
        raise ValueError("not a valid branch name")
    return value


TEXT_VALIDATORS: dict[str, Any] = {
    "agent_update_branch": _branch_name,
    "notify_ntfy_url": _url_or_empty,
    "notify_webhook_url": _url_or_empty,
    "notify_min_severity": _severity,
    "notify_smtp_host": _short_text,
    "notify_smtp_user": _short_text,
    "notify_smtp_password": _short_text,
    "notify_smtp_from": _short_text,
    "notify_smtp_to": _short_text,
}

# Lists of text entries, validated by culprit.trust rather than by range.
LIST_FIELDS: dict[str, Any] = {
    "trusted_proxies": trust.clean_proxies,
    "trusted_hosts": trust.parse_hosts,
}

# Accepted ranges for editable numeric fields, used by the API to reject
# nonsense before it reaches the sampler. Inclusive on both ends.
LIMITS: dict[str, tuple[float, float]] = {
    "interval_fast": (0.25, 60.0),
    "interval_proc": (0.5, 120.0),
    "interval_slow": (2.0, 600.0),
    "interval_events": (10.0, 3600.0),
    "retention_days": (1, 365),
    "history_top_processes": (1, 50),
    "live_window_seconds": (60, 86400),
    "process_count": (10, 2000),
    "cpu_high": (10, 100),
    "cpu_queue_per_core": (0.1, 100),
    "mem_available_low_mb": (64, 1_048_576),
    "mem_commit_high": (10, 100),
    "hard_faults_high": (1, 1_000_000),
    "disk_queue_high": (0.1, 1000),
    "disk_latency_high_ms": (1, 10_000),
    "disk_busy_high": (10, 100),
    "disk_space_low_pct": (1, 90),
    "gpu_high": (10, 100),
    "sustain_ticks": (1, 120),
    "psi_cpu_high": (1, 100), "psi_memory_high": (0.5, 100),
    "psi_io_high": (1, 100),
    "weight_cpu": (0, 10), "weight_memory": (0, 10), "weight_disk": (0, 10),
    "weight_gpu": (0, 10), "weight_faults": (0, 10), "weight_stuck": (0, 10), "weight_hung": (0, 10),
    "event_lookback_days": (1, 3650),
    "event_max_per_source": (10, 5000),
    "notify_smtp_port": (1, 65535),
    "auto_update_hour": (0, 23),
}


def get() -> Config:
    return _current


def load() -> Config:
    """Read config.json over the defaults. Unknown/invalid keys are ignored."""
    global _current
    cfg = Config()
    if CONFIG_PATH.exists():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        known = {f.name: f for f in fields(Config)}
        for key, value in (raw or {}).items():
            spec = known.get(key)
            if spec is None:
                continue
            try:
                if spec.type in ("float", float):
                    value = float(value)
                elif spec.type in ("int", int):
                    value = int(value)
                elif spec.type in ("bool", bool):
                    value = bool(value)
                elif spec.type in ("str", str):
                    value = str(value)
                elif key in LIST_FIELDS:
                    value = _load_list(key, value)
            except (TypeError, ValueError):
                continue
            setattr(cfg, key, value)
    # Command-line / environment overrides are deliberately *not* written into
    # the dataclass -- see `effective_port`. Read them via `effective_host` /
    # `effective_port` so a one-off flag never becomes a saved preference.
    with _lock:
        _current = cfg
    return cfg


def _load_list(key: str, value: Any) -> list[str]:
    """A hand-edited config.json may hold anything. Keep the entries that
    parse and log the rest: a dropped proxy entry fails closed (its requests
    are refused, which is visible), a dropped host entry only tightens."""
    entries = trust.split_entries(value)
    kept: list[str] = []
    for entry in entries:
        try:
            LIST_FIELDS[key]([entry])
        except ValueError as exc:
            log.warning("config.json %s: dropping %s", key, exc)
            continue
        kept.append(entry)
    return kept


def _clean_ui(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    if len(value) > 32:
        raise ValueError("too many keys")
    out: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 48 \
                or not all(c.isalnum() or c == "_" for c in key):
            raise ValueError("keys are short identifiers")
        if isinstance(item, bool) or item is None:
            out[key] = item
        elif isinstance(item, (int, float)):
            out[key] = item if abs(item) < 1e12 else 0
        elif isinstance(item, str):
            if len(item) > 64:
                raise ValueError(f"{key}: at most 64 characters")
            out[key] = item
        else:
            raise ValueError(f"{key}: expected a scalar")
    return out


def update(patch: dict[str, Any], persist: bool = True) -> tuple[Config, list[str]]:
    """Apply a patch to the live config, optionally writing it to disk.

    Returns the new config plus a list of human-readable rejections. Invalid
    values are reported rather than silently clamped -- the Settings panel shows
    them inline next to the offending field.

    `persist=False` applies the change to the running sampler and nothing more.
    That is what the title-bar Refresh control uses: it means "show me faster
    right now", not "this is my saved preference". Persisting it there meant one
    mis-click permanently slowed sampling for every future run, with nothing in
    the UI explaining why -- so durable changes belong to the Settings page,
    which is explicit about saving.
    """
    global _current
    errors: list[str] = []
    known = {f.name: f for f in fields(Config)}
    with _lock:
        previous = _current
        cfg = Config(**_current.to_dict())
        for key, value in patch.items():
            if key not in EDITABLE:
                errors.append(f"{key}: not editable at runtime")
                continue
            spec = known[key]
            if key == "ui":
                # Free-form dashboard preferences (container label style,
                # ...). A small flat dict of scalars: it travels in every
                # SSE snapshot frame, so it must not become a dumping ground.
                try:
                    value = _clean_ui(value)
                except ValueError as exc:
                    errors.append(f"ui: {exc}")
                    continue
                setattr(cfg, key, value)
                continue
            if key in LIST_FIELDS:
                try:
                    value = LIST_FIELDS[key](trust.split_entries(value))
                except ValueError as exc:
                    errors.append(f"{key}: {exc}")
                    continue
                setattr(cfg, key, value)
                continue
            try:
                if spec.type in ("bool", bool):
                    value = bool(value)
                elif spec.type in ("int", int):
                    value = int(value)
                elif spec.type in ("float", float):
                    value = float(value)
                elif spec.type in ("str", str):
                    value = str(value).strip()
                    if key in TEXT_VALIDATORS:
                        value = TEXT_VALIDATORS[key](value)
            except (TypeError, ValueError) as exc:
                errors.append(f"{key}: {exc}" if key in TEXT_VALIDATORS
                              else f"{key}: expected a number")
                continue
            if key in LIMITS:
                low, high = LIMITS[key]
                if not (low <= float(value) <= high):
                    errors.append(f"{key}: must be between {low:g} and {high:g}")
                    continue
            setattr(cfg, key, value)
        if not errors:
            changed = {
                key: value for key, value in patch.items()
                if getattr(previous, key, None) != getattr(cfg, key, None)
            }
            _current = cfg
            if not changed:
                return _current, errors
            # Logged either way: both kinds change how the sampler behaves, and
            # without a record a setting that moved by accident is invisible and
            # very confusing later.
            log.info(
                "config %s: %s",
                "updated" if persist else "changed for this session only",
                ", ".join(
                    f"{key}={getattr(previous, key, None)!r}->{value!r}"
                    for key, value in changed.items()
                ),
            )
            if not persist:
                return _current, errors
            try:
                CONFIG_PATH.write_text(
                    json.dumps(cfg.to_dict(), indent=2) + "\n", encoding="utf-8"
                )
            except OSError as exc:
                errors.append(f"could not write config.json: {exc}")
    return _current, errors
