"""The agent: a report-only culprit node.

Runs the exact same collectors and sampler as the host -- same tiers, same
payload shapes, same honesty rules -- but instead of serving a dashboard it
pushes its snapshot to the host node over HTTPS/HTTP with a bearer token.
No FastAPI, no uvicorn, no SQLite: the runtime dependency is psutil plus the
standard library, which is what makes an agent cheap to drop on many servers.

    python -m culprit.agent --host https://hub:8787 --token <name>.<secret>

The first run writes agent.json to the running user's config directory
(~/.config/culprit-agent/agent.json, chmod 600 -- it holds the token); after
that a bare `python -m culprit.agent` is enough, which is what the systemd
unit runs. Nothing is written into the checkout.

Push, not pull, on purpose: an agent only needs *outbound* reachability to the
host, so nothing new listens on the monitored servers and NAT/firewalls in the
wrong direction cost nothing. Reports are gzipped (a full snapshot compresses
roughly 10x) and failures are retried with backoff -- the agent never dies
because the host is temporarily away; it keeps sampling and reports again.
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import logging
import os
import shutil
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from . import config as config_module
from . import updater
from .collectors import forensics
from .collectors import recorder as recorder_mod
from .db import History
from .sampler import Sampler
from .state import Broker, Store

log = logging.getLogger("culprit.agent")


# ------------------------------------------------------------------ paths
# Nothing the agent writes lives in the checkout, so `git pull` (and the
# self-update, which is a git reset) keeps working. The config and the
# flight recorder live in the running account's profile:
#
#   config     %APPDATA%\culprit-agent\agent.json
#   recorder   %LOCALAPPDATA%\culprit-agent\flight-recorder.json.gz
#
# A scheduled task running as SYSTEM has a profile too (under
# C:\Windows\System32\config\systemprofile), but agent.ps1 installs that task
# with explicit --config / --data arguments pointing at %ProgramData%, so the
# installer (run by an administrator) and the task (run as SYSTEM) agree on
# the same files. CULPRIT_AGENT_CONFIG / CULPRIT_AGENT_DATA override either
# for the Linux-style environment route.
_CLI_CONFIG: Path | None = None
_CLI_DATA: Path | None = None


def _profile(var: str, fallback: str) -> Path:
    base = os.environ.get(var)
    if base:
        return Path(base)
    return Path.home() / fallback


def config_path() -> Path:
    if _CLI_CONFIG is not None:
        return _CLI_CONFIG
    override = os.environ.get("CULPRIT_AGENT_CONFIG")
    if override:
        return Path(override)
    return _profile("APPDATA", "AppData/Roaming") / "culprit-agent" / "agent.json"


def data_dir() -> Path:
    if _CLI_DATA is not None:
        return _CLI_DATA
    override = os.environ.get("CULPRIT_AGENT_DATA")
    if override:
        return Path(override)
    return _profile("LOCALAPPDATA", "AppData/Local") / "culprit-agent"


CONFIG_PATH = config_path()
# The flight recorder: the last ten minutes, rewritten every few seconds, so
# the next start can say how the previous run ended (see collectors/recorder.py).
RECORDER_PATH = data_dir() / "flight-recorder.json.gz"
# Where earlier versions kept them, inside the checkout: moved on first sight.
LEGACY_CONFIG_PATH = config_module.ROOT / "agent.json"
LEGACY_RECORDER_PATH = config_module.ROOT / "data" / "flight-recorder.json.gz"


def _migrate(legacy: Path, target: Path, mode: int) -> None:
    """Move a file an earlier version wrote into the checkout to its XDG
    home, once. A copy that cannot be removed (root-owned, we are not) is
    left behind and named; the new location wins from then on."""
    if target.exists() or not legacy.exists():
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(legacy, target)
        os.chmod(target, mode)
    except OSError as exc:
        log.warning("could not move %s to %s: %s", legacy, target, exc)
        return
    try:
        legacy.unlink()
        log.info("moved %s to %s", legacy, target)
    except OSError:
        log.warning("moved %s to %s but could not remove the old copy (owned by "
                    "someone else?); delete it by hand", legacy, target)

_DEFAULTS = {
    "host_url": "",            # e.g. https://hub.example:8787
    "token": "",               # <name>.<secret>, from the host's Nodes view
    "report_interval": 1.0,    # seconds between pushes
    "verify_tls": True,        # False only for self-signed certs you accept
}

# Big sections that change on their own slower cadence. Each is resent only
# when its content object actually changed (the sampler replaces the object
# per tick, so identity is the cheap and exact change test) -- a 1s report
# cadence therefore costs a few KB per second, not the whole snapshot.
_DELTA_SECTIONS = ("process_table", "diagnosis", "services", "volumes",
                   "network_detail", "ports", "sync", "events", "system",
                   "cgroups", "kernel", "changes", "ceilings", "outage")
# A full snapshot goes out anyway on this period, so drift (like the mutated
# uptime inside the cached `system` section) never outlives a minute.
_FULL_SYNC_S = 60.0


def migrate_legacy_files() -> None:
    """Move whatever an earlier version left in the checkout (agent.json and
    the flight recorder) to their XDG homes. Called at every start and by
    agent.sh, so the checkout ends up clean whichever runs first."""
    _migrate(LEGACY_CONFIG_PATH, CONFIG_PATH, 0o600)
    _migrate(LEGACY_RECORDER_PATH, RECORDER_PATH, 0o600)


def load_agent_config(path: Path | None = None) -> dict:
    cfg = dict(_DEFAULTS)
    path = path or CONFIG_PATH
    if path == CONFIG_PATH:
        _migrate(LEGACY_CONFIG_PATH, path, 0o600)
    if path.exists():
        try:
            cfg.update({k: v for k, v in json.loads(path.read_text()).items()
                        if k in _DEFAULTS})
        except (OSError, ValueError) as exc:
            log.error("could not read %s: %s", path, exc)
    return cfg


def save_agent_config(cfg: dict, path: Path | None = None) -> None:
    path = path or CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    # The token lives in here. chmod is a no-op for NTFS ACLs; the file
    # inherits the profile folder's ACL (the user, SYSTEM and Administrators),
    # and agent.ps1 tightens %ProgramData%\culprit-agent the same way.
    os.chmod(path, 0o600)


class Reporter:
    _CAPABILITY_RECHECK_S = 300.0

    def __init__(self, store: Store, cfg: dict) -> None:
        self.store = store
        self.url = cfg["host_url"].rstrip("/") + "/api/agents/report"
        self.token = cfg["token"]
        self.interval = max(0.5, float(cfg["report_interval"]))
        self.node_name = self.token.partition(".")[0]
        self._context: ssl.SSLContext | None = None
        if self.url.startswith("https") and not cfg.get("verify_tls", True):
            self._context = ssl.create_default_context()
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE
            log.warning("TLS verification disabled -- the host's identity is "
                        "not being checked")
        self.consecutive_failures = 0
        self._sent_ids: dict[str, int] = {}   # section -> id() last delivered
        self._full_next = True
        self._last_full = 0.0
        # Set after the sampler starts; the process collector the host's
        # relayed commands run against.
        self.proc = None
        # Self-update capability: recomputed on a slow cadence (see push()),
        # never on every report. Whether an update is *available* is not
        # this agent's call -- the host compares this agent's reported
        # `version` against GitHub once for the whole fleet (NodeRegistry.
        # refresh_remote_version). Set from run_agent() once the event loop
        # exists, so a completed "update" command can ask for a clean
        # restart from the executor thread it actually runs in.
        self._update_capable: bool | None = None
        self._update_reason: str | None = None
        self._last_capability_check = 0.0
        self._restart_after_post = False
        self.loop = None
        self.stopping = None

    def _build_snapshot(self) -> dict:
        """Full snapshot, or just the sections that changed since the last
        report the host acknowledged."""
        snapshot = self.store.snapshot()
        now = time.monotonic()
        if self._full_next or now - self._last_full >= _FULL_SYNC_S:
            self._last_full = now
            self._pending_ids = {key: id(snapshot.get(key))
                                 for key in _DELTA_SECTIONS}
            return snapshot
        for key in _DELTA_SECTIONS:
            section = snapshot.get(key)
            if id(section) == self._sent_ids.get(key):
                snapshot.pop(key, None)
        self._pending_ids = {key: id(self.store.get(key))
                             for key in _DELTA_SECTIONS}
        return snapshot

    def _post(self, payload: dict) -> dict | None:
        """Gzip-POST one payload to the host, returning the parsed reply or
        None on failure. Never raises."""
        body = gzip.compress(
            json.dumps(payload, default=_json_fallback,
                       separators=(",", ":")).encode())
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            })
        with urllib.request.urlopen(request, timeout=15,
                                    context=self._context) as response:
            return json.loads(response.read() or b"{}")

    def _refresh_update_state(self) -> None:
        """Recomputed every _CAPABILITY_RECHECK_S, not every report: a fresh
        install reports it immediately (_last_capability_check starts at 0),
        after that a git-status check every few minutes is plenty for a
        schedule/button that fires at most a few times a day. Whether an
        update is *available* is not computed here -- the host checks
        GitHub once for the whole fleet instead of once per agent."""
        now = time.monotonic()
        if now - self._last_capability_check < self._CAPABILITY_RECHECK_S:
            return
        self._last_capability_check = now
        self._update_capable, self._update_reason = updater.capability()

    def push(self) -> bool:
        """One report. Runs in a thread (urllib blocks)."""
        self._refresh_update_state()
        payload = {
            "agent": {
                "name": self.node_name,
                "version": __version__,
                # Which agent this is. The host picks the version feed, the
                # Patch notes mirror and the dashboard's vocabulary by it;
                # an old host ignores the key.
                "platform": "windows",
                "report_interval": self.interval,
                "interval_fast": config_module.get().interval_fast,
                "update_capable": self._update_capable,
                "update_reason": self._update_reason,
                # This build takes a `ref` on the update command (a version
                # change, usually a downgrade); the host refuses to send one
                # to an agent that has not said so.
                "update_refs": updater.SUPPORTS_REF,
                # The branch this checkout is on, so the host can tell an
                # agent on the wrong line from one that is merely behind. Read
                # from .git/HEAD on every report (a file read, not git), so a
                # checkout done by hand is seen with the next report instead
                # of at the next capability check minutes later.
                "update_branch": updater.head_branch(),
            },
            "snapshot": self._build_snapshot(),
        }
        try:
            reply = self._post(payload) or {}
            if self.consecutive_failures:
                log.info("host reachable again after %d failed report(s)",
                         self.consecutive_failures)
            self.consecutive_failures = 0
            # Delivered: what we just sent is what the host now has.
            self._sent_ids.update(self._pending_ids)
            if payload["snapshot"].get("coroner") is not None:
                # A death report is delivered once; the host stored it. (An
                # old host drops the unknown section -- also once.)
                self.store.put("coroner", None)
            # A host that does not know this node (fresh start, restarted)
            # holds a partial merge at best -- resend everything next time.
            self._full_next = not reply.get("known", True)
            self._apply_settings(reply.get("settings") or {})
            self._run_commands(reply.get("commands") or [])
            return True
        except urllib.error.HTTPError as exc:
            self.consecutive_failures += 1
            if exc.code in (401, 403):
                # An invalid token will not fix itself; still keep trying at a
                # slow crawl in case the token gets (re-)enrolled host-side.
                log.error("host rejected the token (%s) -- re-enroll this "
                          "agent on the host: culprit agents add %s",
                          exc.code, self.node_name)
            else:
                log.warning("report failed: HTTP %s", exc.code)
            return False
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            self.consecutive_failures += 1
            if self.consecutive_failures in (1, 5) or \
                    self.consecutive_failures % 60 == 0:
                log.warning("host unreachable (%s attempt(s)): %s",
                            self.consecutive_failures, exc)
            return False

    def _run_commands(self, commands: list) -> None:
        """Execute commands the host relayed and post the results back at once.

        Same collector code the host runs on itself -- process detail via the
        live ProcessCollector, End task / renice via the module functions,
        which enforce the critical-process guards and honour this agent's own
        allow_process_actions config. Results go back immediately in a
        results-only report, so a command round-trips in about one report
        interval rather than waiting for the next scheduled push.
        """
        if not commands:
            return
        results = [self._execute(command) for command in commands]
        try:
            self._post({
                "agent": {"name": self.node_name, "version": __version__,
                          "report_interval": self.interval},
                "command_results": results,
            })
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            log.warning("could not return %d command result(s): %s",
                        len(results), exc)
        if self._restart_after_post:
            # Fires even if the ack above failed to reach the host: the git
            # reset already landed on disk by this point, so not restarting
            # would strand the process on stale in-memory code -- the next
            # attempt would see "already up to date" and never try again.
            self._restart_after_post = False
            log.warning("update applied; restarting for the new code to take effect")
            if self.loop is not None and self.stopping is not None:
                self.loop.call_soon_threadsafe(self.stopping.set)

    def _execute(self, command: dict) -> dict:
        from .collectors import processes as proc_mod

        cmd_id = command.get("id")
        action = command.get("action")
        try:
            if action == "process_detail":
                if self.proc is None:
                    return _cmd_err(cmd_id, 503, "process collector not ready")
                extras = frozenset(
                    part.strip() for part in (command.get("extras") or "").split(",")
                    if part.strip()) & {"files", "threads"}
                detail = self.proc.detail(int(command["pid"]), extras)
                if detail is None:
                    return _cmd_err(cmd_id, 404, "no such process (it may have exited)")
                return {"id": cmd_id, "ok": True, "result": detail}

            if action in ("terminate", "priority", "throttle", "truncate", "unit_action"):
                # One switch for every verb that changes the machine: the
                # name says "process", the meaning is "actions".
                if not config_module.get().allow_process_actions:
                    return _cmd_err(cmd_id, 403,
                                    "process actions are disabled on this agent "
                                    "(allow_process_actions is false)")
                if action == "terminate":
                    outcome = proc_mod.terminate(int(command["pid"]),
                                                 bool(command.get("force")))
                elif action == "throttle":
                    # Caps the process's whole systemd unit / container scope
                    # (CPUQuota + IOWeight, --runtime) -- the reversible
                    # verb between renice and End task.
                    outcome = proc_mod.throttle(int(command["pid"]),
                                                str(command.get("level")))
                elif action == "truncate":
                    # Frees a deleted-but-open file through the holder's own
                    # descriptor; refuses anything that still has a name.
                    outcome = proc_mod.truncate_deleted(int(command["pid"]),
                                                        str(command.get("path") or ""))
                elif action == "unit_action":
                    # The Outage Doctor's verbs: systemctl restart / start /
                    # reload-or-restart / reset-failed, with the same guards
                    # the process actions have and the unit's state before
                    # and after in the answer.
                    from .collectors import units as units_mod
                    outcome = units_mod.act(str(command.get("unit") or ""),
                                            str(command.get("verb") or ""),
                                            str(command.get("manager") or "system"))
                else:
                    outcome = proc_mod.set_priority(int(command["pid"]),
                                                    str(command.get("level")))
                if outcome.get("ok"):
                    return {"id": cmd_id, "ok": True, "result": outcome}
                return _cmd_err(cmd_id, 409, str(outcome.get("reason")))

            if action == "update":
                ref = command.get("ref")
                branch = command.get("branch")
                outcome = updater.perform(cmd_id, str(ref) if ref else None,
                                          str(branch) if branch else None)
                if outcome.get("ok") and outcome.pop("restart", False):
                    self._restart_after_post = True
                return outcome

            return _cmd_err(cmd_id, 400, f"unknown action {action!r}")
        except Exception as exc:  # noqa: BLE001 -- a bad command must not kill the agent
            log.warning("command %s (%s) failed: %s", cmd_id, action, exc)
            return _cmd_err(cmd_id, 500, str(exc))

    def _apply_settings(self, settings: dict) -> None:
        """Overrides the host handed back with its response -- the Refresh
        control on the dashboard lands here. Applied like the host applies its
        own titlebar control: to the running sampler only, never persisted."""
        fast = settings.get("interval_fast")
        if fast is None:
            return
        try:
            fast = float(fast)
        except (TypeError, ValueError):
            return
        changed = False
        if abs(config_module.get().interval_fast - fast) > 1e-9:
            _, errors = config_module.update({"interval_fast": fast},
                                             persist=False)
            if errors:
                log.warning("host asked for interval_fast=%r: %s", fast, errors)
                return
            changed = True
        # Reporting keeps pace with sampling; below 1s the report floor is
        # 0.5s so a 0.5s refresh on the dashboard still means 2 reports/s max.
        desired_report = max(0.5, fast)
        if abs(self.interval - desired_report) > 1e-9:
            self.interval = desired_report
            changed = True
        if changed:
            log.info("host set sampling to %.2gs (reporting every %.2gs)",
                     fast, self.interval)

    @property
    def delay(self) -> float:
        """Backoff: normal cadence while healthy, up to 60s while the host is
        away. Sampling continues regardless -- only the pushing slows down."""
        if self.consecutive_failures == 0:
            return self.interval
        return min(60.0, self.interval * (2 ** min(self.consecutive_failures, 5)))


async def run_agent(cfg: dict) -> int:
    config_module.load()  # collector thresholds; agent has no config.json UI
    store = Store()
    broker = Broker()  # zero subscribers: publish() is a no-op
    history = History(config_module.DEFAULT_DB_PATH, enabled=False)
    # Before anything else: did the previous run end badly? The recording on
    # disk is read before a new recorder overwrites it.
    migrate_legacy_files()
    death = recorder_mod.detect_death(RECORDER_PATH, recorder_mod.boot_id())
    flight = recorder_mod.FlightRecorder(RECORDER_PATH)
    sampler = Sampler(store, broker, history, recorder=flight)
    await sampler.start()

    reporter = Reporter(store, cfg)
    reporter.proc = sampler.proc  # the collector relayed commands run against
    log.info("agent '%s' reporting to %s every %.0fs",
             reporter.node_name, reporter.url, reporter.interval)
    if death is not None:
        log.warning("the previous run ended without a clean stop %.0f s ago "
                    "(%s died); collecting the evidence for the host's Coroner",
                    death["gap_seconds"], "the machine" if death["kind"] == "machine"
                    else "the agent")
        await asyncio.get_running_loop().run_in_executor(
            None, _report_death, store, death)

    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    reporter.loop = loop
    reporter.stopping = stopping
    # asyncio's add_signal_handler is not implemented on Windows, so the
    # plain signal module does the job: Ctrl+C (SIGINT), Ctrl+Break
    # (SIGBREAK) and the console-close / task-end that Windows delivers as
    # SIGTERM to a Python process all set the stopping event from the
    # handler thread -- so the sampler still marks a clean stop and the
    # Coroner never mistakes a routine restart for a death.
    _install_stop_signals(loop, stopping)

    try:
        while not stopping.is_set():
            await loop.run_in_executor(None, reporter.push)
            try:
                await asyncio.wait_for(stopping.wait(), timeout=reporter.delay)
            except asyncio.TimeoutError:
                pass
    finally:
        await sampler.stop()
    log.info("agent stopped")
    return 0


def _install_stop_signals(loop: asyncio.AbstractEventLoop, stopping: asyncio.Event) -> None:
    def _stop(signum, _frame):  # type: ignore[no-untyped-def]
        log.info("stop signal %s received", signum)
        loop.call_soon_threadsafe(stopping.set)

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stopping.set)
            continue
        except (NotImplementedError, RuntimeError, ValueError):
            pass
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="culprit-agent",
        description="Report-only culprit node: samples this machine and "
                    "pushes to a culprit host. No dashboard, no open ports.",
    )
    parser.add_argument("--host", help="host node URL, e.g. https://hub:8787")
    parser.add_argument("--token", help="agent token from `culprit agents add`")
    parser.add_argument("--interval", type=float,
                        help="seconds between reports (default 1)")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify the host's TLS certificate")
    parser.add_argument("--log-level", default="info",
                        choices=("debug", "info", "warning", "error"))
    parser.add_argument("--config", help="path of agent.json (default: "
                        "%%APPDATA%%\\culprit-agent\\agent.json)")
    parser.add_argument("--data", help="directory for the flight recorder "
                        "(default: %%LOCALAPPDATA%%\\culprit-agent)")
    parser.add_argument("--managed", action="store_true",
                        help="started by the scheduled task agent.ps1 installed "
                             "(something restarts it on exit, so remote updates "
                             "are allowed)")
    args = parser.parse_args(argv)

    global CONFIG_PATH, RECORDER_PATH, _CLI_CONFIG, _CLI_DATA
    if args.config:
        _CLI_CONFIG = Path(args.config)
        CONFIG_PATH = _CLI_CONFIG
    if args.data:
        _CLI_DATA = Path(args.data)
        RECORDER_PATH = _CLI_DATA / "flight-recorder.json.gz"
    if args.managed:
        # The updater reads this the way the Linux agent reads systemd's
        # INVOCATION_ID: proof that something brings the process back up.
        os.environ["CULPRIT_AGENT_MANAGED"] = "1"
        os.environ.setdefault("CULPRIT_AGENT_TASK", "culprit-agent")

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = load_agent_config(CONFIG_PATH)
    changed = False
    if args.host:
        cfg["host_url"] = args.host
        changed = True
    if args.token:
        cfg["token"] = args.token
        changed = True
    if args.interval:
        cfg["report_interval"] = args.interval
        changed = True
    if args.insecure:
        cfg["verify_tls"] = False
        changed = True
    if not cfg["host_url"] or not cfg["token"]:
        parser.error("no host/token configured. First run:\n"
                     "  python -m culprit.agent --host <url> --token <token>\n"
                     "(get a token on the host with: "
                     "python -m culprit agents add <name>)")
    if changed:
        save_agent_config(cfg, CONFIG_PATH)
        log.info("saved %s", CONFIG_PATH)

    return asyncio.run(run_agent(cfg))


def _report_death(store: Store, death: dict) -> None:
    """Gather the previous boot's evidence and queue the death for the host.

    Runs in a thread: the journal queries take up to a few hundred ms. The
    `coroner` section is sent with the next report and cleared once the host
    has acknowledged it (Reporter.push), so it costs one report, not every.
    """
    try:
        evidence = forensics.investigate(death)
    except Exception as exc:  # noqa: BLE001 -- a failed investigation is still a death
        log.warning("forensics failed: %s", exc)
        evidence = {"notes": [f"forensics failed: {exc}"], "markers": [], "tail": []}
    system = store.get("system") or {}
    record = {
        **death,
        "id": f"{death.get('prev_boot_id') or 'agent'}:{int(death['died_at'])}",
        "evidence": evidence,
        "agent_version": __version__,
        "hostname": system.get("hostname"),
        "boot_time": system.get("boot_time"),
    }
    store.put("coroner", {"available": True, "deaths": [record]})


def _cmd_err(cmd_id, status, message):  # type: ignore[no-untyped-def]
    return {"id": cmd_id, "ok": False, "status": status, "error": message}


def _json_fallback(value):  # type: ignore[no-untyped-def]
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


if __name__ == "__main__":
    sys.exit(main())
