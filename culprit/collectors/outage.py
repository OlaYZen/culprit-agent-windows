"""The Outage Doctor: what is broken, not slow, and why.

Slow and broken are different questions. The Lag Doctor gates on pressure;
this looks at the things that stop a service working while every counter
looks fine, and walks each one to its root:

* a failed unit -- with the dependency that failed first and the first
  error line of the root unit's own journal, quoted
* a unit in a restart loop, with its last error line
* a unit that is running but no longer listens on the port it held
* a TLS listener serving a certificate that has expired or is about to
  (read by connecting to the listener locally, nothing else)
* the clock not synchronised
* DNS resolution failing at the resolver
* a filesystem the kernel remounted read-only (writes fail from then on)
* /boot too full for the next kernel
* storage reporting errors
* a reboot the machine is waiting for

Every item names the unit, the root, the evidence and the fix, carries how
long it has held and what changed just before, and each check reports its
own availability and reason: a source that could not be read is named,
never rendered as "fine". Thresholds are not the point -- a certificate
with eleven days left is information; an expired one on a live listener is
the outage.

Cost is a few subprocesses on the slow tier, each rate-limited: unit
dependency walks only when the failed set changes, TLS handshakes to the
box's own listeners once an hour, timedatectl once a minute.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import ssl
import struct
import time
from typing import Any

from .. import linux
from . import units as units_mod

log = logging.getLogger("culprit.outage")

_SEV = {"info": 1, "warn": 2, "critical": 3}

# Ports whose listeners are expected to speak TLS, so a handshake attempt is
# not noise in someone's log; plus any listener held by a TLS terminator.
_TLS_PORTS = frozenset({443, 8443, 4443, 9443, 10443, 993, 995, 465, 636, 853,
                        5001, 8883, 6514, 2376, 6443, 10250, 3269, 8006, 9200,
                        9443, 5986})
_TLS_TERMINATORS = ("nginx", "apache2", "httpd", "haproxy", "caddy", "traefik",
                    "envoy", "stunnel", "dovecot", "lighttpd", "openresty")
_TLS_REFRESH_S = 3600.0
_TLS_MAX_PORTS = 24
_TIME_REFRESH_S = 60.0
_RESOLVED_REFRESH_S = 300.0
_LISTENER_HOLD_TICKS = 3        # a port must be held this many slow ticks to count
_LISTENER_GONE_TICKS = 2        # and be gone this many before it is an item
_BOOT_MIN_FREE = 150 * 1024 ** 2
_NTP_UNITS = ("chrony", "chronyd", "ntpd", "ntp", "ntpsec", "openntpd",
              "systemd-timesyncd")

_UNIT_PROPS = ("Id,ActiveState,SubState,Result,ConditionResult,ExecMainStatus,"
               "Requires,Requisite,BindsTo,Wants,After,InactiveEnterTimestamp,"
               "Description,Type,RemainAfterExit")


class OutageCollector:
    def __init__(self) -> None:
        self._started = time.time()
        self._since: dict[str, float] = {}
        self._failed_seen: frozenset[str] = frozenset()
        self._failed_at = 0.0
        self._roots: dict[str, dict[str, Any]] = {}
        self._loop_lines: dict[str, dict[str, Any]] = {}
        self._held: dict[tuple[str, int], int] = {}     # (unit, port) -> ticks seen
        self._gone: dict[tuple[str, int], int] = {}     # (unit, port) -> ticks missing
        self._tls: dict[int, dict[str, Any]] = {}
        self._tls_at = 0.0
        self._time: dict[str, Any] | None = None
        self._time_at = 0.0
        self._mounts_base: dict[str, bool] = {}
        self._dns_bad_ticks = 0
        self._resolved_prev: tuple[float, int] | None = None
        self._resolved_rate: float | None = None

    # ----------------------------------------------------------------- sample
    def sample(self, services: dict | None, ports: dict | None, volumes: dict | None,
               events: dict | None, net_detail: dict | None, system: dict | None,
               changes: Any = None) -> dict[str, Any]:
        started = time.perf_counter()
        now = time.time()
        items: list[dict[str, Any]] = []
        checks: dict[str, Any] = {}

        items += self._units(services or {}, checks, now)
        items += self._listeners(services or {}, ports or {}, checks)
        items += self._certificates(ports or {}, system or {}, checks, now)
        items += self._clock(services or {}, checks)
        items += self._dns(net_detail or {}, checks)
        items += self._mounts(volumes or {}, checks)
        items += self._boot(volumes or {}, checks)
        items += self._disk_errors(events or {}, checks, now)
        items += self._reboot(events or {}, checks)

        live = {item["key"] for item in items}
        for key in [k for k in self._since if k not in live]:
            del self._since[key]
        for item in items:
            since = self._since.setdefault(item["key"], now)
            item["since"] = since
            # An item already there on the first sample predates the record:
            # its true start is unknown, and the changes around the agent's
            # own start are startup noise (timedated waking for our query),
            # not what preceded the outage.
            item["since_start"] = since - self._started < 90.0
            item["changes"] = []
            if changes is not None and not item["since_start"]:
                try:
                    item["changes"] = changes.around(since)
                except Exception:  # noqa: BLE001
                    item["changes"] = []
        items.sort(key=lambda i: (-_SEV.get(i["severity"], 0), i["key"]))
        worst = "ok"
        for item in items:
            if _SEV.get(item["severity"], 0) > _SEV.get(worst, 0):
                worst = item["severity"]
        broken = [i for i in items if i["severity"] in ("warn", "critical")]
        return {
            "available": True,
            "reason": None,
            "ts": now,
            "status": "broken" if broken else "ok",
            "severity": worst,
            "items": items,
            "count": len(items),
            "broken": len(broken),
            "checks": checks,
            "sample_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    # ------------------------------------------------------------------ units
    def _units(self, services: dict, checks: dict[str, Any], now: float) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not services.get("available"):
            checks["units"] = {"available": False, "reason": services.get("reason") or "systemd not readable"}
            return out
        problems = [p for p in (services.get("problems") or []) if isinstance(p, dict)]
        failed = [p for p in problems if p.get("status") == "failed"]
        looping = [p for p in problems if p.get("status") != "failed" and int(p.get("restarts") or 0) >= 3]
        stopped = [p for p in problems if p.get("status") != "failed" and int(p.get("restarts") or 0) < 3]
        names = frozenset(str(p["name"]) for p in failed)
        # Dependency walks and journal lines only when the failed set changes
        # (or every ten minutes, in case the root recovered).
        if names != self._failed_seen or now - self._failed_at > 600:
            self._failed_seen, self._failed_at = names, now
            scopes = {str(p["name"]): str(p.get("scope") or "system") for p in failed}
            self._roots = {name: _root_of(name, scopes.get(name, "system")) for name in names}
        for problem in failed:
            name = str(problem["name"])
            root = self._roots.get(name) or {}
            root_name = root.get("root")
            title = f"{name} has failed"
            if root_name and root_name != name:
                title = f"{name} is down because {root_name} failed first"
            line = root.get("line") or {}
            detail = problem.get("detail") or "Unit failed."
            if line.get("message"):
                detail += f" {root_name or name}'s journal: \"{line['message']}\""
            manager = str(problem.get("scope") or "system")
            out.append({
                "key": f"unit_failed:{name}", "kind": "unit", "severity": "critical",
                "title": title, "detail": detail, "unit": name, "manager": manager,
                "root": {"unit": root_name or name, "result": root.get("result") or problem.get("result"),
                         "line": line or None, "chain": root.get("chain") or []},
                "fix": f"journalctl -u {root_name or name} -e; then systemctl restart {root_name or name}"
                       + (f" && systemctl restart {name}" if root_name and root_name != name else ""),
                # The verbs the dashboard may offer for this item, decided
                # here (guards included) so the host renders data, never
                # invents a command for a unit it cannot see.
                "actions": units_mod.offered("unit_failed", name, root_name, manager),
                "evidence": {"result": problem.get("result"), "restarts": problem.get("restarts"),
                             "scope": problem.get("scope")},
            })
        for problem in looping:
            name = str(problem["name"])
            cached = self._loop_lines.get(name)
            if cached is None or now - float(cached.get("at") or 0) > 600:
                cached = {"at": now, "line": _last_error_line(name, str(problem.get("scope") or "system"))}
                self._loop_lines[name] = cached
            line = cached.get("line") or {}
            manager = str(problem.get("scope") or "system")
            out.append({
                "key": f"unit_looping:{name}", "kind": "unit", "severity": "warn",
                "title": f"{name} is crash-looping ({problem.get('restarts')} restarts)",
                "detail": (problem.get("detail") or "")
                          + (f" Last error: \"{line['message']}\"" if line.get("message") else ""),
                "unit": name, "manager": manager,
                "root": {"unit": name, "result": problem.get("result"), "line": line or None, "chain": []},
                "fix": f"journalctl -u {name} -e (the crash output); fix the cause, then systemctl restart {name}",
                "actions": units_mod.offered("unit_looping", name, None, manager),
                "evidence": {"restarts": problem.get("restarts"), "result": problem.get("result")},
            })
        for problem in stopped:
            name = str(problem["name"])
            manager = str(problem.get("scope") or "system")
            out.append({
                "key": f"unit_stopped:{name}", "kind": "unit", "severity": "warn",
                "title": f"{name} is enabled but not running",
                "detail": problem.get("detail") or "", "unit": name, "manager": manager,
                "root": {"unit": name, "result": problem.get("result"), "line": None, "chain": []},
                "fix": f"systemctl start {name}; if it stops again, journalctl -u {name} -e says why",
                "actions": units_mod.offered("unit_stopped", name, None, manager),
                "evidence": {"result": problem.get("result")},
            })
        checks["units"] = {"available": True, "failed": len(failed), "looping": len(looping),
                           "stopped": len(stopped), "total": (services.get("summary") or {}).get("total")}
        return out

    # -------------------------------------------------------------- listeners
    def _listeners(self, services: dict, ports: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not ports.get("available"):
            checks["listeners"] = {"available": False, "reason": ports.get("reason") or "port map not readable"}
            return out
        running = {str(s.get("name")) for s in (services.get("services") or [])
                   if isinstance(s, dict) and s.get("status") == "running"}
        scopes = {str(s.get("name")): str(s.get("scope") or "system")
                  for s in (services.get("services") or []) if isinstance(s, dict)}
        current: set[tuple[str, int]] = set()
        for port in ports.get("ports") or []:
            if not isinstance(port, dict) or "tcp" not in (port.get("protocols") or []):
                continue
            for proc in port.get("processes") or []:
                unit = proc.get("unit") if isinstance(proc, dict) else None
                if unit and str(unit).endswith(".service"):
                    current.add((str(unit), int(port["port"])))
        for key in current:
            self._held[key] = self._held.get(key, 0) + 1
            self._gone.pop(key, None)
        for key in [k for k in self._held if k not in current]:
            unit, port = key
            if unit in running and self._held[key] >= _LISTENER_HOLD_TICKS:
                self._gone[key] = self._gone.get(key, 0) + 1
            else:
                # The unit stopped too (that is a unit item), or the port
                # was never held long enough to be its own.
                del self._held[key]
                self._gone.pop(key, None)
        for (unit, port), ticks in self._gone.items():
            if ticks >= _LISTENER_GONE_TICKS:
                out.append({
                    "key": f"not_listening:{unit}:{port}", "kind": "listener", "severity": "warn",
                    "title": f"{unit} is running but no longer listens on :{port}",
                    "detail": f"The unit is active, but the port it held for the last "
                              f"{self._held.get((unit, port), 0)} samples is no longer bound. Clients get a "
                              "connection refused while systemd still reports the service as running: a "
                              "worker that died inside the unit, a bind that failed on reload, or a listener "
                              "moved to another address.",
                    "unit": unit, "port": port, "manager": scopes.get(unit, "system"),
                    "root": {"unit": unit, "result": None, "line": None, "chain": []},
                    "fix": f"journalctl -u {unit} -e; ss -ltnp | grep :{port}; systemctl reload-or-restart {unit}",
                    "actions": units_mod.offered("not_listening", unit, None, scopes.get(unit, "system")),
                    "evidence": {"port": port, "missing_samples": ticks},
                })
        checks["listeners"] = {"available": True, "tracked": len(self._held), "missing": len(out)}
        return out

    # ----------------------------------------------------------- certificates
    def _certificates(self, ports: dict, system: dict, checks: dict[str, Any],
                      now: float) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not ports.get("available"):
            checks["tls"] = {"available": False, "reason": ports.get("reason") or "port map not readable",
                             "certificates": []}
            return out
        candidates: list[tuple[int, str, str | None, str | None]] = []
        for port in ports.get("ports") or []:
            if not isinstance(port, dict) or "tcp" not in (port.get("protocols") or []):
                continue
            number = int(port.get("port") or 0)
            procs = [p for p in (port.get("processes") or []) if isinstance(p, dict)]
            name = str(procs[0].get("name") or "") if procs else ""
            unit = procs[0].get("unit") if procs else None
            if number in _TLS_PORTS or name.lower().startswith(_TLS_TERMINATORS):
                addresses = [str(a) for a in (port.get("addresses") or [])]
                host = "127.0.0.1"
                if addresses and not any(a in ("0.0.0.0", "::", "*") for a in addresses):
                    host = addresses[0]
                candidates.append((number, host, name or None, unit))
        candidates = candidates[:_TLS_MAX_PORTS]
        if now - self._tls_at > _TLS_REFRESH_S or {c[0] for c in candidates} != set(self._tls):
            self._tls_at = now
            hostname = str(system.get("fqdn") or system.get("hostname") or "localhost")
            self._tls = {number: _certificate(host, number, hostname, name, unit)
                         for number, host, name, unit in candidates}
        certs = []
        for number, info in sorted(self._tls.items()):
            certs.append(info)
            if not info.get("tls"):
                continue
            days = info.get("days_left")
            if days is None:
                continue
            severity = "critical" if days < 0 else "warn" if days <= 7 else "info" if days <= 30 else None
            if severity is None:
                continue
            who = info.get("unit") or info.get("process") or f"port {number}"
            out.append({
                "key": f"tls:{number}", "kind": "certificate", "severity": severity,
                "title": (f"{who} serves an expired certificate on :{number}" if days < 0
                          else f"{who}'s certificate on :{number} expires in {days} day{'s' if days != 1 else ''}"),
                "detail": (f"Subject {info.get('subject') or '?'}, issued by {info.get('issuer') or '?'}, "
                           f"valid until {time.strftime('%Y-%m-%d %H:%M', time.localtime(float(info['not_after'])))}. "
                           + ("Every client that verifies certificates has been refusing this listener since then; "
                              "browsers show an error page, and API clients fail the handshake."
                              if days < 0 else
                              "Clients start failing the moment it expires; renew before then.")),
                "unit": info.get("unit"), "port": number,
                "root": {"unit": info.get("unit"), "result": None, "line": None, "chain": []},
                "fix": ("renew the certificate (certbot renew, or the issuing CA), then reload "
                        f"{info.get('unit') or 'the service'}"),
                "evidence": {"days_left": days, "not_after": info.get("not_after"),
                             "issuer": info.get("issuer")},
            })
        checks["tls"] = {"available": True, "checked": len(self._tls), "certificates": certs,
                         "next_check": self._tls_at + _TLS_REFRESH_S,
                         "note": None if candidates else "no listener on a TLS port and no TLS terminator is running"}
        return out

    # ------------------------------------------------------------------ clock
    def _clock(self, services: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        now = time.time()
        if self._time is None or now - self._time_at > _TIME_REFRESH_S:
            self._time = _time_sync(services)
            self._time_at = now
        info = self._time
        checks["time"] = info
        if not info.get("available"):
            return []
        if info.get("synchronized"):
            return []
        if info.get("ntp") is False and not info.get("daemon"):
            return [{
                "key": "time_unsynced", "kind": "clock", "severity": "warn",
                "title": "The clock is not synchronised: no time service is on",
                "detail": "systemd-timesyncd is off and no chrony/ntpd unit is running. The clock drifts; "
                          "TLS handshakes, Kerberos, log correlation and scheduled jobs go wrong quietly "
                          "as it does.",
                "root": {"unit": "systemd-timesyncd.service", "result": None, "line": None, "chain": []},
                "fix": "timedatectl set-ntp true  (or install and enable chrony)",
                "evidence": {"ntp": info.get("ntp"), "synchronized": False},
            }]
        return [{
            "key": "time_unsynced", "kind": "clock", "severity": "warn",
            "title": "The clock is not synchronised",
            "detail": (f"A time service is on ({info.get('daemon') or 'systemd-timesyncd'}) but reports the "
                       "clock as not synchronised: the servers are unreachable, DNS cannot resolve them, "
                       "or the service just started."
                       + (f" Current offset {info['offset_ms']:.0f} ms." if isinstance(info.get("offset_ms"), (int, float)) else "")),
            "root": {"unit": info.get("daemon") or "systemd-timesyncd.service", "result": None, "line": None, "chain": []},
            "fix": "timedatectl timesync-status  (or chronyc tracking); check that UDP 123 to the servers is allowed",
            "evidence": {"ntp": info.get("ntp"), "synchronized": False, "offset_ms": info.get("offset_ms")},
        }]

    # -------------------------------------------------------------------- dns
    def _dns(self, net_detail: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        probe = (net_detail.get("connectivity") or {}).get("dns_resolution")
        # resolved's counters go over D-Bus and measured ~1 s a call, so the
        # timeout rate is read every five minutes, not every tick.
        mono = time.monotonic()
        if self._resolved_prev is None or mono - self._resolved_prev[0] >= _RESOLVED_REFRESH_S:
            stats = _resolved_stats()
            if stats is not None:
                if self._resolved_prev and mono > self._resolved_prev[0]:
                    self._resolved_rate = round(
                        60 * max(0, stats - self._resolved_prev[1]) / (mono - self._resolved_prev[0]), 2)
                self._resolved_prev = (mono, stats)
            else:
                self._resolved_prev = (mono, 0)
        rate = self._resolved_rate
        if not isinstance(probe, dict):
            checks["dns"] = {"available": False, "reason": "no resolution probe yet", "timeouts_per_min": rate}
            self._dns_bad_ticks = 0
            return []
        ok = bool(probe.get("ok"))
        self._dns_bad_ticks = 0 if ok else self._dns_bad_ticks + 1
        checks["dns"] = {"available": True, "ok": ok, "latency_ms": probe.get("latency_ms"),
                         "timeouts_per_min": rate, "error": probe.get("error"),
                         "timeouts_reason": None if os.geteuid() == 0 else
                         "resolved's timeout counter needs root (resolvectl statistics is "
                         "polkit-guarded and would prompt on a desktop)"}
        if ok or self._dns_bad_ticks < 2:
            return []
        return [{
            "key": "dns_failing", "kind": "dns", "severity": "critical",
            "title": "DNS resolution is failing",
            "detail": ("The resolver could not resolve a name on two consecutive checks "
                       f"({probe.get('error') or 'no answer'}). Package installs, sync clients, TLS "
                       "(OCSP), mail and most of the web fail while this holds; services that cache "
                       "addresses keep working until they restart, which hides it."
                       + (f" systemd-resolved counts {rate:.1f} timeouts/min." if rate else "")),
            "root": {"unit": "systemd-resolved.service", "result": None, "line": None, "chain": []},
            "fix": "resolvectl status; resolvectl query example.com; check the upstream servers and UDP/TCP 53",
            "evidence": {"error": probe.get("error"), "timeouts_per_min": rate},
        }]

    # ----------------------------------------------------------------- mounts
    def _mounts(self, volumes: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        entries = [v for v in (volumes.get("volumes") or []) if isinstance(v, dict)]
        readonly_now = 0
        for volume in entries:
            mount = str(volume.get("mountpoint") or "")
            ro = bool(volume.get("readonly"))
            first = self._mounts_base.setdefault(mount, ro)
            if not ro:
                continue
            readonly_now += 1
            fstype = volume.get("fstype")
            if not first:
                out.append({
                    "key": f"readonly:{mount}", "kind": "mount", "severity": "critical",
                    "title": f"{mount} was remounted read-only",
                    "detail": (f"{mount} ({fstype}) was writable when the agent started and is mounted read-only "
                               "now. The kernel does that after a filesystem error (errors=remount-ro): every "
                               "write there fails from that moment, while reads and the processes look fine."),
                    "mount": mount, "root": {"unit": None, "result": None, "line": None, "chain": []},
                    "fix": f"dmesg | grep -i {fstype}; back up, then fsck {volume.get('device')} from a rescue boot",
                    "evidence": {"fstype": fstype, "device": volume.get("device")},
                })
            elif mount in ("/", "/var", "/home", "/tmp", "/srv", "/opt", "/var/log", "/var/lib"):
                out.append({
                    "key": f"readonly:{mount}", "kind": "mount", "severity": "warn",
                    "title": f"{mount} is mounted read-only",
                    "detail": (f"{mount} ({fstype}) has been read-only since the agent started. On an image "
                               "meant to be immutable that is by design; on anything else, writes are failing."),
                    "mount": mount, "root": {"unit": None, "result": None, "line": None, "chain": []},
                    "fix": f"mount | grep ' {mount} '; dmesg | grep -i {fstype}",
                    "evidence": {"fstype": fstype, "device": volume.get("device")},
                })
        for gone in [m for m in self._mounts_base if m not in {str(v.get("mountpoint")) for v in entries}]:
            del self._mounts_base[gone]
        checks["mounts"] = {"available": True, "checked": len(entries), "readonly": readonly_now}
        return out

    # ------------------------------------------------------------------- boot
    def _boot(self, volumes: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        boot = next((v for v in (volumes.get("volumes") or [])
                     if isinstance(v, dict) and v.get("mountpoint") == "/boot"), None)
        if boot is None:
            checks["boot"] = {"available": True, "separate": False}
            return []
        free = int(boot.get("free") or 0)
        checks["boot"] = {"available": True, "separate": True, "free": free, "total": boot.get("total"),
                          "ok": free >= _BOOT_MIN_FREE}
        if free >= _BOOT_MIN_FREE:
            return []
        return [{
            "key": "boot_full", "kind": "mount", "severity": "warn",
            "title": f"/boot has {free / 1024 ** 2:.0f} MB free: the next kernel will not fit",
            "detail": "A kernel image plus its initramfs needs roughly 100-150 MB. The next kernel upgrade "
                      "fails half-way, which on Debian and Ubuntu leaves apt broken until old kernels are "
                      "removed by hand.",
            "mount": "/boot", "root": {"unit": None, "result": None, "line": None, "chain": []},
            "fix": "apt autoremove --purge  (or dnf remove old kernels); then df -h /boot",
            "evidence": {"free": free, "total": boot.get("total")},
        }]

    # ------------------------------------------------------------ disk errors
    def _disk_errors(self, events: dict, checks: dict[str, Any], now: float) -> list[dict[str, Any]]:
        crashes = ((events.get("crashes") or {}).get("events")) or []
        recent = [e for e in crashes if isinstance(e, dict) and e.get("source_key") == "disk_error"
                  and float(e.get("timestamp") or 0) >= now - 86400]
        checks["storage"] = {"available": bool((events.get("journal") or {}).get("readable", True)),
                             "errors_24h": len(recent),
                             "reason": None if (events.get("journal") or {}).get("readable", True)
                             else (events.get("journal") or {}).get("reason")}
        if not recent:
            return []
        latest = recent[0]
        return [{
            "key": "disk_errors", "kind": "storage", "severity": "warn",
            "title": f"Storage reported {len(recent)} error{'s' if len(recent) != 1 else ''} in the last 24 h",
            "detail": f"The kernel logged \"{latest.get('title')}\" at "
                      f"{time.strftime('%H:%M', time.localtime(float(latest.get('timestamp') or now)))}. "
                      "IO errors precede a remount read-only and a dead disk; check SMART and back up first.",
            "root": {"unit": None, "result": None, "line": None, "chain": []},
            "fix": "dmesg -T | grep -iE 'I/O error|EXT4-fs error|nvme|ata'; smartctl -a on the device; back up",
            "evidence": {"errors_24h": len(recent), "latest": latest.get("timestamp")},
        }]

    # ----------------------------------------------------------------- reboot
    def _reboot(self, events: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        pending = events.get("pending_reboot") or {}
        checks["reboot"] = {"available": True, "pending": bool(pending.get("pending")),
                            "reasons": pending.get("reasons") or []}
        if not pending.get("pending"):
            return []
        reasons = [str(r) for r in (pending.get("reasons") or [])]
        return [{
            "key": "reboot_pending", "kind": "reboot", "severity": "info",
            "title": "A reboot is pending",
            "detail": "; ".join(reasons) + ". Nothing is broken by this alone, but processes running "
                      "against replaced libraries or an old kernel keep the old code, fixes included.",
            "root": {"unit": None, "result": None, "line": None, "chain": []},
            "fix": "schedule the reboot (or restart the listed services)",
            "evidence": {"reasons": reasons},
        }]


# ------------------------------------------------------------- unit roots
def _unit_props(name: str, scope_flag: list[str] | None = None) -> dict[str, str]:
    text = linux.run(["systemctl", *(scope_flag or []), "show", "-p", _UNIT_PROPS, "--", name],
                     timeout=5)
    fields: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, found, value = line.partition("=")
        if found:
            fields[key] = value
    return fields


def _root_of(name: str, scope: str = "system", depth: int = 2) -> dict[str, Any]:
    """The dependency that failed first, walking Requires/Requisite/BindsTo
    (and Wants) at most `depth` levels, plus the root's first error line."""
    flag = ["--user"] if scope == "user" else []
    chain: list[dict[str, Any]] = []
    seen = {name}
    current = name
    root = name
    root_props = _unit_props(name, flag)
    for _ in range(depth):
        props = root_props if current == name else _unit_props(current, flag)
        deps: list[str] = []
        for key in ("Requires", "Requisite", "BindsTo", "Wants"):
            deps += [d for d in (props.get(key) or "").split() if d and d not in seen]
        # Only dependencies that are themselves failed (or inactive with a
        # failed result) explain anything; a healthy dependency does not.
        culprit_dep = None
        for dep in deps:
            if dep.endswith((".target", ".slice", ".socket", ".mount", ".device")):
                if not dep.endswith(".mount"):
                    continue
            dprops = _unit_props(dep, flag)
            state = dprops.get("ActiveState")
            result = dprops.get("Result")
            if state == "failed" or (state == "inactive" and result not in (None, "", "success")):
                culprit_dep = (dep, dprops)
                break
        if culprit_dep is None:
            break
        dep, dprops = culprit_dep
        seen.add(dep)
        chain.append({"unit": dep, "state": dprops.get("ActiveState"), "result": dprops.get("Result"),
                      "description": dprops.get("Description")})
        root, root_props, current = dep, dprops, dep
    return {"root": root, "result": root_props.get("Result"),
            "state": root_props.get("ActiveState"), "chain": chain,
            "line": _last_error_line(root, scope)}


def _last_error_line(unit: str, scope: str = "system") -> dict[str, Any] | None:
    """The newest error-priority line from the unit's own journal in this
    boot; the unit's stdout/stderr and systemd's own verdict are both there.
    A user unit is matched on _SYSTEMD_USER_UNIT (--user-unit), which reads
    the user's own journal without the group the system journal needs."""
    match = ["--user-unit", unit] if scope == "user" else ["-u", unit]
    entries = linux.journalctl_json(["-b", *match, "-p", "err"], timeout=10, max_entries=1)
    if not entries:
        entries = linux.journalctl_json(["-b", *match], timeout=10, max_entries=1)
    if not entries:
        return None
    entry = entries[0]
    message = entry.get("MESSAGE")
    if isinstance(message, list):
        try:
            message = bytes(message).decode("utf-8", "replace")
        except (TypeError, ValueError):
            message = ""
    raw = entry.get("_SOURCE_REALTIME_TIMESTAMP") or entry.get("__REALTIME_TIMESTAMP")
    try:
        ts = int(raw) / 1e6
    except (TypeError, ValueError):
        ts = None
    return {"ts": ts, "message": str(message or "").split("\n", 1)[0][:300],
            "source": entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")}


# ------------------------------------------------------------ certificates
def _certificate(host: str, port: int, hostname: str, process: str | None,
                 unit: str | None) -> dict[str, Any]:
    """One TLS handshake to the box's own listener, then the certificate's
    validity from its DER -- no library, a forty-line ASN.1 walk."""
    info: dict[str, Any] = {"port": port, "host": host, "process": process, "unit": unit,
                            "tls": False, "reason": None, "not_after": None, "not_before": None,
                            "days_left": None, "subject": None, "issuer": None, "checked_at": time.time()}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=1.5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname if _sni_ok(hostname) else None) as tls:
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as exc:
        info["reason"] = f"not TLS, or the handshake was refused ({exc.reason or exc})"
        return info
    except (OSError, ValueError) as exc:
        info["reason"] = f"could not connect: {type(exc).__name__}"
        return info
    if not der:
        info["reason"] = "the listener sent no certificate"
        return info
    try:
        parsed = _parse_cert(der)
    except (ValueError, IndexError, struct.error) as exc:
        info.update({"tls": True, "reason": f"certificate not parseable: {exc}"})
        return info
    info.update({"tls": True, **parsed})
    if parsed.get("not_after"):
        info["days_left"] = int((float(parsed["not_after"]) - time.time()) // 86400)
    return info


def _sni_ok(hostname: str) -> bool:
    return bool(hostname) and hostname != "localhost" and not hostname.replace(".", "").isdigit()


def _tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """(tag, header length, content length, content offset) at `offset`."""
    tag = data[offset]
    length = data[offset + 1]
    header = 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
        header = 2 + count
    return tag, header, length, offset + header


def _children(data: bytes, offset: int, length: int) -> list[tuple[int, int, int]]:
    """(tag, content offset, content length) of each element in a SEQUENCE."""
    out = []
    end = offset + length
    while offset < end:
        tag, _header, clen, coff = _tlv(data, offset)
        out.append((tag, coff, clen))
        offset = coff + clen
    return out


def _asn1_time(tag: int, raw: bytes) -> float:
    text = raw.decode("ascii")
    if tag == 0x17:     # UTCTime YYMMDDHHMMSSZ
        year = int(text[:2])
        year += 2000 if year < 50 else 1900
        text = f"{year}{text[2:]}"
    struct_time = time.strptime(text.rstrip("Z")[:14], "%Y%m%d%H%M%S")
    return float(_timegm(struct_time))


def _timegm(value: time.struct_time) -> int:
    import calendar
    return calendar.timegm(value)


_OID_CN = b"\x55\x04\x03"
_OID_O = b"\x55\x04\x0a"


def _name(data: bytes, offset: int, length: int) -> str:
    """CN (else O) from an X.501 Name: SEQUENCE of SET of SEQUENCE(OID, value)."""
    cn = org = None
    for _tag, set_off, set_len in _children(data, offset, length):
        for _t, seq_off, seq_len in _children(data, set_off, set_len):
            parts = _children(data, seq_off, seq_len)
            if len(parts) < 2:
                continue
            oid_tag, oid_off, oid_len = parts[0]
            val_tag, val_off, val_len = parts[1]
            oid = data[oid_off:oid_off + oid_len]
            value = data[val_off:val_off + val_len].decode("utf-8", "replace")
            if oid == _OID_CN:
                cn = value
            elif oid == _OID_O:
                org = value
    return cn or org or "?"


def _parse_cert(der: bytes) -> dict[str, Any]:
    tag, _h, length, offset = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    cert = _children(der, offset, length)
    tbs_tag, tbs_off, tbs_len = cert[0]
    fields = _children(der, tbs_off, tbs_len)
    index = 0
    if fields[0][0] == 0xA0:      # explicit version
        index = 1
    # serial, signature algorithm, issuer, validity, subject
    issuer = fields[index + 2]
    validity = fields[index + 3]
    subject = fields[index + 4]
    times = _children(der, validity[1], validity[2])
    not_before = _asn1_time(times[0][0], der[times[0][1]:times[0][1] + times[0][2]])
    not_after = _asn1_time(times[1][0], der[times[1][1]:times[1][1] + times[1][2]])
    return {"not_before": not_before, "not_after": not_after,
            "subject": _name(der, subject[1], subject[2]), "issuer": _name(der, issuer[1], issuer[2])}


# ------------------------------------------------------------------- clock
def _time_sync(services: dict) -> dict[str, Any]:
    text = linux.run(["timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized", "-p", "CanNTP"],
                     timeout=5)
    if text is None:
        return {"available": False, "reason": "timedatectl is not available (no systemd-timedated)"}
    fields = dict(line.partition("=")[::2] for line in text.splitlines() if "=" in line)
    daemon = next((str(s.get("name")) for s in (services.get("services") or [])
                   if isinstance(s, dict) and s.get("status") == "running"
                   and str(s.get("name", "")).split(".")[0] in _NTP_UNITS), None)
    out: dict[str, Any] = {
        "available": True, "reason": None,
        "ntp": fields.get("NTP") == "yes",
        "synchronized": fields.get("NTPSynchronized") == "yes",
        "daemon": daemon, "offset_ms": None, "server": None,
    }
    status = linux.run(["timedatectl", "timesync-status"], timeout=5) or ""
    for line in status.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "server":
            out["server"] = value
        elif key == "offset":
            match = re.match(r"([+-]?[\d.]+)\s*(us|ms|s)", value)
            if match:
                number, unit = float(match.group(1)), match.group(2)
                out["offset_ms"] = round(number / 1000 if unit == "us" else number * 1000 if unit == "s" else number, 3)
    if out["offset_ms"] is None and daemon and daemon.startswith("chrony"):
        tracking = linux.run(["chronyc", "tracking"], timeout=5) or ""
        match = re.search(r"System time\s*:\s*([\d.]+) seconds (slow|fast)", tracking)
        if match:
            out["offset_ms"] = round(float(match.group(1)) * 1000 * (-1 if match.group(2) == "slow" else 1), 3)
    return out


def _resolved_stats() -> int | None:
    """systemd-resolved's own timeout counter, or None without resolved.

    Root only: `resolvectl statistics` is guarded by the polkit action
    org.freedesktop.resolve1.dump-statistics (systemd 254+), and for an
    unprivileged user the desktop's polkit agent answers it with a password
    prompt every time. A monitoring agent must never raise a dialog on the
    machine it watches, so without root the counter is honestly absent.
    """
    if os.geteuid() != 0:
        return None
    text = linux.run(["resolvectl", "statistics"], timeout=5)
    if not text:
        return None
    match = re.search(r"Total Timeouts:\s*(\d+)", text)
    return int(match.group(1)) if match else None
