"""The Outage Doctor: what is broken, not slow, and why.

Slow and broken are different questions. The Lag Doctor gates on pressure;
this looks at the things that stop a service working while every counter
looks fine, and walks each one to its root:

* an automatic service that is stopped -- with the service it depends on
  that is stopped first (the SCM's dependency list, walked two levels) and
  the Service Control Manager's last event about it, quoted
* a service the SCM keeps restarting (7031 "terminated unexpectedly" three
  times or more in a day)
* a service that is running but no longer listens on the port it held
* a TLS listener serving a certificate that has expired or is about to
  (read by connecting to the listener locally, nothing else)
* the clock not synchronised (w32tm)
* DNS resolution failing at the resolver
* a volume that went read-only
* storage reporting errors
* a reboot the machine is waiting for

Every item names the service, the root, the evidence and the fix, carries how
long it has held and what changed just before, and each check reports its
own availability and reason: a source that could not be read is named,
never rendered as "fine". Thresholds are not the point -- a certificate
with eleven days left is information; an expired one on a live listener is
the outage.

The certificate machinery is the Linux agent's, verbatim: a TLS handshake
and a forty-line ASN.1 walk are the same on every OS. /boot has no Windows
counterpart (the EFI system partition carries no letter and is not a
capacity problem), and `checks.boot` says so.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import struct
import time
from typing import Any

from .. import windows
from . import units as units_mod

log = logging.getLogger("culprit.outage")

_SEV = {"info": 1, "warn": 2, "critical": 3}

# Ports whose listeners are expected to speak TLS, so a handshake attempt is
# not noise in someone's log; plus any listener held by a TLS terminator.
_TLS_PORTS = frozenset({443, 8443, 4443, 9443, 10443, 993, 995, 465, 636, 853,
                        5001, 8883, 6514, 2376, 6443, 10250, 3269, 8006, 9200,
                        5986, 3389})
_TLS_TERMINATORS = ("nginx", "httpd", "apache", "haproxy", "caddy", "traefik",
                    "envoy", "stunnel", "w3wp", "iisexpress", "tomcat")
_TLS_REFRESH_S = 3600.0
_TLS_MAX_PORTS = 24
_TIME_REFRESH_S = 60.0
_LISTENER_HOLD_TICKS = 3        # a port must be held this many slow ticks to count
_LISTENER_GONE_TICKS = 2        # and be gone this many before it is an item
_LOOP_EVENTS = 3                # SCM crash events in a day before "looping"


class OutageCollector:
    def __init__(self) -> None:
        self._started = time.time()
        self._since: dict[str, float] = {}
        self._failed_seen: frozenset[str] = frozenset()
        self._failed_at = 0.0
        self._roots: dict[str, dict[str, Any]] = {}
        self._held: dict[tuple[str, int], int] = {}     # (service, port) -> ticks seen
        self._gone: dict[tuple[str, int], int] = {}     # (service, port) -> ticks missing
        self._tls: dict[int, dict[str, Any]] = {}
        self._tls_at = 0.0
        self._time: dict[str, Any] | None = None
        self._time_at = 0.0
        self._mounts_base: dict[str, bool] = {}
        self._dns_bad_ticks = 0

    # ----------------------------------------------------------------- sample
    def sample(self, services: dict | None, ports: dict | None, volumes: dict | None,
               events: dict | None, net_detail: dict | None, system: dict | None,
               changes: Any = None) -> dict[str, Any]:
        started = time.perf_counter()
        now = time.time()
        items: list[dict[str, Any]] = []
        checks: dict[str, Any] = {}

        items += self._units(services or {}, checks, now, events)
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
    def _units(self, services: dict, checks: dict[str, Any], now: float,
               events: dict | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not services.get("available"):
            checks["units"] = {"available": False,
                               "reason": services.get("reason") or "the Service Control Manager is not readable"}
            return out
        problems = [p for p in (services.get("problems") or []) if isinstance(p, dict)]
        # The SCM's own crash record: 7031/7034 per service in the last day.
        crashes: dict[str, list[dict]] = {}
        for event in ((events or {}).get("crashes") or {}).get("events") or []:
            if not isinstance(event, dict) or event.get("source_key") != "service_fail":
                continue
            if float(event.get("timestamp") or 0) < now - 86400:
                continue
            name = str((event.get("service") or {}).get("name") or "")
            if name:
                crashes.setdefault(name.lower(), []).append(event)
        by_name = {str(s.get("name")).lower(): s for s in (services.get("services") or [])
                   if isinstance(s, dict)}
        display = {k: str(v.get("display_name") or v.get("name")) for k, v in by_name.items()}

        failed = [p for p in problems if p.get("severity") == "critical"]
        stopped = [p for p in problems if p.get("severity") != "critical"]
        looping = [s for key, s in by_name.items()
                   if s.get("status") == "running" and len(crashes.get(key, [])) >= _LOOP_EVENTS]
        looping_names = {str(s["name"]) for s in looping}
        # Match the SCM's events to a service by either its name or its display
        # name: the events carry whichever the message template used.
        display_to_name = {v.lower(): k for k, v in display.items()}

        def crash_events(name: str) -> list[dict]:
            low = name.lower()
            return crashes.get(low) or crashes.get(display.get(low, "").lower()) or []

        names = frozenset(str(p["name"]) for p in failed)
        if names != self._failed_seen or now - self._failed_at > 600:
            self._failed_seen, self._failed_at = names, now
            self._roots = {name: _root_of(name, by_name) for name in names}
        for problem in failed:
            name = str(problem["name"])
            root = self._roots.get(name) or {}
            root_name = root.get("root")
            title = f"{display.get(name.lower(), name)} has stopped with an error"
            if root_name and root_name != name:
                title = f"{name} is down because {root_name} stopped first"
            last = (crash_events(root_name or name) or [None])[0]
            line = ({"ts": last.get("timestamp"), "message": last.get("title"),
                     "source": "Service Control Manager"} if last else None)
            detail = problem.get("detail") or "Service stopped."
            if line:
                detail += f" The SCM logged: \"{line['message']}\""
            out.append({
                "key": f"unit_failed:{name}", "kind": "unit", "severity": "critical",
                "title": title, "detail": detail, "unit": name, "manager": "system",
                "root": {"unit": root_name or name, "result": root.get("result") or problem.get("result"),
                         "line": line, "chain": root.get("chain") or []},
                "fix": (f"Get-WinEvent -LogName System -MaxEvents 50 | ? ProviderName -eq 'Service Control Manager' "
                        f"| ? Message -match '{root_name or name}'; then Restart-Service {root_name or name}"
                        + (f"; Restart-Service {name}" if root_name and root_name != name else "")),
                "actions": units_mod.offered("unit_failed", name, root_name, "system"),
                "evidence": {"result": problem.get("result"), "exit_status": problem.get("exit_status"),
                             "restarts": None, "scope": "system"},
            })
        for service in looping:
            name = str(service["name"])
            recent = crash_events(name)
            last = recent[0] if recent else None
            line = ({"ts": last.get("timestamp"), "message": last.get("title"),
                     "source": "Service Control Manager"} if last else None)
            out.append({
                "key": f"unit_looping:{name}", "kind": "unit", "severity": "warn",
                "title": f"{display.get(name.lower(), name)} keeps terminating unexpectedly "
                         f"({len(recent)} times in 24 h)",
                "detail": ("The Service Control Manager has restarted it under its recovery policy; "
                           "each restart loses the service's state and its clients' connections."
                           + (f" Last: \"{line['message']}\"" if line else "")),
                "unit": name, "manager": "system",
                "root": {"unit": name, "result": "terminated unexpectedly", "line": line, "chain": []},
                "fix": f"Get-WinEvent -LogName Application | ? Message -match '{name}' (the crash); fix the cause, "
                       f"then Restart-Service {name}",
                "actions": units_mod.offered("unit_looping", name, None, "system"),
                "evidence": {"crashes_24h": len(recent), "restarts": len(recent)},
            })
        for problem in stopped:
            name = str(problem["name"])
            if name in looping_names:
                continue
            out.append({
                "key": f"unit_stopped:{name}", "kind": "unit", "severity": "warn",
                "title": f"{display.get(name.lower(), name)} is set to start automatically but is not running",
                "detail": problem.get("detail") or "", "unit": name, "manager": "system",
                "root": {"unit": name, "result": problem.get("result"), "line": None, "chain": []},
                "fix": f"Start-Service {name}; if it stops again, the System event log says why",
                "actions": units_mod.offered("unit_stopped", name, None, "system"),
                "evidence": {"result": problem.get("result")},
            })
        checks["units"] = {"available": True, "failed": len(failed), "looping": len(looping),
                           "stopped": len(stopped), "total": (services.get("summary") or {}).get("total")}
        del display_to_name
        return out

    # -------------------------------------------------------------- listeners
    def _listeners(self, services: dict, ports: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not ports.get("available"):
            checks["listeners"] = {"available": False, "reason": ports.get("reason") or "port map not readable"}
            return out
        running = {str(s.get("display_name") or s.get("name")) for s in (services.get("services") or [])
                   if isinstance(s, dict) and s.get("status") == "running"}
        current: set[tuple[str, int]] = set()
        for port in ports.get("ports") or []:
            if not isinstance(port, dict) or "tcp" not in (port.get("protocols") or []):
                continue
            for proc in port.get("processes") or []:
                unit = proc.get("unit") if isinstance(proc, dict) else None
                if unit:
                    current.add((str(unit), int(port["port"])))
        for key in current:
            self._held[key] = self._held.get(key, 0) + 1
            self._gone.pop(key, None)
        for key in [k for k in self._held if k not in current]:
            unit, port = key
            if unit in running and self._held[key] >= _LISTENER_HOLD_TICKS:
                self._gone[key] = self._gone.get(key, 0) + 1
            else:
                del self._held[key]
                self._gone.pop(key, None)
        for (unit, port), ticks in self._gone.items():
            if ticks >= _LISTENER_GONE_TICKS:
                out.append({
                    "key": f"not_listening:{unit}:{port}", "kind": "listener", "severity": "warn",
                    "title": f"{unit} is running but no longer listens on :{port}",
                    "detail": f"The service is running, but the port it held for the last "
                              f"{self._held.get((unit, port), 0)} samples is no longer bound. Clients get a "
                              "connection refused while the SCM still reports the service as running: a "
                              "worker that died inside the service, a bind that failed, or a listener "
                              "moved to another address.",
                    "unit": unit, "port": port, "manager": "system",
                    "root": {"unit": unit, "result": None, "line": None, "chain": []},
                    "fix": f"netstat -abno | findstr :{port}; Restart-Service '{unit}'",
                    "actions": units_mod.offered("not_listening", unit, None, "system"),
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
                "fix": ("renew the certificate (the issuing CA, or win-acme for Let's Encrypt), then "
                        f"restart {info.get('unit') or 'the service'}"),
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
        if not info.get("available") or info.get("synchronized"):
            return []
        if not info.get("daemon"):
            return [{
                "key": "time_unsynced", "kind": "clock", "severity": "warn",
                "title": "The clock is not synchronised: the Windows Time service is not running",
                "detail": "W32Time is stopped, so nothing corrects the clock. It drifts; TLS handshakes, "
                          "Kerberos sign-in and scheduled jobs go wrong quietly as it does.",
                "root": {"unit": "W32Time", "result": None, "line": None, "chain": []},
                "fix": "Start-Service W32Time; w32tm /resync",
                "actions": units_mod.offered("unit_stopped", "W32Time", None, "system"),
                "evidence": {"ntp": False, "synchronized": False},
            }]
        return [{
            "key": "time_unsynced", "kind": "clock", "severity": "warn",
            "title": "The clock is not synchronised",
            "detail": ("The Windows Time service is running but reports the clock as not synchronised: "
                       "the time source is unreachable, DNS cannot resolve it, or the service just started."
                       + (f" Source: {info['server']}." if info.get("server") else "")
                       + (f" Current offset {info['offset_ms']:.0f} ms." if isinstance(info.get("offset_ms"), (int, float)) else "")),
            "root": {"unit": "W32Time", "result": None, "line": None, "chain": []},
            "fix": "w32tm /query /status; w32tm /resync; check that UDP 123 to the source is allowed",
            "evidence": {"ntp": True, "synchronized": False, "offset_ms": info.get("offset_ms")},
        }]

    # -------------------------------------------------------------------- dns
    def _dns(self, net_detail: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:
        probe = (net_detail.get("connectivity") or {}).get("dns_resolution")
        if not isinstance(probe, dict):
            checks["dns"] = {"available": False, "reason": "no resolution probe yet", "timeouts_per_min": None}
            self._dns_bad_ticks = 0
            return []
        ok = bool(probe.get("ok"))
        self._dns_bad_ticks = 0 if ok else self._dns_bad_ticks + 1
        checks["dns"] = {"available": True, "ok": ok, "latency_ms": probe.get("latency_ms"),
                         "timeouts_per_min": None, "error": probe.get("error"),
                         "timeouts_reason": windows.not_capable(
                             "the DNS Client service keeps no readable timeout counter; the "
                             "resolution probe is the signal")}
        if ok or self._dns_bad_ticks < 2:
            return []
        return [{
            "key": "dns_failing", "kind": "dns", "severity": "critical",
            "title": "DNS resolution is failing",
            "detail": ("The resolver could not resolve a name on two consecutive checks "
                       f"({probe.get('error') or 'no answer'}). Domain sign-in, mapped drives, sync clients, "
                       "TLS (OCSP), mail and most of the web fail while this holds; services that cache "
                       "addresses keep working until they restart, which hides it."),
            "root": {"unit": "Dnscache", "result": None, "line": None, "chain": []},
            "fix": "ipconfig /all (the configured servers); Resolve-DnsName example.com; ipconfig /flushdns",
            "evidence": {"error": probe.get("error")},
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
                    "title": f"{mount} went read-only",
                    "detail": (f"{mount} ({fstype}) was writable when the agent started and is read-only "
                               "now. NTFS does that after a filesystem error, and a drive that lost its "
                               "connection comes back read-only: every write there fails from that moment."),
                    "mount": mount, "root": {"unit": None, "result": None, "line": None, "chain": []},
                    "fix": f"Get-WinEvent -LogName System | ? ProviderName -match 'Ntfs|disk'; chkdsk {mount} /scan",
                    "evidence": {"fstype": fstype, "device": volume.get("device")},
                })
            elif mount.upper().startswith("C:"):
                out.append({
                    "key": f"readonly:{mount}", "kind": "mount", "severity": "warn",
                    "title": f"{mount} is read-only",
                    "detail": f"{mount} ({fstype}) has been read-only since the agent started; writes are failing.",
                    "mount": mount, "root": {"unit": None, "result": None, "line": None, "chain": []},
                    "fix": f"chkdsk {mount} /scan; Get-Volume",
                    "evidence": {"fstype": fstype, "device": volume.get("device")},
                })
        for gone in [m for m in self._mounts_base if m not in {str(v.get("mountpoint")) for v in entries}]:
            del self._mounts_base[gone]
        checks["mounts"] = {"available": True, "checked": len(entries), "readonly": readonly_now}
        return out

    # ------------------------------------------------------------------- boot
    def _boot(self, volumes: dict, checks: dict[str, Any]) -> list[dict[str, Any]]:  # noqa: ARG002
        checks["boot"] = {"available": True, "separate": False,
                          "reason": windows.not_capable("the EFI system partition holds only the "
                                                        "boot loader; kernels are not staged there")}
        return []

    # ------------------------------------------------------------ disk errors
    def _disk_errors(self, events: dict, checks: dict[str, Any], now: float) -> list[dict[str, Any]]:
        crashes = ((events.get("crashes") or {}).get("events")) or []
        recent = [e for e in crashes if isinstance(e, dict) and e.get("source_key") == "disk_error"
                  and float(e.get("timestamp") or 0) >= now - 86400]
        readable = (events.get("journal") or {}).get("readable", True)
        checks["storage"] = {"available": bool(readable), "errors_24h": len(recent),
                             "reason": None if readable else (events.get("journal") or {}).get("reason")}
        if not recent:
            return []
        latest = recent[0]
        return [{
            "key": "disk_errors", "kind": "storage", "severity": "warn",
            "title": f"Storage reported {len(recent)} error{'s' if len(recent) != 1 else ''} in the last 24 h",
            "detail": f"The System log has \"{latest.get('title')}\" at "
                      f"{time.strftime('%H:%M', time.localtime(float(latest.get('timestamp') or now)))}. "
                      f"{latest.get('detail') or ''} Check the drive's health and back up first.",
            "root": {"unit": None, "result": None, "line": None, "chain": []},
            "fix": "Get-WinEvent -LogName System | ? ProviderName -match 'disk|Ntfs|stor'; Get-PhysicalDisk | Get-StorageReliabilityCounter",
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
            "detail": "; ".join(reasons) + ". Nothing is broken by this alone, but staged updates and "
                      "queued file replacements do not take effect until the restart.",
            "root": {"unit": None, "result": None, "line": None, "chain": []},
            "fix": "schedule the restart",
            "evidence": {"reasons": reasons},
        }]


# ------------------------------------------------------------- service roots
def _root_of(name: str, by_name: dict[str, dict], depth: int = 2) -> dict[str, Any]:
    """The service this one depends on that is stopped first, walking the
    SCM's dependency list at most `depth` levels."""
    chain: list[dict[str, Any]] = []
    seen = {name.lower()}
    current = name
    root = name
    root_entry = by_name.get(name.lower()) or {}
    for _ in range(depth):
        deps = windows.service_dependencies(current) or []
        culprit = None
        for dep in deps:
            low = dep.lower()
            if low in seen:
                continue
            entry = by_name.get(low)
            if entry is None:
                continue
            if entry.get("status") in ("stopped", "paused") and entry.get("start_type") != "disabled":
                culprit = (dep, entry)
                break
        if culprit is None:
            break
        dep, entry = culprit
        seen.add(dep.lower())
        chain.append({"unit": dep, "state": entry.get("status"), "result": entry.get("result"),
                      "description": entry.get("display_name")})
        root, root_entry, current = dep, entry, dep
    return {"root": root, "result": root_entry.get("result"),
            "state": root_entry.get("status"), "chain": chain, "line": None}


# ------------------------------------------------------------------- clock
def _time_sync(services: dict) -> dict[str, Any]:
    """w32tm's view: the Leap Indicator is 3 while the clock is unsynchronised,
    and the status carries the source and the phase offset."""
    daemon = next((str(s.get("name")) for s in (services.get("services") or [])
                   if isinstance(s, dict) and s.get("status") == "running"
                   and str(s.get("name", "")).lower() == "w32time"), None)
    text = windows.run(["w32tm", "/query", "/status"], timeout=5)
    if text is None:
        if not windows.IS_WINDOWS:
            return {"available": False, "reason": "w32tm only exists on Windows",
                    "synchronized": None, "ntp": None, "daemon": None, "offset_ms": None, "server": None}
        # w32tm exits non-zero while the service is stopped; that is the answer.
        return {"available": True, "reason": None, "ntp": daemon is not None,
                "synchronized": False, "daemon": daemon, "offset_ms": None, "server": None}
    out: dict[str, Any] = {"available": True, "reason": None, "ntp": daemon is not None,
                           "synchronized": False, "daemon": daemon, "offset_ms": None,
                           "server": None, "last_sync": None}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "leap indicator":
            out["synchronized"] = value.startswith("0")
        elif key == "source":
            out["server"] = value or None
        elif key == "phase offset":
            match = re.match(r"([+-]?[\d.]+)s", value)
            if match:
                out["offset_ms"] = round(float(match.group(1)) * 1000, 3)
        elif key == "last successful sync time":
            out["last_sync"] = value or None
    return out


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


