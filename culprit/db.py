"""SQLite history.

Purpose is narrow: answer "what was this machine doing at 14:20 yesterday, and
which process was responsible". That needs three tables and nothing more.

Sizing: one `samples` row per `rollup_seconds` (60s default) plus
`history_top_processes` rows in `proc_samples` per rollup. At the defaults that
is ~1,440 sample rows and ~11,500 process rows per day, which lands around
2-4 MB/day and well under 30 MB at the 7-day retention default.

Concurrency: the sampler thread writes once a minute, HTTP handlers read on
demand. WAL mode lets those overlap without readers blocking, and a single
connection guarded by one lock is more than enough for that traffic -- a
connection pool here would be complexity with no payoff.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import logging
import os
import secrets
import sqlite3
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Iterable, Sequence

log = logging.getLogger("culprit.db")

SCHEMA_VERSION = 7

ROLES = ("viewer", "operator", "admin")

# The host machine's own data is node 'local'; agent nodes use their enrolled
# name. Kept as a plain column (not a separate DB per node) so cross-node
# queries stay one SQL statement away.
LOCAL_NODE = "local"

# A death's recorder frames, inflated: the caps in coroner.py keep a real one
# under a few MB, so this is a ceiling against a damaged row, not a budget.
_MAX_FRAMES_BYTES = 32 * 1024 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per rollup bucket per node. Averages for trend, maxima so a
-- 3-second spike inside a 60-second bucket is not averaged out of existence.
CREATE TABLE IF NOT EXISTS samples (
    node              TEXT NOT NULL DEFAULT 'local',
    ts                INTEGER NOT NULL,
    n                 INTEGER NOT NULL,
    cpu_avg           REAL, cpu_max           REAL,
    cpu_queue_avg     REAL, cpu_queue_max     REAL,
    mem_percent_avg   REAL, mem_available_min REAL,
    commit_avg        REAL, commit_max        REAL,
    hard_faults_avg   REAL, hard_faults_max   REAL,
    gpu_avg           REAL, gpu_max           REAL,
    disk_busy_avg     REAL, disk_busy_max     REAL,
    disk_queue_avg    REAL, disk_queue_max    REAL,
    disk_latency_avg  REAL, disk_latency_max  REAL,
    disk_read_avg     REAL, disk_write_avg    REAL,
    net_recv_avg      REAL, net_sent_avg      REAL,
    lag_severity      TEXT,
    PRIMARY KEY (node, ts)
) WITHOUT ROWID;

-- The heaviest processes in each bucket, so a spike can be attributed after
-- the fact. Keyed by (node, ts, pid): a PID appears once per bucket per node.
CREATE TABLE IF NOT EXISTS proc_samples (
    node         TEXT NOT NULL DEFAULT 'local',
    ts           INTEGER NOT NULL,
    pid          INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    cpu          REAL,
    working_set  INTEGER,
    io_bytes_sec REAL,
    gpu          REAL,
    lag_score    REAL,
    PRIMARY KEY (node, ts, pid)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_proc_ts    ON proc_samples(ts);
CREATE INDEX IF NOT EXISTS idx_proc_name  ON proc_samples(name);

-- Journal events, deduplicated. Each poll re-reads a window, so without a
-- stable fingerprint every event would be inserted repeatedly.
CREATE TABLE IF NOT EXISTS events (
    fingerprint TEXT PRIMARY KEY,
    node        TEXT NOT NULL DEFAULT 'local',
    ts          REAL    NOT NULL,
    kind        TEXT,
    source_key  TEXT,
    event_id    INTEGER,
    severity    TEXT,
    title       TEXT,
    payload     TEXT,
    seen_at     REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

-- Lag Doctor findings over time: "the machine was struggling, here is when".
CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    node      TEXT NOT NULL DEFAULT 'local',
    ts        REAL NOT NULL,
    key       TEXT NOT NULL,
    severity  TEXT,
    resource  TEXT,
    title     TEXT,
    detail    TEXT,
    culprits  TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);

-- The change log: unit starts/stops, timers fired, mounts, listeners, logins,
-- package upgrades, quota changes -- facts with a time, per node. Agents keep
-- a ring in memory and resend the section when it changes; the host keeps
-- everything it sees so "what changed before this incident" survives an
-- agent restart. `uid` is the agent's own id (ts:kind:subject).
CREATE TABLE IF NOT EXISTS changes (
    node      TEXT NOT NULL DEFAULT 'local',
    uid       TEXT NOT NULL,
    ts        REAL NOT NULL,
    kind      TEXT,
    source    TEXT,
    title     TEXT,
    detail    TEXT,
    subject   TEXT,
    severity  TEXT,
    exact     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (node, uid)
);

CREATE INDEX IF NOT EXISTS idx_changes_ts ON changes(ts);

-- Expected-busy annotations: "this finding, on this node (or all), led by
-- this culprit (or any), is normal -- here is why, and during this window".
-- The host matches live findings against these at ingest and reports them
-- as expected rather than as problems. Human-written, never inferred.
CREATE TABLE IF NOT EXISTS expectations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node        TEXT NOT NULL DEFAULT '*',   -- '*' = every node
    key         TEXT NOT NULL,               -- finding key, e.g. psi_io
    culprit     TEXT,                        -- image name, or NULL for any
    reason      TEXT NOT NULL,
    days        TEXT NOT NULL DEFAULT '[]',  -- JSON list of weekdays, Mon=0; [] = every day
    start       TEXT,                        -- 'HH:MM' local (host) time, or NULL = always
    "end"       TEXT,
    created_at  REAL NOT NULL,
    created_by  TEXT
);

-- Actions taken from the dashboard (End task, renice, throttle) and what
-- happened next: the verdict the host reached by watching the node's own
-- findings after the action. The audit trail an incident timeline needs.
CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node        TEXT NOT NULL,
    ts          REAL NOT NULL,
    action      TEXT NOT NULL,
    pid         INTEGER,
    name        TEXT,
    unit        TEXT,
    detail      TEXT,                        -- JSON: the agent's own result
    verdict     TEXT,                        -- JSON, NULL while still watching
    username    TEXT
);

CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(ts);

-- Deaths: how a node (or its agent) stopped, reconstructed by the Coroner
-- from the agent's flight recorder and the previous boot's journal. `uid`
-- is the agent's own id (previous boot id + time), so a re-sent report is
-- ignored. `frames` is the recorder (gzip JSON), read only for one death's
-- detail page; `verdict` and `evidence` are JSON.
CREATE TABLE IF NOT EXISTS deaths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node        TEXT NOT NULL,
    uid         TEXT NOT NULL,
    kind        TEXT NOT NULL,                -- machine | agent
    died_at     REAL NOT NULL,
    detected_at REAL NOT NULL,
    class       TEXT,
    severity    TEXT,
    title       TEXT,
    verdict     TEXT,
    evidence    TEXT,
    frames      BLOB,
    UNIQUE (node, uid)
);

CREATE INDEX IF NOT EXISTS idx_deaths_ts ON deaths(died_at);

-- Dashboard users. Passwords are scrypt-hashed with a per-user salt; the
-- plaintext never touches the database.
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,     -- scrypt$<salt-hex>$<hash-hex>
    created_at    REAL NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin'   -- viewer | operator | admin
);

-- Enrolled agent nodes. Only the SHA-256 of each token is stored -- the
-- plaintext token is shown exactly once, at enrollment, and cannot be
-- recovered from here.
CREATE TABLE IF NOT EXISTS agents (
    name             TEXT PRIMARY KEY,
    token_hash       TEXT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       REAL NOT NULL,
    last_seen        REAL,
    last_addr        TEXT,
    -- YYYY-MM-DD (host-local), the last day the scheduler sent this node an
    -- "update" command -- persisted so a host restart doesn't forget and
    -- fire twice in one day. NULL until the first scheduled update.
    last_auto_update TEXT,
    -- Set when an operator moved this agent to a chosen (usually older)
    -- version: the daily sweep and "Update all" then leave it alone until
    -- the pin is cleared or the node is explicitly updated again. The ref
    -- is the commit that version resolved to at the time.
    pinned_version   TEXT,
    pinned_ref       TEXT
);
"""

_SAMPLE_COLUMNS: tuple[str, ...] = (
    "ts", "n",
    "cpu_avg", "cpu_max", "cpu_queue_avg", "cpu_queue_max",
    "mem_percent_avg", "mem_available_min", "commit_avg", "commit_max",
    "hard_faults_avg", "hard_faults_max",
    "gpu_avg", "gpu_max",
    "disk_busy_avg", "disk_busy_max", "disk_queue_avg", "disk_queue_max",
    "disk_latency_avg", "disk_latency_max", "disk_read_avg", "disk_write_avg",
    "net_recv_avg", "net_sent_avg", "lag_severity",
)


class History:
    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = path
        self.enabled = enabled
        # Metric recording and credential storage are separate concerns: the
        # database must stay open for users/agents even when the user turns
        # metric history off. `recording` gates only the rollup/event writes.
        self.recording = enabled
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._last_prune = 0.0
        self.error: str | None = None
        if enabled:
            self._open()

    # ------------------------------------------------------------------ setup
    def _open(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                   timeout=10.0)
            conn.row_factory = sqlite3.Row
            # WAL: the once-a-minute writer never blocks a dashboard read.
            conn.execute("PRAGMA journal_mode=WAL")
            # NORMAL is the right trade here -- losing the last minute of
            # samples to a power cut costs nothing, and FULL would fsync on
            # every rollup.
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            _migrate(conn)
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )
            conn.commit()
            self._conn = conn
            self.error = None
            # The database now holds credentials (hashed, but still), so it is
            # nobody else's business.
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except sqlite3.Error as exc:
            log.warning("history disabled: %s", exc)
            self.error = str(exc)
            self.enabled = False
            self._conn = None

    @property
    def ready(self) -> bool:
        return self.enabled and self._conn is not None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def set_enabled(self, enabled: bool) -> None:
        """Toggle metric recording. The connection stays open either way --
        credentials live here too."""
        self.recording = enabled
        if not self.ready:
            self.enabled = True
            self._open()

    # ------------------------------------------------------------------ write
    def write_rollup(self, bucket_ts: int, aggregate: dict[str, Any],
                     processes: Sequence[dict[str, Any]],
                     findings: Iterable[dict[str, Any]] = (),
                     node: str = LOCAL_NODE) -> None:
        if not self.ready or not self.recording:
            return
        row = [node, bucket_ts] + [aggregate.get(column)
                                   for column in _SAMPLE_COLUMNS[1:]]
        placeholders = ", ".join("?" * (len(_SAMPLE_COLUMNS) + 1))
        columns = "node, " + ", ".join(_SAMPLE_COLUMNS)
        with self._lock:
            conn = self._conn
            if conn is None:
                return
            try:
                # REPLACE so a restart mid-bucket overwrites rather than fails.
                conn.execute(
                    f"INSERT OR REPLACE INTO samples ({columns}) VALUES ({placeholders})",
                    row,
                )
                if processes:
                    conn.executemany(
                        "INSERT OR REPLACE INTO proc_samples "
                        "(node, ts, pid, name, cpu, working_set, io_bytes_sec, gpu, lag_score) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            (node, bucket_ts, int(p["pid"]), str(p["name"]),
                             _f(p.get("cpu")), _i(p.get("working_set")),
                             _f(p.get("io_bytes_sec")), _f(p.get("gpu")),
                             _f(p.get("lag_score")))
                            for p in processes
                        ],
                    )
                for finding in findings:
                    conn.execute(
                        "INSERT INTO findings (node, ts, key, severity, resource, "
                        "title, detail, culprits) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (node, bucket_ts, str(finding.get("key")),
                         str(finding.get("severity")), str(finding.get("resource")),
                         str(finding.get("title")), str(finding.get("detail")),
                         json.dumps(finding.get("culprits") or [])),
                    )
                conn.commit()
            except sqlite3.Error as exc:
                log.warning("rollup write failed: %s", exc)

    def write_events(self, events: Iterable[dict[str, Any]],
                     node: str = LOCAL_NODE) -> int:
        """Insert event-log entries, ignoring ones already stored."""
        if not self.ready or not self.recording:
            return 0
        rows = []
        seen = time.time()
        for event in events:
            # Agents relay these verbatim; a hostile or broken one can send
            # anything. Non-objects and unparseable timestamps are skipped.
            if not isinstance(event, dict):
                continue
            timestamp = _f(event.get("timestamp"))
            if not timestamp or not math.isfinite(timestamp):
                continue
            # Journal cursors are unique per journal instance, so prefixing
            # the node keeps two machines' cursors from ever colliding.
            fingerprint = (
                f"{node}:{event.get('channel')}:{event.get('record_id')}"
                if event.get("record_id") is not None
                else f"{node}:{event.get('channel')}:{event.get('id')}:{timestamp}"
            )
            rows.append((
                fingerprint, node, timestamp, _text(event.get("kind")),
                _text(event.get("source_key")), _i(event.get("id")),
                _text(event.get("severity")),
                _text(event.get("title") or event.get("source_label") or ""),
                _text(json.dumps(_compact(event))), seen,
            ))
        if not rows:
            return 0
        with self._lock:
            conn = self._conn
            if conn is None:
                return 0
            try:
                cursor = conn.executemany(
                    "INSERT OR IGNORE INTO events (fingerprint, node, ts, kind, "
                    "source_key, event_id, severity, title, payload, seen_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
                return cursor.rowcount or 0
            except (sqlite3.Error, UnicodeEncodeError) as exc:
                log.warning("event write failed: %s", exc)
                return 0

    def prune(self, retention_days: int) -> None:
        """Drop data past retention. Rate-limited to once an hour."""
        if not self.ready:
            return
        now = time.time()
        if now - self._last_prune < 3600:
            return
        self._last_prune = now
        cutoff = now - retention_days * 86_400
        with self._lock:
            conn = self._conn
            if conn is None:
                return
            try:
                conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
                conn.execute("DELETE FROM proc_samples WHERE ts < ?", (cutoff,))
                conn.execute("DELETE FROM findings WHERE ts < ?", (cutoff,))
                conn.execute("DELETE FROM changes WHERE ts < ?", (cutoff,))
                conn.execute("DELETE FROM actions WHERE ts < ?",
                             (now - max(retention_days, 90) * 86_400,))
                # Events are kept longer -- a bluescreen from six weeks ago is
                # still the most interesting thing in the database.
                conn.execute("DELETE FROM events WHERE ts < ?",
                             (now - max(retention_days, 90) * 86_400,))
                # Deaths likewise: a machine that died twice this quarter is
                # the question the Coroner exists to answer.
                conn.execute("DELETE FROM deaths WHERE died_at < ?",
                             (now - max(retention_days, 90) * 86_400,))
                conn.commit()
            except sqlite3.Error as exc:
                log.warning("prune failed: %s", exc)

    # ------------------------------------------------------------------- read
    def series(self, since: float, until: float | None = None,
               columns: Sequence[str] | None = None,
               node: str = LOCAL_NODE) -> dict[str, Any]:
        """Time series for the trend charts, as parallel arrays for uPlot."""
        if not self.ready:
            return {"available": False, "reason": self.error or "history disabled",
                    "ts": [], "series": {}}
        wanted = [c for c in (columns or _SAMPLE_COLUMNS[2:]) if c in _SAMPLE_COLUMNS]
        until = until or time.time()
        select = ", ".join(["ts"] + wanted)
        rows = self._query(
            f"SELECT {select} FROM samples "
            f"WHERE node = ? AND ts >= ? AND ts <= ? ORDER BY ts",
            (node, since, until),
        )
        timestamps = [row["ts"] for row in rows]
        series = {column: [row[column] for row in rows] for column in wanted}
        return {"available": True, "reason": None, "node": node,
                "ts": timestamps, "series": series, "count": len(timestamps)}

    def top_processes(self, since: float, until: float | None = None,
                      limit: int = 20, node: str = LOCAL_NODE
                      ) -> list[dict[str, Any]]:
        """Which images dominated a window. Grouped by name, not PID, because a
        browser that restarted twice is still 'the browser'."""
        if not self.ready:
            return []
        until = until or time.time()
        rows = self._query(
            "SELECT name, "
            "       COUNT(*)          AS buckets, "
            "       AVG(cpu)          AS cpu_avg, "
            "       MAX(cpu)          AS cpu_max, "
            "       AVG(working_set)  AS mem_avg, "
            "       MAX(working_set)  AS mem_max, "
            "       AVG(io_bytes_sec) AS io_avg, "
            "       MAX(lag_score)    AS lag_max, "
            "       AVG(lag_score)    AS lag_avg "
            "FROM proc_samples WHERE node = ? AND ts >= ? AND ts <= ? "
            "GROUP BY name ORDER BY lag_avg DESC LIMIT ?",
            (node, since, until, limit),
        )
        return [dict(row) for row in rows]

    def processes_at(self, bucket_ts: int,
                     node: str = LOCAL_NODE) -> list[dict[str, Any]]:
        """The stored process rows for one bucket -- the 'what happened at 14:20'
        answer."""
        if not self.ready:
            return []
        rows = self._query(
            "SELECT * FROM proc_samples WHERE node = ? AND ts = ? "
            "ORDER BY lag_score DESC",
            (node, bucket_ts),
        )
        return [dict(row) for row in rows]

    def events(self, since: float | None = None, kinds: Sequence[str] | None = None,
               limit: int = 300, node: str = LOCAL_NODE) -> list[dict[str, Any]]:
        if not self.ready:
            return []
        clauses: list[str] = ["node = ?"]
        params: list[Any] = [node]
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if kinds:
            clauses.append("kind IN (" + ",".join("?" * len(kinds)) + ")")
            params.extend(kinds)
        params.append(limit)
        rows = self._query(
            f"SELECT ts, kind, source_key, event_id, severity, title, payload "
            f"FROM events WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?",
            tuple(params),
        )
        out = []
        for row in rows:
            entry = dict(row)
            try:
                entry["payload"] = json.loads(entry["payload"] or "{}")
            except ValueError:
                entry["payload"] = {}
            out.append(entry)
        return out

    def findings(self, since: float, limit: int = 200,
                 node: str = LOCAL_NODE) -> list[dict[str, Any]]:
        if not self.ready:
            return []
        rows = self._query(
            "SELECT ts, key, severity, resource, title, detail, culprits "
            "FROM findings WHERE node = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (node, since, limit),
        )
        out = []
        for row in rows:
            entry = dict(row)
            try:
                entry["culprits"] = json.loads(entry["culprits"] or "[]")
            except ValueError:
                entry["culprits"] = []
            out.append(entry)
        return out

    def incidents(self, since: float, limit: int = 100, node: str = LOCAL_NODE,
                  bucket_seconds: int = 60) -> list[dict[str, Any]]:
        """Findings folded into incidents: consecutive stored rows of one key
        become one span with a start, an end, the peak severity, the culprits
        ranked by how many buckets they led, and the actions taken meanwhile.

        Rows are written once per rollup bucket, so "consecutive" means within
        a couple of bucket widths -- one missed bucket (a restart mid-minute)
        does not split an incident in two.
        """
        if not self.ready:
            return []
        gap = bucket_seconds * 2.5
        rows = self._query(
            "SELECT ts, key, severity, resource, title, detail, culprits "
            "FROM findings WHERE node = ? AND ts >= ? ORDER BY key, ts",
            (node, since - gap),
        )
        incidents: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        now = time.time()
        for row in rows:
            ts = float(row["ts"])
            try:
                culprits = json.loads(row["culprits"] or "[]")
            except ValueError:
                culprits = []
            if current is None or row["key"] != current["key"] \
                    or ts - current["_last"] > gap:
                if current is not None:
                    incidents.append(_close_incident(current, bucket_seconds, now))
                current = {
                    "key": row["key"], "resource": row["resource"],
                    "start": ts, "_last": ts, "buckets": 0,
                    "severity": "info", "peak_ts": ts,
                    "title": row["title"], "detail": row["detail"],
                    "_names": {}, "_first_by_severity": {},
                }
            current["_last"] = ts
            current["buckets"] += 1
            current["title"] = row["title"]
            current["detail"] = row["detail"]
            sev = str(row["severity"] or "info")
            current["_first_by_severity"].setdefault(sev, ts)
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(current["severity"], 0):
                current["severity"] = sev
                current["peak_ts"] = ts
            for rank, culprit in enumerate(culprits[:5]):
                if not isinstance(culprit, dict):
                    continue
                name = str(culprit.get("name") or "?")
                entry = current["_names"].setdefault(name, {
                    "name": name, "buckets": 0, "led": 0, "pid": None,
                    "share": None, "container": None,
                })
                entry["buckets"] += 1
                if rank == 0:
                    entry["led"] += 1
                entry["pid"] = culprit.get("pid")
                entry["share"] = culprit.get("share")
                entry["container"] = culprit.get("container")
        if current is not None:
            incidents.append(_close_incident(current, bucket_seconds, now))
        incidents = [i for i in incidents if i["end"] >= since]
        incidents.sort(key=lambda i: -i["start"])
        incidents = incidents[:limit]
        if incidents:
            earliest = min(i["start"] for i in incidents)
            actions = self.actions(earliest - bucket_seconds, node=node, limit=500)
            # Findings are written once per bucket, so an incident's `start`
            # is up to one bucket late; look back a bucket plus ten minutes.
            lead = 600.0 + bucket_seconds
            changes = self.changes(earliest - lead, node=node, limit=2000)
            for incident in incidents:
                incident["actions"] = [
                    a for a in actions
                    if incident["start"] - bucket_seconds <= float(a["ts"]) <= incident["end"]
                ]
                window = [
                    c for c in changes
                    if incident["start"] - lead <= float(c["ts"]) <= incident["start"] + 30
                ]
                for change in window:
                    change["offset_seconds"] = round(float(change["ts"]) - incident["start"])
                incident["changes"] = window[:8]
        return incidents

    # ------------------------------------------------------------------ changes
    def write_changes(self, events: Iterable[dict[str, Any]],
                      node: str = LOCAL_NODE) -> int:
        """Insert change-log entries, ignoring ones already stored."""
        if not self.ready or not self.recording:
            return 0
        rows = []
        for event in events:
            if not isinstance(event, dict):
                continue
            ts = _f(event.get("ts"))
            uid = event.get("id")
            if not ts or not math.isfinite(ts) or not isinstance(uid, str):
                continue
            rows.append((
                node, uid[:200], ts, _text(event.get("kind"), 64),
                _text(event.get("source"), 64), _text(event.get("title"), 300),
                _text(event.get("detail"), 1000) if event.get("detail") is not None else None,
                _text(event.get("subject"), 200), _text(event.get("severity"), 16),
                0 if event.get("exact") is False else 1,
            ))
        if not rows:
            return 0
        with self._lock:
            conn = self._conn
            if conn is None:
                return 0
            cur = conn.executemany(
                "INSERT OR IGNORE INTO changes (node, uid, ts, kind, source, title, "
                "detail, subject, severity, exact) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows)
            conn.commit()
            return int(cur.rowcount or 0)

    def changes(self, since: float, until: float | None = None,
                node: str = LOCAL_NODE, limit: int = 500) -> list[dict[str, Any]]:
        """Stored change-log entries for one node, newest first."""
        if not self.ready:
            return []
        clauses, params = ["node = ?", "ts >= ?"], [node, since]
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        params.append(limit)
        rows = self._query(
            f"SELECT uid AS id, ts, kind, source, title, detail, subject, severity, "
            f"exact FROM changes WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?",
            tuple(params))
        out = []
        for row in rows:
            entry = dict(row)
            entry["exact"] = bool(entry.get("exact"))
            out.append(entry)
        return out

    # ------------------------------------------------------------------ deaths
    def write_death(self, node: str, uid: str, kind: str, died_at: float,
                    detected_at: float, verdict: dict[str, Any],
                    evidence: dict[str, Any], frames: bytes | None) -> int | None:
        """Store one death; None when this (node, uid) is already stored --
        an agent re-sends its report until the host answers, so the second
        copy must be a no-op rather than a second grave."""
        if not self.ready:
            return None
        with self._lock:
            conn = self._conn
            if conn is None:
                return None
            try:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO deaths (node, uid, kind, died_at, detected_at, "
                    "class, severity, title, verdict, evidence, frames) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (node, _text(uid, 200), kind, died_at, detected_at,
                     _text(verdict.get("class"), 64), _text(verdict.get("severity"), 16),
                     _text(verdict.get("title"), 300),
                     _text(json.dumps(verdict, default=str), 200_000),
                     _text(json.dumps(evidence, default=str), 400_000), frames),
                )
                conn.commit()
                return int(cur.lastrowid or 0) if cur.rowcount else None
            except (sqlite3.Error, UnicodeEncodeError) as exc:
                log.warning("death write failed: %s", exc)
                return None

    def deaths(self, node: str | None = None, since: float | None = None,
               limit: int = 50) -> list[dict[str, Any]]:
        """Deaths newest first, without the recorder frames (the list is
        polled; the frames are read for one death at a time)."""
        if not self.ready:
            return []
        clauses, params = ["1=1"], []
        if node:
            clauses.append("node = ?")
            params.append(node)
        if since:
            clauses.append("died_at >= ?")
            params.append(since)
        params.append(limit)
        rows = self._query(
            f"SELECT id, node, uid, kind, died_at, detected_at, class, severity, title, "
            f"verdict FROM deaths WHERE {' AND '.join(clauses)} ORDER BY died_at DESC LIMIT ?",
            tuple(params))
        out = []
        for row in rows:
            entry = dict(row)
            entry["verdict"] = _json(entry.pop("verdict"))
            # The frames summary travels with the verdict; the list does not
            # need the whole host context.
            out.append(entry)
        return out

    def death(self, death_id: int) -> dict[str, Any] | None:
        if not self.ready:
            return None
        rows = self._query("SELECT * FROM deaths WHERE id = ?", (death_id,))
        if not rows:
            return None
        entry = dict(rows[0])
        entry["verdict"] = _json(entry.pop("verdict"))
        entry["evidence"] = _json(entry.pop("evidence"))
        frames = entry.pop("frames", None)
        recorder: dict[str, Any] | None = None
        if frames:
            # The blob is ours (written by Coroner.record within its caps), but
            # a bounded inflate costs nothing and keeps one rule everywhere:
            # gzip from outside this process is never inflated unbounded.
            try:
                inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = inflater.decompress(bytes(frames), _MAX_FRAMES_BYTES + 1)
                if len(raw) <= _MAX_FRAMES_BYTES and inflater.eof:
                    recorder = json.loads(raw.decode("utf-8"))
            except (zlib.error, ValueError, UnicodeDecodeError):
                recorder = None
        entry["recorder"] = recorder
        return entry

    # ------------------------------------------------------------ expectations
    def list_expectations(self) -> list[dict[str, Any]]:
        if not self.ready:
            return []
        out = []
        for row in self._query("SELECT * FROM expectations ORDER BY id"):
            entry = dict(row)
            try:
                entry["days"] = json.loads(entry.get("days") or "[]")
            except ValueError:
                entry["days"] = []
            out.append(entry)
        return out

    def add_expectation(self, node: str, key: str, culprit: str | None,
                        reason: str, days: Sequence[int], start: str | None,
                        end: str | None, created_by: str | None) -> int:
        with self._lock:
            conn = self._conn
            if conn is None:
                raise sqlite3.OperationalError("history database not open")
            cur = conn.execute(
                "INSERT INTO expectations (node, key, culprit, reason, days, start, "
                "\"end\", created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (node, key, culprit, reason, json.dumps(list(days)), start, end,
                 time.time(), created_by),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def remove_expectation(self, expectation_id: int) -> bool:
        return self._execute("DELETE FROM expectations WHERE id = ?",
                             (expectation_id,)) > 0

    # ------------------------------------------------------------------ actions
    def action_record(self, node: str, name: str | None,
                      unit: str | None = None, days: int = 90) -> dict[str, Any]:
        """What happened the last times this process (or its unit) was acted
        on: per action, how many tries and how each was judged. The verdict
        store is the memory; nothing is inferred beyond counting."""
        if not self.ready or not (name or unit):
            return {"record": {}, "total": 0}
        clauses, params = ["node = ?", "ts >= ?"], [node, time.time() - days * 86400]
        alts = []
        if name:
            alts.append("name = ?")
            params.append(name)
        if unit:
            alts.append("unit = ?")
            params.append(unit)
        clauses.append("(" + " OR ".join(alts) + ")")
        rows = self._query(
            f"SELECT ts, action, name, unit, verdict FROM actions "
            f"WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT 200", tuple(params))
        record: dict[str, dict[str, Any]] = {}
        for row in rows:
            action = str(row["action"])
            try:
                verdict = json.loads(row["verdict"]) if row["verdict"] else None
            except ValueError:
                verdict = None
            outcome = str(verdict.get("outcome")) if isinstance(verdict, dict) else "pending"
            entry = record.setdefault(action, {
                "tries": 0, "outcomes": {}, "last_ts": None, "last_outcome": None,
                "last_text": None, "same_unit": bool(unit and row["unit"] == unit),
            })
            entry["tries"] += 1
            entry["outcomes"][outcome] = entry["outcomes"].get(outcome, 0) + 1
            if entry["last_ts"] is None:
                entry["last_ts"] = float(row["ts"])
                entry["last_outcome"] = outcome
                entry["last_text"] = (verdict.get("text") if isinstance(verdict, dict) else None)
        return {"record": record, "total": len(rows)}

    def record_action(self, node: str, action: str, pid: int | None,
                      name: str | None, unit: str | None, detail: dict[str, Any],
                      username: str | None) -> int:
        with self._lock:
            conn = self._conn
            if conn is None:
                return 0
            cur = conn.execute(
                "INSERT INTO actions (node, ts, action, pid, name, unit, detail, "
                "username) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (node, time.time(), action, pid, name, unit,
                 json.dumps(detail, default=str)[:8192], username),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def set_verdict(self, action_id: int, verdict: dict[str, Any]) -> None:
        self._execute("UPDATE actions SET verdict = ? WHERE id = ?",
                      (json.dumps(verdict, default=str)[:8192], action_id))

    def actions(self, since: float, node: str | None = None,
                limit: int = 200) -> list[dict[str, Any]]:
        if not self.ready:
            return []
        clauses, params = ["ts >= ?"], [since]
        if node:
            clauses.append("node = ?")
            params.append(node)
        params.append(limit)
        rows = self._query(
            f"SELECT id, node, ts, action, pid, name, unit, detail, verdict, "
            f"username FROM actions WHERE {' AND '.join(clauses)} "
            "ORDER BY ts DESC LIMIT ?", tuple(params))
        out = []
        for row in rows:
            entry = dict(row)
            for field in ("detail", "verdict"):
                try:
                    entry[field] = json.loads(entry[field]) if entry[field] else None
                except ValueError:
                    entry[field] = None
            out.append(entry)
        return out

    def stats(self) -> dict[str, Any]:
        if not self.ready:
            return {"available": False, "reason": self.error or "history disabled"}
        counts: dict[str, Any] = {}
        for table in ("samples", "proc_samples", "events", "findings", "actions",
                      "deaths"):
            rows = self._query(f"SELECT COUNT(*) AS n FROM {table}")
            counts[table] = rows[0]["n"] if rows else 0
        span = self._query("SELECT MIN(ts) AS oldest, MAX(ts) AS newest FROM samples")
        size = 0
        try:
            size = self.path.stat().st_size
            # WAL content is not in the main file until checkpoint.
            wal = self.path.with_name(self.path.name + "-wal")
            if wal.exists():
                size += wal.stat().st_size
        except OSError:
            pass
        return {
            "available": True,
            "recording": self.recording,
            "path": str(self.path),
            "size_bytes": size,
            "rows": counts,
            "oldest": span[0]["oldest"] if span else None,
            "newest": span[0]["newest"] if span else None,
        }

    def history_nodes(self) -> list[str]:
        """Node names that have stored history (enrolled or not)."""
        if not self.ready:
            return []
        return [row["node"] for row in
                self._query("SELECT DISTINCT node FROM samples ORDER BY node")]

    # ------------------------------------------------------------ users / auth
    def add_user(self, username: str, password: str, role: str = "admin") -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role: {role!r}")
        # On conflict (an existing username) only the password is refreshed --
        # this doubles as the "reset a forgotten password" flow, and a role is
        # a separate, deliberate decision (set_role / `users role`), never a
        # side effect of a password reset that might not even mention one.
        self._execute(
            "INSERT INTO users (username, password_hash, created_at, role) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
            (username, hash_password(password), time.time(), role),
        )

    def count_admins(self) -> int:
        rows = self._query(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")
        return int(rows[0]["n"]) if rows else 0

    def remove_user(self, username: str) -> bool:
        """False if no such user, or if removing it would leave zero admins."""
        row = self._query("SELECT role FROM users WHERE username = ?", (username,))
        if not row:
            return False
        if row[0]["role"] == "admin" and self.count_admins() <= 1:
            return False
        return self._execute("DELETE FROM users WHERE username = ?",
                             (username,)) > 0

    def set_role(self, username: str, role: str) -> bool:
        """False if no such user, an unknown role, or the change would leave
        zero admins."""
        if role not in ROLES:
            return False
        row = self._query("SELECT role FROM users WHERE username = ?", (username,))
        if not row:
            return False
        if row[0]["role"] == "admin" and role != "admin" and self.count_admins() <= 1:
            return False
        return self._execute("UPDATE users SET role = ? WHERE username = ?",
                             (role, username)) > 0

    def user_role(self, username: str) -> str | None:
        rows = self._query("SELECT role FROM users WHERE username = ?",
                           (username,))
        return rows[0]["role"] if rows else None

    def set_password(self, username: str, password: str) -> bool:
        """Change an existing user's password. False if no such user."""
        return self._execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(password), username)) > 0

    def user_exists(self, username: str) -> bool:
        return bool(self._query(
            "SELECT 1 FROM users WHERE username = ?", (username,)))

    def rename_user(self, old: str, new: str) -> bool:
        """Rename a user. Caller must ensure `new` is free (the UNIQUE
        constraint otherwise makes _execute log and return 0)."""
        return self._execute(
            "UPDATE users SET username = ? WHERE username = ?",
            (new, old)) > 0

    def list_users(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._query(
            "SELECT username, created_at, role FROM users ORDER BY username")]

    def verify_user(self, username: str, password: str) -> bool:
        rows = self._query("SELECT password_hash FROM users WHERE username = ?",
                           (username,))
        if not rows:
            # Burn comparable time so a missing user is not distinguishable
            # from a wrong password by response latency: exactly one scrypt,
            # against a hash computed once. (Hashing a fresh dummy here as
            # well would cost two scrypts -- a 2x latency tell that
            # tools/check_security.py measures.)
            verify_password(password, _dummy_hash())
            return False
        return verify_password(password, rows[0]["password_hash"])

    def password_hash(self, username: str) -> str | None:
        """The stored hash, which auth.py folds into the session signing key
        so a password change revokes the account's sessions."""
        rows = self._query("SELECT password_hash FROM users WHERE username = ?",
                           (username,))
        return rows[0]["password_hash"] if rows else None

    def user_credentials(self, username: str) -> tuple[str, str] | None:
        """(password_hash, role), one query -- what auth.py caches per user so
        a role change is visible exactly as fast as a password change."""
        rows = self._query(
            "SELECT password_hash, role FROM users WHERE username = ?",
            (username,))
        if not rows:
            return None
        return rows[0]["password_hash"], rows[0]["role"]

    def user_count(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM users")
        return int(rows[0]["n"]) if rows else 0

    def session_secret(self) -> bytes:
        """Stable per-installation secret for signing session cookies.

        Created on first use and stored in meta, so sessions survive restarts
        but a copied database on another machine gets its own on first boot
        only if meta was stripped -- which is the right trade for a local tool.
        """
        rows = self._query("SELECT value FROM meta WHERE key = 'session_secret'")
        if rows:
            return bytes.fromhex(rows[0]["value"])
        secret = secrets.token_bytes(32)
        self._execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('session_secret', ?)",
            (secret.hex(),),
        )
        rows = self._query("SELECT value FROM meta WHERE key = 'session_secret'")
        return bytes.fromhex(rows[0]["value"]) if rows else secret

    # ---------------------------------------------------------------- agents
    def add_agent(self, name: str) -> str:
        """Enroll an agent and return its token -- the only time it exists in
        plaintext. The stored value is a SHA-256, useless to an attacker who
        reads the database."""
        secret = secrets.token_urlsafe(32)
        token = f"{name}.{secret}"
        self._execute(
            "INSERT INTO agents (name, token_hash, enabled, created_at) "
            "VALUES (?, ?, 1, ?) "
            "ON CONFLICT(name) DO UPDATE SET token_hash=excluded.token_hash, "
            "enabled=1",
            (name, hashlib.sha256(secret.encode()).hexdigest(), time.time()),
        )
        return token

    def revoke_agent(self, name: str) -> bool:
        return self._execute("UPDATE agents SET enabled = 0 WHERE name = ?",
                             (name,)) > 0

    def remove_agent(self, name: str) -> bool:
        return self._execute("DELETE FROM agents WHERE name = ?", (name,)) > 0

    def list_agents(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._query(
            "SELECT name, enabled, created_at, last_seen, last_addr, "
            "last_auto_update, pinned_version, pinned_ref FROM agents ORDER BY name")]

    def set_agent_pin(self, name: str, version: str | None, ref: str | None) -> bool:
        """Pin an agent to a version (an operator moved it there on purpose)
        or clear the pin with (None, None). Returns whether the row exists."""
        return self._execute(
            "UPDATE agents SET pinned_version = ?, pinned_ref = ? WHERE name = ?",
            (version, ref, name)) > 0

    def mark_auto_updated(self, name: str, today: str) -> bool:
        """Atomically claim today's auto-update slot for this node. Returns
        whether it actually changed a row -- False means either the node
        does not exist or it was already updated today, so the caller must
        not fire the command either way."""
        return self._execute(
            "UPDATE agents SET last_auto_update = ? WHERE name = ? "
            "AND (last_auto_update IS NULL OR last_auto_update != ?)",
            (today, name, today)) > 0

    def verify_agent_token(self, token: str) -> str | None:
        """'<name>.<secret>' -> the agent name, or None. Constant-time hash
        comparison; disabled agents fail exactly like unknown ones."""
        name, dot, secret = token.partition(".")
        if not dot or not name or not secret:
            return None
        rows = self._query(
            "SELECT token_hash, enabled FROM agents WHERE name = ?", (name,))
        digest = hashlib.sha256(secret.encode()).hexdigest()
        if not rows:
            hmac.compare_digest(digest, digest)  # equalise timing
            return None
        row = rows[0]
        if hmac.compare_digest(digest, row["token_hash"]) and row["enabled"]:
            return name
        return None

    def touch_agent(self, name: str, addr: str | None) -> None:
        self._execute("UPDATE agents SET last_seen = ?, last_addr = ? "
                      "WHERE name = ?", (time.time(), addr, name))

    # -------------------------------------------------------------- internals
    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            conn = self._conn
            if conn is None:
                return []
            try:
                return conn.execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                log.warning("query failed: %s -- %s", sql.split()[0], exc)
                return []

    def _execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            conn = self._conn
            if conn is None:
                return 0
            try:
                cursor = conn.execute(sql, params)
                conn.commit()
                return cursor.rowcount or 0
            except sqlite3.Error as exc:
                log.warning("write failed: %s -- %s", sql.split()[0], exc)
                return 0


# ------------------------------------------------------------------ migration
def _migrate(conn: sqlite3.Connection) -> None:
    """v1 -> v2: the multi-node schema.

    samples/proc_samples need the node in their PRIMARY KEY (otherwise two
    nodes' buckets at the same timestamp REPLACE each other), and SQLite
    cannot alter a primary key -- so those two are rebuilt with existing rows
    tagged 'local'. events/findings only gain a column.
    """
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        version = int(row[0]) if row else None
    except sqlite3.Error:
        version = None  # fresh database; _SCHEMA creates everything
    if version is None or version >= SCHEMA_VERSION:
        return

    log.info("migrating history database v%s -> v%s", version, SCHEMA_VERSION)
    if version >= 2:
        # v2 -> v3 -> v4 only add tables; CREATE IF NOT EXISTS is the whole job.
        # v5 and v6 each add a column to an existing table, which needs an
        # explicit ALTER (CREATE TABLE IF NOT EXISTS is a no-op there). Every
        # user predating roles gets 'admin' -- the single tier they already
        # had, not a silent downgrade.
        conn.executescript(_SCHEMA)
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN last_auto_update TEXT")
        except sqlite3.Error:
            pass  # column already there (partial earlier migration)
        # v7: the version pin (an operator's explicit downgrade).
        for column in ("pinned_version TEXT", "pinned_ref TEXT"):
            try:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {column}")
            except sqlite3.Error:
                pass
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        except sqlite3.Error:
            pass  # column already there (partial earlier migration)
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES "
                     "('schema_version', ?)", (str(SCHEMA_VERSION),))
        conn.commit()
        return
    old_sample_cols = ", ".join(_SAMPLE_COLUMNS)
    conn.executescript("""
        BEGIN;
        ALTER TABLE samples RENAME TO samples_v1;
        ALTER TABLE proc_samples RENAME TO proc_samples_v1;
        COMMIT;
    """)
    conn.executescript(_SCHEMA)
    conn.executescript(f"""
        BEGIN;
        INSERT INTO samples (node, {old_sample_cols})
            SELECT 'local', {old_sample_cols} FROM samples_v1;
        INSERT INTO proc_samples (node, ts, pid, name, cpu, working_set,
                                  io_bytes_sec, gpu, lag_score)
            SELECT 'local', ts, pid, name, cpu, working_set, io_bytes_sec,
                   gpu, lag_score FROM proc_samples_v1;
        DROP TABLE samples_v1;
        DROP TABLE proc_samples_v1;
        COMMIT;
    """)
    for statement in ("ALTER TABLE events ADD COLUMN node TEXT NOT NULL DEFAULT 'local'",
                      "ALTER TABLE findings ADD COLUMN node TEXT NOT NULL DEFAULT 'local'"):
        try:
            conn.execute(statement)
        except sqlite3.Error:
            pass  # column already there (partial earlier migration)
    conn.commit()


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    """scrypt via hashlib -- memory-hard, stdlib, no dependency."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    """A real scrypt hash of a throwaway password, made once per process, for
    the unknown-user branch of verify_user to spend its time against."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("timing-equalizer")
    return _DUMMY_HASH


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(),
                                salt=bytes.fromhex(salt_hex),
                                n=2 ** 14, r=8, p=1)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------- helpers
def aggregate_window(samples: Sequence[dict[str, Any]],
                     lag_severity: str | None = None) -> dict[str, Any]:
    """Collapse a bucket's worth of fast samples into one history row."""

    def pull(*path: str) -> list[float]:
        values: list[float] = []
        for sample in samples:
            node: Any = sample
            for key in path:
                if not isinstance(node, dict):
                    node = None
                    break
                node = node.get(key)
            if isinstance(node, (int, float)) and not isinstance(node, bool):
                number = _f(node)
                if number is not None and math.isfinite(number):
                    values.append(number)
        return values

    def avg(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 3) if values else None

    def mx(values: list[float]) -> float | None:
        return round(max(values), 3) if values else None

    def mn(values: list[float]) -> float | None:
        return round(min(values), 3) if values else None

    cpu = pull("cpu", "total")
    queue = pull("cpu", "queue_per_core")
    mem_pct = pull("memory", "percent")
    mem_avail = pull("memory", "available_mb")
    commit = pull("memory", "commit_percent")
    faults = pull("memory", "hard_faults_sec")
    gpu = pull("gpu", "total")
    busy = pull("disk", "total", "busy_percent")
    dqueue = pull("disk", "total", "queue_length")
    latency = pull("disk", "total", "latency_ms")
    read = pull("disk", "total", "read_bytes_sec")
    write = pull("disk", "total", "write_bytes_sec")
    recv = pull("network", "total", "recv_bytes_sec")
    sent = pull("network", "total", "sent_bytes_sec")

    return {
        "n": len(samples),
        "cpu_avg": avg(cpu), "cpu_max": mx(cpu),
        "cpu_queue_avg": avg(queue), "cpu_queue_max": mx(queue),
        "mem_percent_avg": avg(mem_pct), "mem_available_min": mn(mem_avail),
        "commit_avg": avg(commit), "commit_max": mx(commit),
        "hard_faults_avg": avg(faults), "hard_faults_max": mx(faults),
        "gpu_avg": avg(gpu), "gpu_max": mx(gpu),
        "disk_busy_avg": avg(busy), "disk_busy_max": mx(busy),
        "disk_queue_avg": avg(dqueue), "disk_queue_max": mx(dqueue),
        "disk_latency_avg": avg(latency), "disk_latency_max": mx(latency),
        "disk_read_avg": avg(read), "disk_write_avg": avg(write),
        "net_recv_avg": avg(recv), "net_sent_avg": avg(sent),
        "lag_severity": lag_severity,
    }


_SEVERITY_RANK = {"ok": 0, "info": 1, "warn": 2, "critical": 3}


def _close_incident(current: dict[str, Any], bucket_seconds: int,
                    now: float) -> dict[str, Any]:
    names = sorted(current.pop("_names").values(),
                   key=lambda c: (-c["led"], -c["buckets"], c["name"]))
    last = current.pop("_last")
    current.pop("_first_by_severity", None)
    end = last + bucket_seconds
    current["end"] = end
    current["duration_seconds"] = round(end - current["start"])
    # Still being written to: the latest bucket is the current one.
    current["ongoing"] = now - last < bucket_seconds * 2.5
    current["culprits"] = names[:5]
    current["lead"] = names[0] if names else None
    current["id"] = f"{current['key']}@{int(current['start'])}"
    return current


def _compact(event: dict[str, Any]) -> dict[str, Any]:
    """Strip the bulky/redundant fields before storing an event as JSON."""
    return {
        key: value for key, value in event.items()
        if key not in ("data", "source_label", "channel", "computer")
        and value is not None
    }


def _json(value: Any) -> Any:
    """A stored JSON column, or None when it is empty or damaged."""
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _f(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _i(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if abs(number) < 2 ** 63 else None


def _text(value: Any, limit: int = 4096) -> str:
    """str() that SQLite will accept: no lone surrogates, bounded length."""
    text = str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "replace").decode("utf-8")
    return text[:limit]
