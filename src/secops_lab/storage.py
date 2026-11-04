"""Transactional storage for accepted events, replay and local investigations."""

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .detection import Alert, evaluate
from .model import Event, Json, canonical
from .soar import enrich, group_case

DDL = """
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
 origin TEXT NOT NULL CHECK(origin IN ('synthetic','real')), document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events(timestamp, id);
CREATE TABLE IF NOT EXISTS ingest (
 source TEXT PRIMARY KEY, accepted INTEGER NOT NULL DEFAULT 0,
 duplicate INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rejects (
 source TEXT NOT NULL, input_ref TEXT NOT NULL, line INTEGER NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, severity TEXT NOT NULL,
 rule_id TEXT NOT NULL, case_id TEXT NOT NULL, document TEXT NOT NULL,
 FOREIGN KEY (case_id) REFERENCES cases(id)
);
CREATE INDEX IF NOT EXISTS alert_time ON alerts(timestamp, id);
CREATE INDEX IF NOT EXISTS alert_case ON alerts(case_id);
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, subject TEXT NOT NULL, category TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('open','investigating','closed')),
 updated TEXT NOT NULL, risk INTEGER NOT NULL, notes TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, document TEXT NOT NULL);
"""
MAX_REPLAY = 25000


@contextmanager
def database(path: Path, readonly: bool = False):
    if readonly:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=15)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        if not readonly:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(DDL)
        with conn:
            yield conn
    finally:
        conn.close()


def bump(conn: sqlite3.Connection, source: str, field: str) -> None:
    if field not in ("accepted", "duplicate", "rejected"):
        raise ValueError("unsupported ingestion metric")
    conn.execute(
        f"""INSERT INTO ingest (source,{field}) VALUES (?,1)
                      ON CONFLICT (source) DO UPDATE SET {field}={field}+1""",
        (source,),
    )


def accept(conn: sqlite3.Connection, event: Event) -> bool:
    cursor = conn.execute(
        "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)",
        (event.id, event.timestamp, event.source, event.origin, canonical(asdict(event))),
    )
    inserted = bool(cursor.rowcount)
    bump(conn, event.source, "accepted" if inserted else "duplicate")
    return inserted


def reject(conn: sqlite3.Connection, source: str, input_ref: str, line: int, reason: str) -> None:
    conn.execute("INSERT INTO rejects VALUES (?,?,?,?)", (source, input_ref, line, reason))
    bump(conn, source, "rejected")


def load_event(row: sqlite3.Row) -> Event:
    return Event(**json.loads(row["document"]))


def upsert_alert(conn: sqlite3.Connection, alert: Alert, events: list[Event]) -> None:
    case_id = group_case(alert, events)
    triage = enrich(alert, events)
    conn.execute(
        """INSERT INTO cases (id, subject, category, status, updated, risk) VALUES (?,?,?,'open',?,?)
           ON CONFLICT(id) DO UPDATE SET updated=max(updated,excluded.updated),
           risk=max(risk,excluded.risk)""",
        (case_id, alert.subject, alert.playbook, alert.timestamp, triage["risk"]),
    )
    document = asdict(alert) | {"engine": "local-python", "triage": triage}
    conn.execute(
        "INSERT INTO alerts VALUES (?,?,?,?,?,?)",
        (alert.id, alert.timestamp, alert.severity, alert.rule_id, case_id, canonical(document)),
    )


def replay(conn: sqlite3.Connection) -> Json:
    conn.execute("BEGIN IMMEDIATE")
    events = [
        load_event(row)
        for row in conn.execute(
            "SELECT document FROM events ORDER BY timestamp,id LIMIT ?", (MAX_REPLAY + 1,)
        )
    ]
    if len(events) > MAX_REPLAY:
        raise ValueError(f"replay exceeds {MAX_REPLAY} events; use a fresh database")
    by_id = {event.id: event for event in events}
    alerts = evaluate(events)
    old = {row[0] for row in conn.execute("SELECT id FROM alerts")}
    for alert in alerts:
        if alert.id not in old:
            upsert_alert(conn, alert, [by_id[event_id] for event_id in alert.event_ids])
    # Late input can shift a threshold alert. Preserve prior evidence and analyst state.
    set_meta(
        conn,
        "last_replay",
        {
            "events": len(events),
            "computed": len(alerts),
            "new": sum(alert.id not in old for alert in alerts),
        },
    )
    return {
        "events": len(events),
        "alerts_computed": len(alerts),
        "alerts_added": sum(alert.id not in old for alert in alerts),
        "cases": conn.execute("SELECT count(*) FROM cases").fetchone()[0],
    }


def rows(conn: sqlite3.Connection, sql: str, args: tuple[Any, ...] = ()) -> list[Json]:
    return [dict(row) for row in conn.execute(sql, args)]


def set_meta(conn: sqlite3.Connection, key: str, data: Json) -> None:
    conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, canonical(data)))


def meta(conn: sqlite3.Connection, key: str) -> Json:
    row = conn.execute("SELECT document FROM meta WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else {}


def case_detail(conn: sqlite3.Connection, case_id: str) -> Json | None:
    cases = rows(conn, "SELECT * FROM cases WHERE id=?", (case_id,))
    if not cases:
        return None
    case = cases[0]
    case["notes"] = json.loads(case["notes"])
    alerts = [
        json.loads(row[0])
        for row in conn.execute(
            "SELECT document FROM alerts WHERE case_id=? ORDER BY timestamp,id", (case_id,)
        )
    ]
    case["alerts"] = alerts
    evidence = set(event_id for alert in alerts for event_id in alert["event_ids"])
    case["timeline"] = [
        {
            "id": event.id,
            "timestamp": event.timestamp,
            "source": event.source,
            "origin": event.origin,
            "product_event_type": event.parsed["action"],
            "udm": event.udm,
        }
        for event in (
            load_event(row)
            for row in conn.execute("SELECT id,document FROM events ORDER BY timestamp,id")
            if row["id"] in evidence
        )
    ]
    return case
