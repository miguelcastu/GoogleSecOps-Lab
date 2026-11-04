"""Read-only reports used by the CLI and dashboard."""

import json
import sqlite3
from pathlib import Path

from .adapters import ADAPTERS
from .detection import catalog
from .model import Json
from .storage import meta, rows


def summary(conn: sqlite3.Connection) -> Json:
    ingest = rows(conn, "SELECT * FROM ingest ORDER BY source")
    totals = {
        key: sum(item[key] for item in ingest) for key in ("accepted", "duplicate", "rejected")
    }
    attempts = sum(totals.values())
    rule_catalog = catalog()
    techniques = sorted({t for rule in rule_catalog for t in rule["attack"]})
    counts = rows(
        conn, "SELECT rule_id,count(*) AS total FROM alerts GROUP BY rule_id ORDER BY rule_id"
    )
    fired = {row["rule_id"] for row in counts}
    return {
        "ingestion": ingest,
        "totals": totals,
        "parse_success_rate": round((totals["accepted"] + totals["duplicate"]) / attempts, 4)
        if attempts
        else None,
        "origin": rows(conn, "SELECT origin,count(*) AS total FROM events GROUP BY origin"),
        "severity": rows(conn, "SELECT severity,count(*) AS total FROM alerts GROUP BY severity"),
        "rule_counts": counts,
        "attack": techniques,
        "attack_observed": sorted(
            {t for rule in rule_catalog if rule["id"] in fired for t in rule["attack"]}
        ),
        "sources": sorted(ADAPTERS),
        "recent_alerts": rows(
            conn,
            """SELECT id,timestamp,rule_id,severity,case_id
                                      FROM alerts ORDER BY timestamp DESC,id LIMIT 30""",
        ),
        "queue": rows(
            conn,
            """SELECT id,subject,category,status,risk,updated FROM cases
                               ORDER BY status='closed',risk DESC,updated DESC,id LIMIT 50""",
        ),
        "case_total": conn.execute("SELECT count(*) FROM cases").fetchone()[0],
        "alerts_total": sum(row["total"] for row in counts),
        "recent_rejects": rows(
            conn,
            """SELECT source,input_ref,line,reason FROM rejects
                                       ORDER BY rowid DESC LIMIT 20""",
        ),
        "last_replay": meta(conn, "last_replay"),
        "validation": meta(conn, "validation"),
        "health": {"database": "reachable", "mode": "local-python", "native_validation": "PENDING"},
    }


def export(path: Path, document: Json, *, case: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        contents = json.dumps(document, ensure_ascii=False, indent=2)
    elif path.suffix == ".md":
        if case:
            contents = case_markdown(document)
        else:
            validation = document["validation"]
            lines = [
                "# Local SOC report",
                "",
                f"- Events: {document['totals']['accepted']}",
                f"- Alerts: {document['alerts_total']}",
                f"- Cases: {document['case_total']}",
                f"- Source adapters: {len(document['sources'])}",
                f"- Local fixture validation: {validation.get('passed', 0)}/{validation.get('total', 0)}",
                "- Google SecOps native validation: PENDING",
                "",
                "## Rule results",
                "",
            ]
            lines.extend(f"- {row['rule_id']}: {row['total']}" for row in document["rule_counts"])
            contents = "\n".join(lines)
    else:
        raise ValueError("output must end in .json or .md")
    path.write_text(contents + "\n", encoding="utf-8")


def safe_md(value: str) -> str:
    return value.replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ").replace("\r", " ")


def case_markdown(case: Json) -> str:
    lines = [
        f"# Case {case['id'][:12]}",
        "",
        f"- Subject: {safe_md(case['subject'])}",
        f"- Status: {case['status']}",
        f"- Risk: {case['risk']}",
        "",
        "## Evidence timeline",
        "",
    ]
    lines.extend(
        f"- {event['timestamp']} · {event['source']} ({event['origin']}) · "
        f"{safe_md(event['product_event_type'])} · {event['id']}"
        for event in case["timeline"]
    )
    lines.extend(["", "## Alerts and recommendations", ""])
    for alert in case["alerts"]:
        lines.append(f"- {alert['rule_id']} {alert['title']} ({alert['severity']})")
        for entry in alert["triage"]["attack"]:
            lines.append(f"  - [{entry['id']}]({entry['url']})")
        lines.extend(f"  - Dry run: {entry}" for entry in alert["triage"]["recommendations"])
    lines.extend(["", "## Analyst notes", ""])
    lines.extend(f"- {note['timestamp']} · {safe_md(note['text'])}" for note in case["notes"])
    return "\n".join(lines)
