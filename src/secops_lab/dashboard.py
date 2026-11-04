"""A loopback-only, read-only SOC console using the laboratory database."""

import json
import sqlite3
from collections.abc import Iterable
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

from .model import Json
from .reports import case_markdown, summary
from .storage import case_detail, database

STYLE = """
:root{color-scheme:dark;--bg:#0a111d;--panel:#111d2d;--line:#29394f;--text:#e5efff;--muted:#a9bcd4;--cyan:#55ded2;--hot:#ff9d91;--med:#fbd078}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}
main{max-width:1280px;margin:auto;padding:34px 32px 60px}header{border-bottom:1px solid var(--line);padding-bottom:24px}
h1{font-size:40px;margin:0;letter-spacing:-1.5px}h2{font-size:20px;margin:0 0 12px}
p{margin:4px 0 12px}.muted{color:var(--muted)}.eyebrow{color:var(--cyan);font-size:12px;font-weight:750;letter-spacing:2px;text-transform:uppercase}
a{color:var(--cyan)}a:focus-visible{outline:2px solid var(--cyan);outline-offset:4px}
.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}
.tile,section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px 20px;min-width:0}
.tile strong{display:block;font-size:32px;letter-spacing:-1px;line-height:1.2}.tile span{color:var(--muted)}
.columns{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:0 0 14px}
.wide{margin-bottom:14px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}
th,td{border-bottom:1px solid var(--line);padding:7px 9px;vertical-align:top}
th{font-size:11px;color:var(--muted);letter-spacing:.8px;text-transform:uppercase}td{overflow-wrap:anywhere}tr:last-child td{border:0}
.badge{border:1px solid var(--line);display:inline-block;border-radius:100px;padding:2px 9px;margin:2px 4px 2px 0;font-size:12px}
.high{color:var(--hot)}.medium{color:var(--med)}.good{color:var(--cyan)}
code,pre{font-family:ui-monospace,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere}
.feature{border-color:#357574;background:linear-gradient(120deg,#112b34,var(--panel) 62%)}
.feature h2{font-size:23px}.feature .eyebrow{margin-bottom:5px}.steps{margin:12px 0 0;padding-left:22px}
.steps li{margin:8px 0}.steps code{overflow-wrap:anywhere}details{margin-top:12px}
summary{cursor:pointer;color:var(--cyan)}.callout{color:var(--med);border-left:3px solid;padding-left:10px}
@media(max-width:850px){.columns{grid-template-columns:1fr}.tiles{grid-template-columns:1fr 1fr}main{padding:22px 14px}h1{font-size:32px}}
"""


def e(value: object) -> str:
    return escape(str(value))


def table(heads: Iterable[str], data: Iterable[Iterable[str]]) -> str:
    header = "".join(f"<th scope='col'>{e(head)}</th>" for head in heads)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>" for cells in data
    )
    if not body:
        return "<p class='muted'>No records available.</p>"
    return f"<div class='scroll'><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>"


def case_link(case_id: str, label: str) -> str:
    return f'<a href="/cases/{e(case_id)}">{e(label)}</a>'


def section(title: str, body: str, css: str = "") -> str:
    return f'<section class="{css}"><h2>{e(title)}</h2>{body}</section>'


def page(title: str, label: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{e(title)} | GoogleSecOps-Lab</title><style>{STYLE}</style><main>"
        f"<header><div class='eyebrow'>{e(label)}</div><h1>{e(title)}</h1>"
        "<p class='muted'>Custom laboratory interface · Local Python detection · Chronicle validation pending</p>"
        f"</header>{body}</main></html>"
    )


def overview(doc: Json) -> str:
    v = doc["validation"]
    metrics = [
        (doc["totals"]["accepted"], "Accepted events"),
        (doc["alerts_total"], "Local alerts"),
        (doc["case_total"], "Investigation cases"),
        (f"{v['passed']}/{v['total']}" if v else "Pending", "Fixture checks"),
    ]
    tiles = "".join(
        f"<div class='tile'><strong>{e(n)}</strong><span>{e(label)}</span></div>"
        for n, label in metrics
    )
    queue = table(
        ("Subject", "Playbook", "Status", "Risk"),
        (
            [case_link(x["id"], x["subject"]), e(x["category"]), e(x["status"]), e(x["risk"])]
            for x in doc["queue"]
        ),
    )
    volume = table(
        ("Source", "Accepted", "Duplicate", "Rejected"),
        (
            [e(x[k]) for k in ("source", "accepted", "duplicate", "rejected")]
            for x in doc["ingestion"]
        ),
    )
    alerts = table(
        ("UTC time", "Rule", "Severity", "Case"),
        (
            [
                e(x["timestamp"][:19].replace("T", " ")),
                e(x["rule_id"]),
                f'<span class="{e(x["severity"])}">{e(x["severity"])}</span>',
                case_link(x["case_id"], x["case_id"][:10]),
            ]
            for x in doc["recent_alerts"]
        ),
    )
    counts = ", ".join(f"{x['total']} {x['severity']}" for x in doc["severity"]) or "no alerts"
    origins = ", ".join(f"{x['total']} {x['origin']}" for x in doc["origin"]) or "no events"
    success = doc["parse_success_rate"]
    rate = (
        f"{success:.1%} success / {1 - success:.1%} rejected"
        if success is not None
        else "waiting for input"
    )
    health = f"<p><b>SQLite</b> · reachable</p><p><b>Ingestion</b> · {e(rate)}</p>"
    health += f"<p><b>Provenance</b> · {e(origins)}</p><p><b>Severity</b> · {e(counts)}</p>"
    health += (
        f"<p><b>Sources</b> · {len(doc['ingestion'])} seen / {len(doc['sources'])} supported</p>"
    )
    if v:
        health += (
            f"<p><b>Fixture precision</b> · {v['precision']:.1%} · {v['fp']} false positive(s)</p>"
        )
    attack = "".join(
        f"<span class='badge{' good' if t in doc['attack_observed'] else ''}'>{e(t)}</span>"
        for t in doc["attack"]
    )
    rule_counts = table(
        ("Rule", "Alerts"), ([e(x["rule_id"]), e(x["total"])] for x in doc["rule_counts"])
    )
    source_coverage = table(
        ("Adapter", "State"),
        (
            [
                e(source),
                "Observed"
                if any(row["source"] == source and row["accepted"] for row in doc["ingestion"])
                else "Awaiting input",
            ]
            for source in doc["sources"]
        ),
    )
    fixture_checks = table(
        ("Scenario", "Expected", "Observed", "Result"),
        (
            [
                e(x["scenario"]),
                e(", ".join(x["expected"]) or "—"),
                e(", ".join(x["actual"]) or "—"),
                "Pass" if x["passed"] else "Fail",
            ]
            for x in v.get("tests", [])
        ),
    )
    rejected = table(
        ("Source", "Record", "Reason"),
        ([e(x["source"]), e(x["line"]), e(x["reason"])] for x in doc["recent_rejects"]),
    )
    return page(
        "SOC Operations Console",
        "GoogleSecOps-Lab / Operations",
        f"<div class='tiles'>{tiles}</div>"
        + iam_overview(doc)
        + "<div class='columns'>"
        + section("Incident queue", queue)
        + section("Pipeline health", health)
        + "</div><div class='columns'>"
        + section("Ingestion by source", volume)
        + section("Alert timeline", alerts)
        + "</div>"
        + section(
            "MITRE ATT&CK coverage",
            "<p class='muted'>Observed techniques are highlighted.</p>" + attack,
            "wide",
        )
        + "<div class='columns'>"
        + section("Detection counts", rule_counts)
        + section("Source coverage", source_coverage)
        + "</div>"
        + section("Detection fixture results", fixture_checks, "wide")
        + section("Ingestion errors", rejected),
    )


def iam_overview(doc: Json) -> str:
    evaluation = doc["iam_evaluation"]
    cases = doc["iam_cases"]
    if not (evaluation or cases):
        return ""
    links = "".join(
        f"<li>{case_link(item['case_id'], item['subject'])} · {e(item['timestamp'][:19])} UTC</li>"
        for item in cases
    )
    body = (
        "<div class='eyebrow'>Identity detection · GSL020</div>"
        "<p>Trace a sensitive grant to the beneficiary's observed activity.</p>"
        + (f"<ul class='steps'>{links}</ul>" if links else "")
    )
    if evaluation:

        def pct(value: float | None) -> str:
            return f"{value:.1%}" if value is not None else "—"

        scores = table(
            ("Rule", "Precision", "Recall", "True positives", "False positives", "Missed"),
            (
                [
                    e(rule),
                    pct(score["precision"]),
                    pct(score["recall"]),
                    e(score["tp"]),
                    e(score["fp"]),
                    e(score["fn"]),
                ]
                for rule, score in evaluation["metrics"].items()
            ),
        )
        examples = table(
            ("Scenario", "Ground truth", "GSL020", "Evidence"),
            (
                [
                    e(item["case"]),
                    "Malicious" if item["malicious"] else "Benign",
                    "Alert" if item["observed"]["GSL020"] else "No alert",
                    e(item["purpose"]),
                ]
                for item in evaluation["cases"]
            ),
        )
        body += (
            f"<details><summary>Evaluation · {evaluation['total']} synthetic scenarios</summary>"
            + scores
            + examples
            + "</details>"
        )
    return section("IAM grant investigations", body, "feature wide")


def iam_investigation(case: Json) -> str:
    panels = []
    for alert in case["alerts"]:
        context = alert.get("context", {})
        if not context.get("grant_event_id"):
            continue
        review = (
            "<p class='callout'>Needs review. The current replay no longer confirms this sequence. "
            "Earlier evidence is retained.</p>"
            if alert.get("correlation_state") == "needs_review"
            else ""
        )
        panels.append(
            review + f"<p><b>Project</b> {e(context['project'])} · "
            f"<b>Time to observed use</b> {e(context['elapsed_seconds'])} seconds</p>"
            "<ol class='steps'>"
            f"<li><b>Grant.</b> {e(context['grant_actor'] or 'Actor unavailable')} granted "
            f"<code>{e(context['role'])}</code> to <code>{e(context['beneficiary'])}</code> "
            f"on <code>{e(context['grant_resource'])}</code>. "
            f"<a href='#event-{e(context['grant_event_id'])}'>Grant evidence</a></li>"
            f"<li><b>Activity.</b> The beneficiary used <code>{e(context['permission'])}</code> "
            f"on <code>{e(context['activity_resource'])}</code>. "
            f"<a href='#event-{e(context['activity_event_id'])}'>Activity evidence</a></li></ol>"
            "<p class='muted'>The sequence shows observed use after the grant. "
            "Another binding may also have authorized the activity.</p>"
        )
    return section("Why this case fired", "".join(panels), "feature wide") if panels else ""


def investigation(case: Json) -> str:
    evidence = table(
        ("UTC time", "Source", "Origin", "Operation and evidence"),
        (
            [
                e(x["timestamp"]),
                e(x["source"]),
                e(x["origin"]),
                f"<span id='event-{e(x['id'])}'>{e(x['product_event_type'])}</span>"
                + "".join(
                    f"<br><small>{e(change['action'])} · {e(change['role'])} · {e(change['member'])}"
                    f"{' · conditional' if change['condition'] is not None else ''}</small>"
                    for change in x.get("iam_changes", [])
                ),
            ]
            for x in case["timeline"]
        ),
    )
    notes = "".join(
        f"<li>{e(note['text'])} <small>{e(note['timestamp'])}</small></li>"
        for note in case["notes"]
    )
    alert_html = ""
    for alert in case["alerts"]:
        triage = alert["triage"]
        steps = "".join(f"<li>{e(step)}</li>" for step in triage["recommendations"])
        ips = ", ".join(f"{address} ({value})" for address, value in triage["ip_context"].items())
        domains = ", ".join(
            f"{domain} ({value})" for domain, value in triage["domain_context"].items()
        )
        alert_html += (
            f"<h3>{e(alert['rule_id'])} · {e(alert['title'])}</h3>"
            f"<p>{e(alert['severity'])} · confidence {e(triage['confidence'])} · "
            f"{e(', '.join(alert['attack']))}</p><p>{e(ips)}</p><p>{e(domains)}</p><ol>{steps}</ol>"
        )
    return page(
        case["subject"],
        "Investigation / " + case["id"][:12],
        "<p><a href='/'>← Operations overview</a></p>"
        f"<p>{e(case['status'])} · risk {e(case['risk'])} · {e(case['category'])}</p>"
        + f"<p><a href='/cases/{e(case['id'])}/report.md' download='case-{e(case['id'][:12])}.md'>Download case report</a></p>"
        + iam_investigation(case)
        + section("Evidence timeline", evidence, "wide")
        + section("Dry-run playbook", alert_html, "wide")
        + section("Analyst notes", f"<ul>{notes}</ul>" if notes else "<p>No notes yet.</p>"),
    )


def make_server(path: Path, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, content: str, mime: str = "text/html") -> None:
            payload = content.encode()
            self.send_response(status)
            self.send_header("Content-Type", f"{mime}; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            # Reject foreign hosts to reduce exposure through DNS rebinding.
            if self.headers.get("Host", "") not in (
                f"127.0.0.1:{cast(ThreadingHTTPServer, self.server).server_port}",
                f"localhost:{cast(ThreadingHTTPServer, self.server).server_port}",
            ):
                self.respond(400, "Invalid host", "text/plain")
                return
            try:
                with database(path, readonly=True) as conn:
                    if self.path == "/":
                        self.respond(200, overview(summary(conn)))
                        return
                    if self.path == "/health":
                        conn.execute("SELECT 1")
                        self.respond(200, json.dumps({"database": "reachable"}), "application/json")
                        return
                    if self.path.startswith("/cases/"):
                        case_id, _, subpage = self.path.removeprefix("/cases/").partition("/")
                        case = case_detail(conn, case_id) if subpage in ("", "report.md") else None
                        if case:
                            if subpage == "report.md":
                                self.respond(200, case_markdown(case) + "\n", "text/plain")
                            else:
                                self.respond(200, investigation(case))
                            return
            except sqlite3.Error:
                self.respond(503, "Laboratory database is unavailable", "text/plain")
                return
            self.respond(404, "Page not found", "text/plain")

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
