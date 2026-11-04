"""Command-line entry points for repeatable operation of the lab."""

import argparse
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from .dashboard import make_server
from .detection import catalog
from .ingestion import MAX_BATCH, read_jsonl
from .model import Json
from .reports import export, summary
from .scenarios import EXTRAS, envelopes, fixture_catalog, suite, write_jsonl
from .storage import accept, case_detail, database, reject, replay, set_meta

DEFAULT_DB = Path("var/lab.sqlite")


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="secops-lab", description=__doc__)
    cli.add_argument(
        "--db", type=Path, default=DEFAULT_DB, help="SQLite path (default var/lab.sqlite)"
    )
    commands = cli.add_subparsers(dest="command", required=True)
    demo = commands.add_parser(
        "demo", help="Generate, ingest, replay and validate the safe fixture suite"
    )
    demo.add_argument("--out", type=Path, default=Path("var/demo"))
    generate = commands.add_parser("generate", help="Generate bounded synthetic JSONL")
    generate.add_argument(
        "--scenario", choices=["all", *EXTRAS, *(r["scenario"] for r in catalog())], default="all"
    )
    generate.add_argument("--negative", action="store_true")
    generate.add_argument("--out", type=Path, default=Path("var/synthetic.jsonl"))
    commands.add_parser("scenarios", help="Print the scenario catalog")
    for name in ("normalize", "ingest"):
        item = commands.add_parser(name)
        item.add_argument("input", type=Path)
        item.add_argument("--limit", type=int, default=MAX_BATCH)
        item.add_argument("--allow-real", action="store_true")
    commands.add_parser("replay", help="Evaluate local rules and create alerts and cases")
    validate = commands.add_parser("validate", help="Run the labeled safe detection suite")
    validate.add_argument("--out", type=Path, default=Path("var/validation.json"))
    report = commands.add_parser("report")
    report.add_argument("--out", type=Path)
    dashboard = commands.add_parser("dashboard")
    dashboard.add_argument("--port", type=int, default=8765)
    case = commands.add_parser("case")
    case.add_argument("id")
    case.add_argument("--status", choices=["open", "investigating", "closed"])
    case.add_argument("--note")
    case.add_argument("--out", type=Path)
    cloud = commands.add_parser("cloud-pull")
    cloud.add_argument("--project", required=True)
    cloud.add_argument("--limit", type=int, default=10)
    cloud.add_argument("--authorized", action="store_true", required=True)
    return cli


def emit(data: object) -> None:
    print(json.dumps(data, ensure_ascii=True, indent=2))


def ingest(conn: sqlite3.Connection, path: Path, limit: int, allow_real: bool = False) -> Json:
    counts = {"accepted": 0, "duplicate": 0, "rejected": 0}
    for line, source, item in read_jsonl(path, limit, allow_real):
        if isinstance(item, str):
            reject(conn, source, path.name, line, item)
            counts["rejected"] += 1
        else:
            counts["accepted" if accept(conn, item) else "duplicate"] += 1
    return counts


def get_case(conn: sqlite3.Connection, case_id: str) -> Json:
    case = case_detail(conn, case_id)
    if case is None:
        raise ValueError("case ID not found; use the complete ID from the JSON report")
    return case


def update_case(args: argparse.Namespace) -> None:
    with database(args.db) as conn:
        conn.execute("BEGIN IMMEDIATE")
        case = get_case(conn, args.id)
        if args.status or args.note:
            now = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
            notes = case["notes"]
            if args.note:
                if len(args.note) > 2000:
                    raise ValueError("note exceeds 2000 characters")
                notes.append({"timestamp": now, "text": args.note})
            conn.execute(
                "UPDATE cases SET status=?,notes=?,updated=? WHERE id=?",
                (args.status or case["status"], json.dumps(notes), now, args.id),
            )
            case = get_case(conn, args.id)
        if args.out:
            export(args.out, case, case=True)
    emit(case)


def run(args: argparse.Namespace) -> int:
    match args.command:
        case "scenarios":
            emit(fixture_catalog())
        case "generate":
            if args.scenario == "all" and args.negative:
                raise ValueError("--negative requires a specific scenario")
            rows = (
                suite()[0]
                if args.scenario == "all"
                else envelopes(args.scenario, not args.negative)
            )
            write_jsonl(args.out, rows)
            emit({"generated": len(rows), "file": str(args.out), "origin": "synthetic"})
        case "normalize":
            had_errors = False
            for line, source, item in read_jsonl(args.input, args.limit, args.allow_real):
                if isinstance(item, str):
                    had_errors = True
                    print(
                        json.dumps({"line": line, "source": source, "error": item}), file=sys.stderr
                    )
                else:
                    print(
                        json.dumps(
                            {
                                "id": item.id,
                                "source": item.source,
                                "origin": item.origin,
                                "raw": item.raw,
                                "parsed": item.parsed,
                                "udm": item.udm,
                            }
                        )
                    )
            return int(had_errors)
        case "ingest":
            with database(args.db) as conn:
                result = ingest(conn, args.input, args.limit, args.allow_real)
            emit(result)
            return int(result["rejected"] > 0)
        case "replay":
            with database(args.db) as conn:
                emit(replay(conn))
        case "demo":
            fixtures, validation = suite()
            target = args.out / "events.jsonl"
            write_jsonl(target, fixtures)
            with database(args.db) as conn:
                result = ingest(conn, target, MAX_BATCH)
                set_meta(conn, "validation", validation)
            with database(args.db) as conn:
                results = replay(conn)
            with database(args.db, readonly=True) as conn:
                doc = summary(conn)
            export(args.out / "report.json", doc)
            export(args.out / "report.md", doc)
            export(args.out / "validation.json", validation)
            emit(
                {
                    "ingestion": result,
                    "replay": results,
                    "fixture_checks": f"{validation['passed']}/{validation['total']}",
                    "out": str(args.out),
                }
            )
            return int(validation["passed"] != validation["total"] or result["rejected"] > 0)
        case "validate":
            _, validation = suite()
            export(args.out, validation)
            with database(args.db) as conn:
                set_meta(conn, "validation", validation)
            emit(validation)
            return int(validation["passed"] != validation["total"])
        case "report":
            with database(args.db, readonly=True) as conn:
                doc = summary(conn)
            if args.out:
                export(args.out, doc)
            else:
                emit(doc)
        case "case":
            update_case(args)
        case "dashboard":
            with database(args.db):
                pass
            with make_server(args.db, args.port) as server:
                print(f"Local SOC console at http://127.0.0.1:{server.server_port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        case "cloud-pull":
            from .cloud import pull_once

            emit(pull_once(args.db, args.project, args.limit))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (ValueError, OSError, sqlite3.Error, ImportError) as error:
        print(f"secops-lab: {error}", file=sys.stderr)
        return 2
