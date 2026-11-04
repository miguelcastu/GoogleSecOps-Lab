"""Operate only an explicitly approved, labeled GCP lab project."""

import argparse
import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from secops_lab.cloud import PROJECT, SUBSCRIPTION, pull_once
from secops_lab.model import get
from secops_lab.storage import database, load_event

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "var" / "cloud"
SINK = "gsl-audit-routing"
TOPIC = "gsl-audit"
METHOD = "google.pubsub.v1.Publisher.UpdateTopic"


def cmd(tool: str, *args: str, capture: bool = False, timeout: int = 180) -> str:
    executable = shutil.which(tool)
    if not executable:
        raise ValueError(f"install {tool} before running cloud operations")
    result = subprocess.run(
        [executable, *args],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        capture_output=capture,
        timeout=timeout,
    )
    return result.stdout.strip() if capture else ""


def tf(*args: str, capture: bool = False) -> str:
    return cmd("terraform", "-chdir=infrastructure", *args, capture=capture)


def gcloud(*args: str, project: str, capture: bool = True) -> str:
    return cmd("gcloud", *args, f"--project={project}", "--quiet", capture=capture, timeout=35)


def guard(project: str) -> None:
    if not PROJECT.fullmatch(project):
        raise ValueError("use the dedicated gsl-* project ID")
    raw = gcloud(
        "projects", "describe", project, "--format=value(labels.application)", project=project
    )
    if raw != "googlesecops-lab":
        raise ValueError("project must be labeled application=googlesecops-lab")


def state_topic(project: str) -> str:
    topic = tf("output", "-raw", "topic", capture=True)
    if topic != f"projects/{project}/topics/{TOPIC}":
        raise ValueError("Terraform state is not bound to the specified lab project")
    return topic


def verify(project: str) -> dict:
    topic = state_topic(project)
    sink = json.loads(
        gcloud("logging", "sinks", "describe", SINK, "--format=json", project=project)
    )
    pubsub = json.loads(
        gcloud(
            "pubsub", "subscriptions", "describe", SUBSCRIPTION, "--format=json", project=project
        )
    )
    policy = json.loads(
        gcloud("pubsub", "topics", "get-iam-policy", TOPIC, "--format=json", project=project)
    )
    writer = sink.get("writerIdentity")
    binding = any(
        item.get("role") == "roles/pubsub.publisher" and writer in item.get("members", [])
        for item in policy.get("bindings", [])
    )
    if (
        sink.get("destination") != f"pubsub.googleapis.com/{topic}"
        or pubsub.get("topic") != topic
        or not binding
    ):
        raise ValueError("routing, subscription or writer binding does not match Terraform")
    return {
        "infrastructure_verified": True,
        "routing_enabled": not sink.get("disabled", False),
        "retention": pubsub.get("messageRetentionDuration"),
    }


def smoke(project: str, db: Path) -> dict:
    details = verify(project)
    if not details["routing_enabled"]:
        raise ValueError("enable audit routing in a reviewed Terraform plan first")
    STATE.mkdir(parents=True, exist_ok=True)
    checkpoint = STATE / f"{project}.last-smoke"
    now = datetime.now(UTC)
    if checkpoint.exists() and now.timestamp() - checkpoint.stat().st_mtime < 60:
        raise ValueError("wait at least 60 seconds between smoke operations")
    checkpoint.touch()
    marker = now.strftime("t%Y%m%d%H%M%S")
    start = (now - timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
    gcloud(
        "pubsub",
        "topics",
        "update",
        TOPIC,
        f"--update-labels=verification={marker}",
        project=project,
    )
    query = (
        f'log_id("cloudaudit.googleapis.com/activity") AND protoPayload.methodName="{METHOD}" '
        f'AND protoPayload.resourceName="projects/{project}/topics/{TOPIC}" AND timestamp>="{start}"'
    )
    for _ in range(4):
        logs = json.loads(
            gcloud("logging", "read", query, "--limit=8", "--format=json", project=project)
        )
        ids = {item.get("insertId") for item in logs if item.get("insertId")}
        pull_once(db, project, 10)
        with database(db, readonly=True) as conn:
            matched = any(
                event.raw.get("insertId") in ids
                and get(event.raw, "protoPayload.methodName") == METHOD
                for event in (
                    load_event(row)
                    for row in conn.execute(
                        "SELECT document FROM events WHERE origin='real' AND source='gcp_audit' AND timestamp>=?",
                        (start,),
                    )
                )
            )
        if matched:
            return details | {
                "cloud_logging_to_pubsub_to_sqlite": True,
                "real_audit_event_verified": True,
            }
        time.sleep(4)
    raise ValueError("no matching audit insert ID observed in both Cloud Logging and SQLite")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["plan", "stop-plan", "destroy-plan", "apply", "verify", "smoke"]
    )
    parser.add_argument("project")
    parser.add_argument("--kind", choices=["plan", "stop-plan", "destroy-plan"], default="plan")
    parser.add_argument("--var-file", type=Path)
    parser.add_argument("--db", type=Path, default=ROOT / "var" / "cloud.sqlite")
    parser.add_argument("--authorized", action="store_true")
    args = parser.parse_args()
    os.environ["CHECKPOINT_DISABLE"] = "1"
    try:
        if args.action in ("apply", "smoke") and not args.authorized:
            raise ValueError("explicit authorization is required for apply or smoke")
        guard(args.project)
        if args.action in ("verify", "smoke"):
            print(
                json.dumps(
                    verify(args.project)
                    if args.action == "verify"
                    else smoke(args.project, args.db)
                )
            )
            return 0
        STATE.mkdir(parents=True, exist_ok=True)
        kind = args.kind if args.action == "apply" else args.action
        target = STATE / f"{args.project}-{kind}.tfplan"
        if args.action == "apply":
            if not target.is_file():
                raise ValueError("create and review the corresponding plan before apply")
            snapshot = json.loads(tf("show", "-json", str(target), capture=True))
            if snapshot.get("variables", {}).get("project_id", {}).get("value") != args.project:
                raise ValueError("saved plan project does not match")
            tf("apply", "-input=false", str(target))
            return 0
        tf("init", "-input=false")
        if (ROOT / "infrastructure" / "terraform.tfstate").exists():
            current = json.loads(tf("show", "-json", capture=True))
            resources = get(current, "values.root_module.resources", [])
            projects = {
                resource["values"]["project"]
                for resource in resources
                if isinstance(get(resource, "values.project"), str)
            }
            if projects - {args.project}:
                raise ValueError("local Terraform state belongs to a different project")
        options = [f"-var-file={args.var_file.resolve()}"] if args.var_file else []
        options += [f"-var=project_id={args.project}"]
        if kind == "stop-plan":
            options += ["-var=route_audit=false"]
        if kind == "destroy-plan":
            options += ["-destroy"]
        tf("plan", "-input=false", *options, f"-out={target}")
        print(f"Reviewed-plan path: {target}")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(2, f"cloud-ops: {error}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
