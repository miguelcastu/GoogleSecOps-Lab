"""Reproducible synthetic investigations and a separately labeled IAM benchmark."""

import json
from collections import Counter
from datetime import datetime, timedelta
from importlib.resources import files

from .adapters import parse
from .detection import evaluate
from .iam import RULE
from .ingestion import check_sensitive
from .model import Json, digest
from .scenarios import audit

PROJECT = "gsl-iam-demo"
ATTACKER = "contractor@partner.example.test"
AUTOMATION = "pipeline@gsl-iam-demo.iam.gserviceaccount.com"


def demo_events() -> list[Json]:
    """One sensitive grant with subsequent use and one ordinary deployment."""
    rows: list[Json] = []
    for name, actor, beneficiary, role, bucket, minute in (
        (
            "sensitive",
            "operator@example.test",
            ATTACKER,
            "roles/storage.objectAdmin",
            "finance-archive",
            0,
        ),
        (
            "routine",
            "deploy@example.test",
            AUTOMATION,
            "roles/storage.objectViewer",
            "build-artifacts",
            45,
        ),
    ):
        start = datetime.fromisoformat("2026-02-02T14:00:00Z") + timedelta(minutes=minute)
        kind = "serviceAccount" if beneficiary.endswith(".gserviceaccount.com") else "user"
        grant = audit(
            start.isoformat(),
            f"iam-{name}-grant",
            "SetIamPolicy",
            "cloudresourcemanager.googleapis.com",
            actor=actor,
        )
        grant["logName"] = f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity"
        grant["protoPayload"]["resourceName"] = f"projects/{PROJECT}"
        grant["protoPayload"]["serviceData"] = {
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": role, "member": f"{kind}:{beneficiary}"}
                ]
            }
        }
        access = audit(
            (start + timedelta(minutes=4)).isoformat(),
            f"iam-{name}-activity",
            "storage.objects.get",
            "storage.googleapis.com",
            actor=beneficiary,
        )
        access["logName"] = f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access"
        resource = f"projects/_/buckets/{bucket}/objects/report.csv"
        access["protoPayload"]["resourceName"] = resource
        access["protoPayload"]["authorizationInfo"] = [
            {"permission": "storage.objects.get", "resource": resource, "granted": True}
        ]
        rows.extend(
            {"source": source, "origin": "synthetic", "raw": raw}
            for source, raw in (("gcp_iam", grant), ("gcp_audit", access))
        )
    return rows


def evaluate_corpus() -> Json:
    corpus = json.loads(
        files("secops_lab").joinpath("iam_evaluation.json").read_text(encoding="utf-8")
    )
    rule_ids: list[str] = ["GSL001", RULE["id"]]
    stats: dict[str, Counter[str]] = {rule_id: Counter() for rule_id in rule_ids}
    cases = []
    for example in corpus["cases"]:
        events = []
        for row in example["events"]:
            check_sensitive(row["raw"])
            events.append(parse(row["source"], "synthetic", row["raw"]))
        hits = {alert.rule_id for alert in evaluate(events)}
        observed = {}
        for rule_id in rule_ids:
            hit = rule_id in hits
            observed[rule_id] = hit
            label = ("tp" if hit else "fn") if example["malicious"] else ("fp" if hit else "tn")
            stats[rule_id][label] += 1
        cases.append(
            {
                "case": example["case"],
                "malicious": example["malicious"],
                "purpose": example["purpose"],
                "observed": observed,
                "expected_gsl020": example["expected_gsl020"],
                "passed": observed[RULE["id"]] == example["expected_gsl020"],
            }
        )
    metrics = {}
    for rule_id, counts in stats.items():
        tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
        metrics[rule_id] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        }
    return {
        "dataset": corpus["name"],
        "dataset_sha256": digest(corpus),
        "unit": "scenario",
        "metrics": metrics,
        "cases": cases,
        "total": len(cases),
        "passed": sum(case["passed"] for case in cases),
    }
