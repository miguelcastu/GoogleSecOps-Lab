"""Deterministic, network-free scenarios built from native-shaped JSON records."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .adapters import GCP_AUDIT, parse
from .detection import catalog, evaluate
from .model import Json

BASE = datetime(2026, 1, 20, 9, tzinfo=UTC)
SRC = "192.0.2.20"
DST = "198.51.100.17"
ACTOR = "analyst@example.test"
POSITIVE_COUNTS = {
    "failures": 4,
    "spray": 5,
    "fail_success": 4,
    "countries": 2,
    "long_dns": 3,
    "c2": 4,
    "reads": 5,
    "cross": 2,
}
EXTRAS = ("windows_sample", "linux_sample", "falcon_sample", "proxy_sample", "webhook_sample")


def audit(
    time: str,
    event_id: str,
    action: str,
    service: str,
    *,
    actor: str = ACTOR,
    blocked: bool = False,
) -> Json:
    return {
        "timestamp": time,
        "insertId": event_id,
        "logName": "projects/synthetic-lab/logs/cloudaudit.googleapis.com%2Factivity",
        "protoPayload": {
            "@type": GCP_AUDIT,
            "serviceName": service,
            "methodName": action,
            "authenticationInfo": {"principalEmail": actor},
            "requestMetadata": {"callerIp": SRC},
            "resourceName": "projects/synthetic-lab/lab-resource",
            "status": {"code": 7 if blocked else 0},
        },
    }


def sign_in(time: str, event_id: str, actor: str, success: bool, country: str = "ES") -> Json:
    return {
        "createdDateTime": time,
        "id": event_id,
        "userPrincipalName": actor,
        "ipAddress": SRC,
        "status": {"errorCode": 0 if success else 50126},
        "location": {"countryOrRegion": country},
    }


def endpoint(time: str, index: int, host: str, code: int, **fields: str) -> Json:
    return {
        "TimeCreated": time,
        "EventRecordID": index,
        "Computer": host,
        "EventID": code,
        "EventData": {"User": host + r"\test-user"} | fields,
    }


def sample(name: str, index: int, time: str, positive: bool) -> tuple[str, Json]:
    event_id = f"{name}-{positive}-{index}"
    actor = f"{name}@example.test"
    host = f"{name}.example.test"
    audit_actions = {
        "iam_policy": ("gcp_iam", "SetIamPolicy", "cloudresourcemanager.googleapis.com"),
        "service_key": (
            "gcp_iam",
            "google.iam.admin.v1.CreateServiceAccountKey",
            "iam.googleapis.com",
        ),
        "sink": (
            "gcp_audit",
            "google.logging.v2.ConfigServiceV2.UpdateSink",
            "logging.googleapis.com",
        ),
        "firewall": ("gcp_audit", "v1.compute.firewalls.insert", "compute.googleapis.com"),
    }
    if name in audit_actions:
        source, action, service = audit_actions[name]
        return source, audit(time, event_id, action, service, actor=actor, blocked=not positive)
    if name in ("aws_role", "aws_bucket", "reads"):
        action = {
            "aws_role": "AttachRolePolicy",
            "aws_bucket": "PutBucketPolicy",
            "reads": "GetObject",
        }[name]
        data: Json = {
            "eventTime": time,
            "eventID": event_id,
            "eventName": action,
            "eventSource": "iam.amazonaws.com" if name == "aws_role" else "s3.amazonaws.com",
            "sourceIPAddress": SRC,
            "userIdentity": {"arn": f"arn:aws:iam::000000000000:user/{name}"},
            "requestParameters": {
                "roleName" if name == "aws_role" else "bucketName": "example-lab"
            },
        }
        if not positive:
            data["errorCode"] = "AccessDenied"
        return "cloudtrail", data
    if name == "cross":
        if index == 0:
            return "workspace", {
                "id": {"time": time, "uniqueQualifier": event_id},
                "events": [{"name": "login_success"}],
                "actor": {"email": actor},
                "ipAddress": SRC,
            }
        return "gcp_iam", audit(
            time,
            event_id,
            "SetIamPolicy",
            "iam.googleapis.com",
            actor=actor if positive else "different@example.test",
        )
    if name in ("failures", "spray", "fail_success", "countries"):
        success = name == "countries" or name == "fail_success" and index == 3
        if name == "failures" and not positive:
            success = True
        if name == "spray":
            actor = f"spray-{index if positive else index % 2}@example.test"
        if name == "fail_success" and not positive and success:
            actor = "unrelated@example.test"
        country = "US" if name == "countries" and index == 1 and positive else "ES"
        return "entra", sign_in(time, event_id, actor, success, country)
    if name in ("powershell", "office", "registry", "smb"):
        if name == "powershell":
            flag = "-EncodedCommand VwByAGkAdABlAA==" if positive else "-NoProfile"
            return "sysmon", endpoint(
                time,
                index,
                host,
                1,
                Image=r"C:\Lab\powershell.exe",
                CommandLine=f"powershell.exe {flag}",
            )
        if name == "office":
            parent = "WINWORD.EXE" if positive else "explorer.exe"
            return "sysmon", endpoint(
                time,
                index,
                host,
                1,
                Image=r"C:\Windows\cmd.exe",
                ParentImage=f"C:\\Program Files\\{parent}",
                CommandLine="cmd.exe /c echo demo",
            )
        if name == "registry":
            subkey = "Run" if positive else "Policies"
            return "sysmon", endpoint(
                time,
                index,
                host,
                13,
                Image=r"C:\Lab\fixture.exe",
                TargetObject=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\{subkey}\\Lab",
            )
        return "sysmon", endpoint(
            time,
            index,
            host,
            3,
            SourceIp=SRC,
            DestinationIp=DST,
            DestinationPort="445" if positive else "443",
        )
    if name == "long_dns":
        query = ("a" * 52 + str(index) if positive else "short") + ".example.test"
        return "dns", {
            "ts": time,
            "id": event_id,
            "id.orig_h": SRC,
            "id.resp_h": DST,
            "query": query,
        }
    if name in ("c2", "egress"):
        port = 4444 if name == "c2" and positive else 443
        size = 128 * 1024 * 1024 if name == "egress" and positive else 1024
        return "fortigate", {
            "timestamp": time,
            "record_id": event_id,
            "type": "traffic",
            "subtype": "forward",
            "action": "accept",
            "srcip": SRC,
            "dstip": DST,
            "dstport": port,
            "sentbyte": size,
            "srcintfrole": "lan",
            "dstintfrole": "wan",
        }
    if name == "windows_sample":
        return "windows", {
            "TimeCreated": time,
            "EventRecordID": index,
            "Computer": host,
            "EventID": 4624,
            "EventData": {"TargetUserName": actor, "IpAddress": SRC},
        }
    if name == "linux_sample":
        return "linux", {
            "timestamp": time,
            "id": event_id,
            "hostname": host,
            "message": f"Accepted publickey for lab-user from {SRC} port 43210 ssh2",
        }
    if name == "falcon_sample":
        return "falcon", {
            "metadata": {
                "eventType": "DetectionSummaryEvent",
                "eventCreationTime": int(datetime.fromisoformat(time).timestamp() * 1000),
            },
            "event": {
                "DetectId": event_id,
                "FilePath": r"C:\Lab\example.exe",
                "ComputerName": host,
                "UserName": actor,
                "CommandLine": "example.exe",
            },
        }
    if name == "proxy_sample":
        return "proxy", {
            "timestamp": time,
            "request_id": event_id,
            "user": actor,
            "client_ip": SRC,
            "url": "https://downloads.example.test/sample",
            "method": "GET",
            "request_bytes": 128,
        }
    if name == "webhook_sample":
        return "webhook", {
            "timestamp": time,
            "id": event_id,
            "action": "lab_deployment_checked",
            "actor": actor,
            "source_ip": SRC,
            "resource": "test-resource",
        }
    raise ValueError(f"unknown scenario {name}")


def envelopes(name: str, positive: bool, offset: int = 0) -> list[Json]:
    count = POSITIVE_COUNTS.get(name, 1)
    rows = []
    for index in range(count):
        time = BASE + timedelta(minutes=offset, seconds=index * 35)
        source, raw = sample(name, index, time.isoformat(), positive)
        rows.append({"source": source, "origin": "synthetic", "raw": raw})
    return rows


def fixture_catalog() -> list[Json]:
    return [
        {
            "name": rule["scenario"],
            "rule": rule["id"],
            "attack": rule["attack"],
            "description": rule["rationale"],
            "sources": rule["sources"],
            "origin": "synthetic",
            "investigate": rule["tuning"],
        }
        for rule in catalog()
    ]


def suite() -> tuple[list[Json], Json]:
    rows: list[Json] = []
    results: list[Json] = []
    tp = fp = fn = tn = 0
    collateral = {"cross": {"GSL001"}, "cross:negative": {"GSL001"}}
    for index, rule in enumerate(catalog()):
        name = rule["scenario"]
        for positive in (True, False):
            case = name if positive else f"{name}:negative"
            fixture = envelopes(name, positive, index * 60 + (0 if positive else 20))
            rows.extend(fixture)
            alerts = evaluate(parse(row["source"], row["origin"], row["raw"]) for row in fixture)
            actual = {alert.rule_id for alert in alerts}
            expected = collateral.get(case, set()) | ({rule["id"]} if positive else set())
            tp += len(expected & actual)
            fp += len(actual - expected)
            fn += len(expected - actual)
            tn += len({item["id"] for item in catalog()} - (actual | expected))
            results.append(
                {
                    "scenario": case,
                    "expected": sorted(expected),
                    "actual": sorted(actual),
                    "passed": expected == actual,
                }
            )
    for index, extra in enumerate(EXTRAS):
        rows.extend(envelopes(extra, True, 1200 + index * 20))
    approved_backup = envelopes("egress", True, 1350)
    backup = approved_backup[0]["raw"]
    backup["record_id"] = "approved-backup"
    backup["srcip"] = "192.0.2.90"
    rows.extend(approved_backup)
    observed_backup = {a.rule_id for a in evaluate([parse("fortigate", "synthetic", backup)])}
    fp += len(observed_backup)
    tn += len(catalog()) - len(observed_backup)
    results.append(
        {
            "scenario": "approved_backup_false_positive",
            "expected": ["GSL017"],
            "actual": sorted(observed_backup),
            "passed": observed_backup == {"GSL017"},
            "ground_truth": "benign",
        }
    )
    return rows, {
        "tests": results,
        "passed": sum(row["passed"] for row in results),
        "total": len(results),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "native_validation": "PENDING",
    }


def write_jsonl(path: Path, rows: list[Json]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
