import json
import threading
from copy import deepcopy
from dataclasses import replace
from urllib.request import urlopen

from secops_lab.adapters import parse
from secops_lab.cli import main
from secops_lab.dashboard import make_server
from secops_lab.detection import evaluate
from secops_lab.iam_lab import demo_events, evaluate_corpus
from secops_lab.scenarios import envelopes
from secops_lab.storage import accept, case_detail, database, replay


def normalized(row):
    return parse(row["source"], row["origin"], row["raw"])


def iam_alerts(events):
    return [alert for alert in evaluate(events) if alert.rule_id == "GSL020"]


def revised(row, identity, instant):
    row = deepcopy(row)
    row["raw"]["insertId"] = identity
    row["raw"]["timestamp"] = f"2026-02-02T14:{instant:02d}:00Z"
    return row


def test_direct_binding_scope_and_origin():
    grant, use, benign_grant, benign_use = map(normalized, demo_events())
    (alert,) = iam_alerts([use, grant, use, benign_grant, benign_use])
    assert alert.event_ids == [grant.id, use.id]
    assert alert.context["grant_actor"] == "operator@example.test"
    assert alert.context["beneficiary"] == "user:contractor@partner.example.test"
    assert alert.context["elapsed_seconds"] == 240
    assert grant.parsed["iam_changes"][0]["action"] == "ADD"
    assert not iam_alerts([grant, replace(use, origin="real")])
    assert not iam_alerts([grant, replace(use, timestamp=grant.timestamp)])
    assert not iam_alerts([grant, replace(use, timestamp="2026-02-02T14:30:01.000000Z")])
    assert iam_alerts([grant, replace(use, timestamp="2026-02-02T14:30:00.000000Z")])


def test_policy_delta_preserves_binding_pairs_and_ignores_untrusted_fields():
    row, use, *_ = demo_events()
    payload = row["raw"]["protoPayload"]
    deltas = payload["serviceData"]["policyDelta"]["bindingDeltas"]
    binding = deltas[0]
    deltas[:] = [
        False,
        {"action": "ADD", "role": binding["role"], "member": "user:other@example.test"},
        {"action": "ADD", "role": "roles/storage.objectViewer", "member": binding["member"]},
        {"action": "ADD", "role": binding["role"], "member": binding["member"], "condition": "bad"},
    ]
    payload["request"] = {"policy": {"bindings": [binding]}}
    assert len(normalized(row).parsed["iam_changes"]) == 2
    assert not iam_alerts([normalized(row), normalized(use)])


def test_same_timestamp_revocation_prevents_future_match():
    grant_row, use_row, *_ = demo_events()
    revoke_row = revised(grant_row, "simultaneous-remove", 0)
    revoke_row["raw"]["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"][0][
        "action"
    ] = "REMOVE"
    assert not iam_alerts([normalized(grant_row), normalized(revoke_row), normalized(use_row)])


def test_permission_probe_does_not_count_as_use():
    grant_row, use_row, *_ = demo_events()
    use_row["raw"]["protoPayload"]["methodName"] = "storage.buckets.testIamPermissions"
    assert not iam_alerts([normalized(grant_row), normalized(use_row)])


def test_late_activity_and_revocation_keep_case_and_notes(tmp_path):
    db = tmp_path / "late.sqlite"
    grant_row, use_row, *_ = demo_events()
    grant, use = map(normalized, (grant_row, use_row))
    earlier = normalized(revised(use_row, "earlier-use", 2))
    revoke_row = revised(grant_row, "late-revocation", 1)
    revoke_row["raw"]["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"][0][
        "action"
    ] = "REMOVE"
    revoke = normalized(revoke_row)
    with database(db) as conn:
        assert accept(conn, use)
    with database(db) as conn:
        assert replay(conn)["alerts_added"] == 0
    with database(db) as conn:
        assert accept(conn, grant)
        assert not accept(conn, use)
    with database(db) as conn:
        assert replay(conn)["alerts_added"] == 2
        case_id = conn.execute("SELECT case_id FROM alerts WHERE rule_id='GSL020'").fetchone()[0]
        assert case_detail(conn, case_id)["alerts"][0]["context"]["activity_event_id"] == use.id
    assert (
        main(
            [
                "--db",
                str(db),
                "case",
                case_id,
                "--status",
                "investigating",
                "--note",
                "review grant",
            ]
        )
        == 0
    )
    with database(db) as conn:
        accept(conn, earlier)
    with database(db) as conn:
        result = replay(conn)
        case = case_detail(conn, case_id)
        assert result["alerts_added"] == 0 and result["alerts_updated"] == 1
        assert [event["id"] for event in case["timeline"]] == [grant.id, earlier.id, use.id]
        assert case["alerts"][0]["context"]["activity_event_id"] == earlier.id
        assert case["status"] == "investigating"
        assert case["notes"][0]["text"] == "review grant"
    with database(db) as conn:
        accept(conn, revoke)
    with database(db) as conn:
        assert replay(conn)["alerts_updated"] == 1
        case = case_detail(conn, case_id)
        assert case["alerts"][0]["correlation_state"] == "needs_review"
        assert case["timeline"][1]["iam_changes"][0]["action"] == "REMOVE"
    with database(db) as conn:
        assert replay(conn)["alerts_updated"] == 0


def test_late_input_extends_existing_threshold_alert(tmp_path):
    db = tmp_path / "threshold.sqlite"
    initial = envelopes("failures", True)
    late = deepcopy(initial[0])
    late["raw"]["createdDateTime"] = "2026-01-20T08:59:30Z"
    late["raw"]["id"] = "late-failure"
    with database(db) as conn:
        for row in initial:
            accept(conn, normalized(row))
    with database(db) as conn:
        replay(conn)
        original = conn.execute("SELECT id FROM alerts WHERE rule_id='GSL007'").fetchone()[0]
    with database(db) as conn:
        accept(conn, normalized(late))
    with database(db) as conn:
        assert replay(conn)["alerts_updated"] == 1
        alerts = conn.execute("SELECT * FROM alerts WHERE rule_id='GSL007'").fetchall()
        assert len(alerts) == 1 and alerts[0]["id"] == original
        assert len(json.loads(alerts[0]["document"])["event_ids"]) == 5


def test_iam_demo_exports_case_and_evaluation(tmp_path, capsys):
    path = tmp_path / "iam.sqlite"
    output = tmp_path / "demo"
    assert main(["--db", str(path), "iam-demo", "--out", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ingestion"]["accepted"] == 4
    assert "Grant actor" in (output / "investigation.md").read_text(encoding="utf-8")
    report = evaluate_corpus()
    assert report["passed"] == report["total"] == 20
    assert report["metrics"]["GSL020"] == {
        "tp": 6,
        "fp": 1,
        "fn": 2,
        "tn": 11,
        "precision": 0.8571,
        "recall": 0.75,
    }
    with make_server(path, 0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base, timeout=5) as response:
                html = response.read().decode()
                assert "IAM grant investigations" in html
                assert "20 synthetic scenarios" in html
            with urlopen(base + result["investigation_path"], timeout=5) as response:
                html = response.read().decode()
                assert "Why this case fired" in html
                assert "Grant evidence" in html and "storage.objects.get" in html
                assert "Another binding may also have authorized the activity" in html
            with urlopen(base + result["investigation_path"] + "/report.md", timeout=5) as response:
                assert "Observed use" in response.read().decode()
        finally:
            server.shutdown()
            thread.join(timeout=5)
