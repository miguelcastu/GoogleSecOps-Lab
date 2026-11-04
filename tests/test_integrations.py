import base64
import json
from unittest.mock import Mock

import pytest

from secops_lab.adapters import parse
from secops_lab.chronicle import Chronicle
from secops_lab.cloud import pull_once
from secops_lab.scenarios import envelopes
from secops_lab.storage import database


def response(body=None, status=200):
    result = Mock()
    result.status_code = status
    result.json.return_value = body if body is not None else {}
    result.content = b"data" if body else b""
    return result


def test_cloud_commit_before_ack_and_retries(tmp_path):
    db = tmp_path / "cloud.sqlite"
    row = envelopes("iam_policy", True)[0]
    raw = row["raw"]
    raw["logName"] = "projects/gsl-pubsub-test/logs/cloudaudit.googleapis.com%2Factivity"
    encoded = base64.b64encode(json.dumps(raw).encode()).decode()
    items = [
        {"ackId": "one", "message": {"data": encoded}},
        {"ackId": "bad", "message": {"data": "not-base64"}},
    ]
    session = Mock()

    def post(url, **kwargs):
        if url.endswith(":pull"):
            assert kwargs["json"] == {"maxMessages": 2}
            return response({"receivedMessages": items})
        assert url.endswith(":acknowledge")
        assert kwargs["json"] == {"ackIds": ["one", "bad"]}
        with database(db, readonly=True) as conn:
            assert conn.execute("SELECT origin FROM events").fetchone()[0] == "real"
            assert conn.execute("SELECT count(*) FROM rejects").fetchone()[0] >= 1
        return response()

    session.post.side_effect = post
    assert pull_once(db, "gsl-pubsub-test", 2, session) == {
        "accepted": 1,
        "duplicate": 0,
        "rejected": 1,
    }
    assert pull_once(db, "gsl-pubsub-test", 2, session) == {
        "accepted": 0,
        "duplicate": 1,
        "rejected": 1,
    }
    with pytest.raises(ValueError):
        pull_once(db, "prod-project", 2, session)


def test_cloud_transaction_rolls_back_before_ack_when_response_invalid(tmp_path):
    db = tmp_path / "cloud.sqlite"
    raw = envelopes("iam_policy", True)[0]["raw"]
    raw["logName"] = "projects/gsl-pubsub-test/logs/cloudaudit.googleapis.com%2Factivity"
    encoded = base64.b64encode(json.dumps(raw).encode()).decode()
    session = Mock()
    session.post.return_value = response(
        {"receivedMessages": [{"ackId": "one", "message": {"data": encoded}}, {}]}
    )
    with pytest.raises(ValueError, match="ack ID"):
        pull_once(db, "gsl-pubsub-test", 2, session)
    assert session.post.call_count == 1
    with database(db, readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_ack_transport_failure_recovers_without_duplicate_alert(tmp_path):
    from secops_lab.iam_lab import demo_events
    from secops_lab.storage import replay

    db = tmp_path / "ack-recovery.sqlite"
    received = []
    for index, row in enumerate(demo_events()[:2]):
        raw = row["raw"]
        suffix = raw["logName"].split("/logs/", 1)[1]
        raw["logName"] = "projects/gsl-pubsub-test/logs/" + suffix
        if index == 0:
            raw["protoPayload"]["resourceName"] = "projects/gsl-pubsub-test"
        encoded = base64.b64encode(json.dumps(raw).encode()).decode()
        received.append({"ackId": str(index), "message": {"data": encoded}})
    session = Mock()
    pulled = response({"receivedMessages": received})
    session.post.side_effect = [pulled, OSError("ack transport unavailable"), pulled, response()]

    with pytest.raises(OSError, match="ack transport"):
        pull_once(db, "gsl-pubsub-test", 2, session)
    with database(db) as conn:
        assert replay(conn)["alerts_added"] == 2
    assert pull_once(db, "gsl-pubsub-test", 2, session) == {
        "accepted": 0,
        "duplicate": 2,
        "rejected": 0,
    }
    with database(db) as conn:
        assert replay(conn)["alerts_added"] == 0
        assert conn.execute("SELECT count(*) FROM alerts WHERE rule_id='GSL020'").fetchone()[0] == 1


def test_chronicle_opt_in_and_verify(monkeypatch):
    monkeypatch.delenv("GSL_ENABLE_CHRONICLE", raising=False)
    with pytest.raises(ValueError, match="ENABLE_CHRONICLE"):
        Chronicle.from_environment()
    session = Mock()
    session.request.return_value = response({"success": True})
    client = Chronicle("example-project", "eu", "example-instance", session)
    with pytest.raises(ValueError, match="WRITE"):
        client.create_rule("rule lab {}")
    session.request.assert_not_called()
    assert client.verify_rule("rule lab {}") == {"success": True}
    args, kwargs = session.request.call_args
    assert args == (
        "POST",
        "https://eu-chronicle.googleapis.com/v1/projects/example-project/locations/eu/instances/example-instance:verifyRuleText",
    )
    assert kwargs["json"] == {"ruleText": "rule lab {}"}
    assert kwargs["allow_redirects"] is False


def test_chronicle_v1_payloads_and_rule_rejection():
    session = Mock()
    session.request.return_value = response()
    client = Chronicle("example-project", "eu", "example-instance", session, allow_write=True)
    row = envelopes("countries", True)[0]
    event = parse(row["source"], row["origin"], row["raw"])
    client.import_raw("AZURE_AD_SIGNIN", [(event.timestamp, json.dumps(event.raw))])
    raw_args, raw_kwargs = session.request.call_args
    assert raw_args[1].endswith("/logTypes/AZURE_AD_SIGNIN/logs:import")
    assert (
        json.loads(base64.b64decode(raw_kwargs["json"]["inlineSource"]["logs"][0]["data"]))
        == event.raw
    )
    client.import_udm([event.udm])
    args, kwargs = session.request.call_args
    assert args[1].endswith("/events:import")
    assert kwargs["json"]["inlineSource"] == {"events": [{"udm": event.udm}]}
    session.request.reset_mock()
    session.request.return_value = response({"success": False})
    with pytest.raises(ValueError, match="rejected"):
        client.create_rule("invalid rule")
    assert session.request.call_count == 1
    session.request.side_effect = [response({"success": True}), response({"name": "new-rule"})]
    assert client.create_rule("rule lab {}") == {"name": "new-rule"}
    args, kwargs = session.request.call_args
    assert args[1].endswith("/rules") and kwargs["json"] == {"text": "rule lab {}"}


def test_chronicle_deployment_and_investigation_paths():
    session = Mock()
    session.request.return_value = response()
    client = Chronicle("example-project", "eu", "example-instance", session, allow_write=True)
    client.deploy_rule("ru_example", enabled=True)
    args, kwargs = session.request.call_args
    assert args[0] == "PATCH" and args[1].endswith("/rules/ru_example/deployment")
    assert kwargs["json"]["enabled"] is True and kwargs["params"]["updateMask"] == "enabled"
    client.detections("ru_example", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    args, kwargs = session.request.call_args
    assert "/v1alpha/" in args[1] and args[1].endswith("/legacy:legacySearchDetections")
    assert kwargs["params"]["ruleId"] == "ru_example"
    client.cases("next")
    assert session.request.call_args.kwargs["params"]["pageToken"] == "next"
    client.case_detections("case1")
    assert session.request.call_args.args[1].endswith("/cases/case1/detections")
