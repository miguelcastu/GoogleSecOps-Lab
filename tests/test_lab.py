import json
import re
import threading
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from secops_lab.adapters import ADAPTERS, parse
from secops_lab.cli import main
from secops_lab.dashboard import make_server
from secops_lab.detection import catalog, evaluate
from secops_lab.ingestion import read_jsonl
from secops_lab.model import MAX_RECORD, InvalidEvent, timestamp, validate_udm
from secops_lab.scenarios import envelopes, suite, write_jsonl
from secops_lab.storage import case_detail, database

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("rule", catalog(), ids=lambda rule: rule["id"])
def test_per_rule_positive_and_negative(rule):
    for positive in (True, False):
        inputs = envelopes(rule["scenario"], positive)
        events = [parse(item["source"], item["origin"], item["raw"]) for item in inputs]
        alerts = evaluate(events, [rule])
        assert bool(alerts) is positive
        native = ROOT / "detections" / "yara_l" / f"{rule['id']}_{rule['name']}.yaral"
        text = native.read_text(encoding="utf-8")
        assert re.search(r"^rule [a-z_]+ \{", text)
        assert all(
            re.search(rf"^  {section}:$", text, re.M) for section in ("meta", "events", "condition")
        )
        assert bool(re.search(r"^  match:$", text, re.M)) is bool(rule["correlation"])
        assert f'rule_id = "{rule["id"]}"' in text
        assert 'validation = "PENDING"' in text
        assert text.rstrip().endswith("}")


@pytest.mark.parametrize("source", ADAPTERS)
def test_source_fixture(source):
    fixture = ROOT / "datasets" / "synthetic.jsonl"
    normalized = [
        event
        for _, _, event in read_jsonl(fixture, 5000)
        if not isinstance(event, str) and event.source == source
    ]
    assert normalized
    for event in normalized:
        assert event.origin == "synthetic"
        assert event.timestamp.endswith("Z")
        assert event.raw
        assert event.udm["metadata"]["eventTimestamp"] == event.timestamp
        validate_udm(event.udm)


def test_structural_udm_projection():
    row = envelopes("countries", True)[0]
    event = parse(row["source"], row["origin"], row["raw"])
    assert event.udm["target"]["user"]["userid"] == "countries@example.test"
    assert event.udm["principal"]["location"]["countryOrRegion"] == "ES"
    assert event.udm["securityResult"] == [{"action": ["ALLOW"]}]
    assert timestamp("2026-01-20T10:00:00+01:00") == "2026-01-20T09:00:00.000000Z"
    with pytest.raises(InvalidEvent, match="timezone"):
        timestamp("2026-01-20T09:00:00")


def test_ingestion_quarantines_invalid_records_and_continues(tmp_path):
    path = tmp_path / "mixed.jsonl"
    good = envelopes("countries", True)[0]
    malformed = good | {"raw": good["raw"] | {"status": {"errorCode": "not an integer"}}}
    sensitive = good | {"raw": good["raw"] | {"nested": {"access_token": "test-secret"}}}
    missing = good | {"raw": good["raw"] | {"userPrincipalName": None}}
    wrong_type = good | {"raw": good["raw"] | {"userPrincipalName": ["wrong"]}}
    real = good | {"origin": "real"}
    messages = [
        b"{",
        b"a" * (MAX_RECORD + 1),
        b'{"x":1e999}',
        *(
            json.dumps(row).encode()
            for row in (malformed, sensitive, missing, wrong_type, real, good)
        ),
    ]
    path.write_bytes(b"\n".join(messages) + b"\n")
    rows = list(read_jsonl(path, 10))
    assert len(rows) == 9
    assert all(isinstance(row[2], str) for row in rows[:-1])
    assert rows[-1][2].raw == good["raw"]
    assert list(read_jsonl(path, 1)) == [rows[0]]
    assert "sensitive" in rows[4][2]
    assert "real data requires" in rows[7][2]
    assert list(read_jsonl(path, 10, allow_real=True))[7][2].origin == "real"


def test_ordered_correlation_window_and_deduplication():
    rule = next(r for r in catalog() if r["name"] == "fail_then_success")
    events = [
        parse(row["source"], row["origin"], row["raw"]) for row in envelopes("fail_success", True)
    ]
    assert len(evaluate(reversed(events), [rule])) == 1
    success = events[-1]
    start = datetime.fromisoformat(events[0].timestamp)
    for span, expected in (
        (timedelta(minutes=5), 1),
        (timedelta(minutes=5, seconds=1), 0),
        (timedelta(seconds=1), 0),
    ):
        shifted = replace(success, timestamp=timestamp((start + span).isoformat()))
        assert len(evaluate(events[:-1] + [shifted], [rule])) == expected
    assert evaluate([events[0]] * 3 + [success], [rule]) == []


def test_correlation_suppression():
    rule = next(r for r in catalog() if r["name"] == "repeated_failures")
    sets = [
        [
            parse(row["source"], row["origin"], row["raw"])
            for row in envelopes("failures", True, offset)
        ]
        for offset in (0, 6, 17)
    ]
    assert len(evaluate(sum(sets, []), [rule])) == 2


def test_synthetic_and_real_cannot_correlate():
    rule = next(r for r in catalog() if r["name"] == "login_then_iam")
    events = [parse(row["source"], row["origin"], row["raw"]) for row in envelopes("cross", True)]
    assert evaluate(events, [rule])
    assert not evaluate([events[0], replace(events[1], origin="real")], [rule])


def test_demo_replay_case_and_dashboard(tmp_path, capsys):
    db = tmp_path / "lab.sqlite"
    out = tmp_path / "demo"
    assert main(["--db", str(db), "demo", "--out", str(out)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["ingestion"] == {"accepted": 86, "duplicate": 0, "rejected": 0}
    assert first["replay"]["alerts_added"] == 22
    assert first["replay"]["cases"] == 21
    validation = json.loads((out / "validation.json").read_text())
    assert validation["passed"] == validation["total"] == 39
    assert (validation["tp"], validation["fp"], validation["fn"]) == (21, 1, 0)
    assert validation["precision"] == 0.9545
    report = json.loads((out / "report.json").read_text())
    assert report["origin"] == [{"origin": "synthetic", "total": 86}]
    cid = report["queue"][0]["id"]
    assert (
        main(
            [
                "--db",
                str(db),
                "case",
                cid,
                "--status",
                "investigating",
                "--note",
                "<script>fixture note</script>",
                "--out",
                str(out / "case.md"),
            ]
        )
        == 0
    )
    case = json.loads(capsys.readouterr().out)
    assert case["timeline"]
    assert case["alerts"][0]["triage"]["mode"] == "dry-run"
    assert "&lt;script&gt;" in (out / "case.md").read_text(encoding="utf-8")
    assert main(["--db", str(db), "demo", "--out", str(out)]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["ingestion"]["duplicate"] == 86 and second["replay"]["alerts_added"] == 0
    with database(db, readonly=True) as conn:
        assert case_detail(conn, cid)["status"] == "investigating"
    with make_server(db, 0) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/", timeout=5) as response:
                html = response.read().decode()
                assert "SOC Operations Console" in html and "21" in html and "39/39" in html
                assert "default-src 'none'" in response.headers["Content-Security-Policy"]
            with urlopen(base + f"/cases/{cid}", timeout=5) as response:
                html = response.read().decode()
                assert "Evidence timeline" in html and "&lt;script&gt;" in html
                assert "<script>" not in html
            with urlopen(base + "/health", timeout=5) as response:
                assert json.load(response) == {"database": "reachable"}
            with pytest.raises(HTTPError) as error:
                urlopen(base + "/cases/absent", timeout=5)
            assert error.value.code == 404
        finally:
            server.shutdown()
            worker.join(5)


def test_committed_dataset_matches_fixture_catalog(tmp_path):
    expected, _ = suite()
    output = tmp_path / "events.jsonl"
    write_jsonl(output, expected)
    assert output.read_bytes() == (ROOT / "datasets" / "synthetic.jsonl").read_bytes()
