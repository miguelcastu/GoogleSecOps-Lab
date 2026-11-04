"""Render tracked lab fixtures, detection reference and YARA-L source from the catalog."""

import argparse
import json
import re
from pathlib import Path
from typing import Any

from secops_lab.detection import catalog
from secops_lab.model import Json
from secops_lab.scenarios import fixture_catalog, suite

ROOT = Path(__file__).resolve().parents[1]


def expression(variable: str, condition: list[Any]) -> str:
    field, op, value = condition
    path = f"${variable}.{field}"
    if op == "regex":
        pattern = value.replace("/", r"\/")
        return f"{path} = /{pattern}/ nocase"
    if op == "in":
        if len(value) == 1:
            value = value[0]
        else:
            alternatives = "|".join(re.escape(item).replace(r"\ ", " ") for item in value)
            return f"{path} = /^({alternatives})$/"
    comparator = ">=" if op == "gte" else "="
    return f"{path} {comparator} {json.dumps(value)}"


def render(rule: Json) -> str:
    events = [expression("e", condition) for condition in rule["conditions"]]
    correlation = rule["correlation"]
    match = ""
    condition = "$e"
    if correlation:
        follow = correlation.get("follow", [])
        keys = correlation["keys"]
        follow_keys = correlation.get("follow_keys", keys)
        events.extend(expression("f", predicate) for predicate in follow)
        placeholders = []
        for index, field in enumerate(keys):
            placeholder = f"$key{index}"
            placeholders.append(placeholder)
            events.append(f"{placeholder} = $e.{field}")
            if follow:
                events.append(f"{placeholder} = $f.{follow_keys[index]}")
        distinct = correlation.get("distinct")
        if distinct:
            events += [f"$distinct_value = $e.{distinct}", f'$e.{distinct} != ""']
        count = "#distinct_value" if distinct else "#e"
        condition = f"{count} >= {correlation['count']}"
        if follow:
            events.append(
                "$e.metadata.event_timestamp.seconds < $f.metadata.event_timestamp.seconds"
            )
            condition += " and $f"
        match = f"\n  match:\n    {', '.join(placeholders)} over {correlation['minutes']}m\n"
    statements = "\n".join(f"    {event}" for event in events)
    return f'''rule {rule["name"]} {{
  meta:
    author = "GoogleSecOps-Lab"
    rule_id = "{rule["id"]}"
    description = "{rule["title"]}"
    severity = "{rule["severity"].upper()}"
    mitre_attack = "{", ".join(rule["attack"])}"
    validation = "PENDING"

  events:
{statements}
{match}
  condition:
    {condition}
}}
'''


def reference(rules: list[Json]) -> str:
    lines = [
        "# Detection library",
        "",
        "Native Google SecOps validation is **PENDING** for every rule. "
        "The checked-in YARA-L source and the Python evaluator use a shared detection specification. "
        "Passing fixture checks establishes Python behavior on those inputs.",
        "",
        "The rules target the laboratory UDM profile. Compare product names, event classifications "
        "and identity fields against the native default parser before deploying a rule.",
        "",
    ]
    for rule in rules:
        name = f"{rule['id']}_{rule['name']}.yaral"
        window = rule["correlation"] or {}
        fields = {condition[0] for condition in rule["conditions"] + window.get("follow", [])}
        fields.update(window.get("keys", []) + window.get("follow_keys", []))
        if window.get("distinct"):
            fields.add(window["distinct"])
        if window.get("follow"):
            fields.add("metadata.event_timestamp")
        lines += [
            f"## {rule['id']} · {rule['title']}",
            "",
            f"- [YARA-L source](../detections/yara_l/{name}) · **{rule['severity']}**",
            f"- ATT&CK: {', '.join(rule['attack'])}",
            f"- Sources: {', '.join(rule['sources'])}",
            f"- Fields: {', '.join(f'{field!r}' for field in sorted(fields))}",
            f"- Behavior: {rule['rationale']}",
            f"- False positives: {rule['false_positive']}",
            f"- Tuning: {rule['tuning']}",
            f"- Fixtures: [scenario index](../scenarios/catalog.json) · {rule['scenario']}",
            f"- Expected: {rule['expected']}",
            "- Validation: Python fixture tests and structural source check. Native status PENDING.",
            "",
        ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rules = catalog()
    fixtures, validation = suite()
    artifacts = {
        f"detections/yara_l/{rule['id']}_{rule['name']}.yaral": render(rule) for rule in rules
    }
    artifacts["docs/detections.md"] = reference(rules)
    artifacts["scenarios/catalog.json"] = json.dumps(fixture_catalog(), indent=2) + "\n"
    artifacts["datasets/synthetic.jsonl"] = "".join(
        json.dumps(row, sort_keys=True) + "\n" for row in fixtures
    )
    artifacts["datasets/expected.json"] = (
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario": x["scenario"],
                        "expected": x["expected"],
                        **({"ground_truth": x["ground_truth"]} if "ground_truth" in x else {}),
                    }
                    for x in validation["tests"]
                ]
            },
            indent=2,
        )
        + "\n"
    )
    stale = []
    for name, data in artifacts.items():
        path = ROOT / name
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != data:
                stale.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data, encoding="utf-8", newline="\n")
    if stale:
        print("Regenerate stale content: " + ", ".join(stale))
        return 1
    print(f"{len(artifacts)} artifacts {'checked' if args.check else 'generated'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
