"""Independent Python reference evaluation over normalized event envelopes."""

import json
import re
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib.resources import files
from itertools import product
from typing import Any

from .model import Event, Json, digest

SEVERITIES = {"medium": 55, "high": 80}
SUPPRESSION = timedelta(minutes=15)


def catalog() -> list[Json]:
    return json.loads(files("secops_lab").joinpath("rules.json").read_text(encoding="utf-8"))


def values(udm: Any, path: str) -> list[Any]:
    found = [udm]
    for part in path.split("."):
        names = part.split("_")
        name = names[0] + "".join(segment.title() for segment in names[1:])
        next_level = []
        for parent in found:
            if isinstance(parent, dict) and name in parent:
                result = parent[name]
                next_level.extend(result if isinstance(result, list) else [result])
        found = next_level
    return found


def predicate(udm: Json, item: list[Any]) -> bool:
    path, op, expected = item
    actual = values(udm, path)
    if op == "eq":
        return expected in actual
    if op == "in":
        return any(value in expected for value in actual)
    if op == "regex":
        return any(isinstance(v, str) and re.search(expected, v, re.I) for v in actual)
    if op == "gte":
        return any(
            (type(v) is int or isinstance(v, str) and v.isascii() and v.isdecimal())
            and int(v) >= expected
            for v in actual
        )
    raise ValueError(f"Unknown predicate {op}")


@dataclass(frozen=True)
class Alert:
    id: str
    rule_id: str
    title: str
    severity: str
    attack: list[str]
    playbook: str
    subject: str
    timestamp: str
    event_ids: list[str]


def groups(event: Event, paths: list[str]) -> set[tuple[str, ...]]:
    dimensions = [
        {str(v) for v in values(event.udm, path) if v not in ("", None)} for path in paths
    ]
    return set(product(*dimensions))


def evaluate(events: Iterable[Event], rules: list[Json] | None = None) -> list[Alert]:
    ordered = sorted(
        {event.id: event for event in events}.values(),
        key=lambda event: (event.timestamp, event.id),
    )
    alerts: list[Alert] = []
    for rule in catalog() if rules is None else rules:
        windows: dict[tuple[str, ...], deque[tuple[datetime, Event]]] = defaultdict(deque)
        last_alert: dict[tuple[str, ...], datetime] = {}
        correlation = rule["correlation"]
        for event in ordered:
            if event.source not in rule["sources"]:
                continue
            first = all(predicate(event.udm, p) for p in rule["conditions"])
            if not correlation:
                if first:
                    alerts.append(make_alert(rule, single_subject(event), [event]))
                continue
            follow = correlation.get("follow")
            is_follow = bool(follow and all(predicate(event.udm, p) for p in follow))
            if not first and not is_follow:
                continue
            now = datetime.fromisoformat(event.timestamp)
            cutoff = now - timedelta(minutes=correlation["minutes"])
            first_keys = groups(event, correlation["keys"]) if first else set()
            follow_keys = (
                groups(event, correlation.get("follow_keys", correlation["keys"]))
                if is_follow
                else set()
            )
            for key in sorted(first_keys | follow_keys):
                window = windows[(event.origin, *key)]
                while window and window[0][0] < cutoff:
                    window.popleft()
                if key in first_keys:
                    window.append((now, event))
                if follow and key not in follow_keys:
                    continue
                candidates = [item for time, item in window if not follow or time < now]
                distinct = correlation.get("distinct")
                count = (
                    len({v for item in candidates for v in values(item.udm, distinct) if v})
                    if distinct
                    else len(candidates)
                )
                if count < correlation["count"]:
                    continue
                subject = " → ".join(key)
                suppression_key = (event.origin, *key)
                if (
                    suppression_key in last_alert
                    and now - last_alert[suppression_key] < SUPPRESSION
                ):
                    continue
                last_alert[suppression_key] = now
                alerts.append(make_alert(rule, subject, candidates + ([event] if follow else [])))
    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id, alert.id))


def single_subject(event: Event) -> str:
    for key in (
        "principal.user.userid",
        "target.user.userid",
        "principal.hostname",
        "principal.ip",
        "target.resource.name",
    ):
        found = values(event.udm, key)
        if found:
            return str(found[0])
    return event.id[:12]


def make_alert(rule: Json, subject: str, evidence: list[Event]) -> Alert:
    event_ids = [event.id for event in evidence]
    return Alert(
        digest([rule["id"], subject, event_ids]),
        rule["id"],
        rule["title"],
        rule["severity"],
        rule["attack"],
        rule["playbook"],
        subject,
        evidence[-1].timestamp,
        event_ids,
    )
