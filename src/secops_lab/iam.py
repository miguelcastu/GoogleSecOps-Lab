"""Reconstruct IAM changes from observed deltas and match subsequent activity."""

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from itertools import groupby

from .model import Event, Json, canonical, get

RULE: Json = {
    "id": "GSL020",
    "title": "Sensitive IAM grant followed by beneficiary activity",
    "severity": "high",
    "attack": ["T1098.003", "T1078.004"],
    "playbook": "cloud",
}
WINDOW = timedelta(minutes=30)
STORAGE_OPERATIONS = {
    "storage.objects.get": "storage.objects.get",
    "storage.objects.list": "storage.objects.list",
    "storage.objects.delete": "storage.objects.delete",
    "google.storage.v2.storage.getobject": "storage.objects.get",
    "google.storage.v2.storage.readobject": "storage.objects.get",
    "google.storage.v2.storage.listobjects": "storage.objects.list",
    "google.storage.v2.storage.deleteobject": "storage.objects.delete",
}
SENSITIVE = {
    "roles/owner": {"storage.objects.get", "storage.objects.list", "storage.objects.delete"},
    "roles/editor": {"storage.objects.get", "storage.objects.list", "storage.objects.delete"},
    "roles/storage.admin": {
        "storage.objects.get",
        "storage.objects.list",
        "storage.objects.delete",
    },
    "roles/storage.objectAdmin": {
        "storage.objects.get",
        "storage.objects.list",
        "storage.objects.delete",
    },
}
PROJECT_PATH = re.compile(r"projects/([a-z][a-z0-9-]{4,29})")
BUCKET_PATH = re.compile(r"projects/_/buckets/[^/]+")


@dataclass(frozen=True)
class Binding:
    action: str
    member: str
    role: str
    condition: Json | None


def binding_changes(payload: Json) -> list[Binding]:
    changes = []
    seen = set()
    for source in ("serviceData", "metadata"):
        deltas = get(payload, f"{source}.policyDelta.bindingDeltas", [])
        if not isinstance(deltas, list):
            continue
        for item in deltas:
            action, member, role = (get(item, name) for name in ("action", "member", "role"))
            if action not in ("ADD", "REMOVE") or not all(
                isinstance(value, str) and value.strip() for value in (member, role)
            ):
                continue
            condition = item.get("condition")
            if condition is not None and not isinstance(condition, dict):
                continue
            # Deduplicate overlapping envelopes without splitting the binding's fields.
            key = (action, member, role, canonical(condition))
            if key not in seen:
                seen.add(key)
                changes.append(Binding(action, member, role, condition))
    return changes


def audit_changes(event: Event) -> list[Binding]:
    payload = get(event.raw, "protoPayload")
    if (
        event.source not in {"gcp_audit", "gcp_iam"}
        or event.parsed.get("outcome") != "ALLOW"
        or str(event.parsed.get("action", "")).rsplit(".", 1)[-1].lower() != "setiampolicy"
        or not isinstance(payload, dict)
    ):
        return []
    return binding_changes(payload)


def observed_project(event: Event) -> str | None:
    log, separator, _ = str(event.raw.get("logName", "")).partition("/logs/")
    match = PROJECT_PATH.fullmatch(log)
    label = get(event.raw, "resource.labels.project_id")
    if not separator or not match or label is not None and label != match[1]:
        return None
    return match[1]


def resource_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    for prefix in ("//cloudresourcemanager.googleapis.com/", "//storage.googleapis.com/"):
        if value.startswith(prefix):
            return value.removeprefix(prefix)
    return value


def covered(resource: str, project: str, observed: str) -> bool:
    if resource == f"projects/{project}":
        return observed.startswith((f"projects/{project}/", "projects/_/buckets/"))
    return bool(
        BUCKET_PATH.fullmatch(resource)
        and (observed == resource or observed.startswith(resource + "/"))
    )


def member_id(actor: object) -> str | None:
    if not isinstance(actor, str) or actor.count("@") != 1 or any(c.isspace() for c in actor):
        return None
    if actor.startswith(("user:", "serviceAccount:")):
        actor = actor.split(":", 1)[1]
    if ":" in actor or not all(actor.split("@")):
        return None
    actor = actor.lower()
    kind = "serviceAccount" if actor.endswith(".gserviceaccount.com") else "user"
    return f"{kind}:{actor}"


def eligible_member(member: str) -> str | None:
    normalized = member_id(member)
    if normalized and member.split(":", 1)[0] == normalized.split(":", 1)[0]:
        return normalized
    return None


def granted_permissions(event: Event) -> Iterator[tuple[str, str]]:
    if get(event.raw, "protoPayload.serviceName") != "storage.googleapis.com":
        return
    required = STORAGE_OPERATIONS.get(str(event.parsed.get("action", "")).lower())
    if required is None:
        return
    entries = get(event.raw, "protoPayload.authorizationInfo", [])
    if not isinstance(entries, list):
        return
    for entry in entries:
        permission = get(entry, "permission")
        resource = resource_path(get(entry, "resource"))
        if get(entry, "granted") is True and permission == required and resource:
            yield required, resource


def grant_matches(events: Iterable[Event]) -> Iterator[tuple[Event, Event, Json]]:
    active: dict[tuple[str, str, str], dict[tuple[str, str], Event]] = defaultdict(dict)
    reported: set[tuple[str, str, str, str]] = set()
    cloud_events = (event for event in events if event.source in {"gcp_audit", "gcp_iam"})
    for _, batch in groupby(cloud_events, key=lambda event: event.timestamp):
        activities = []
        removed = set()
        # Apply policy changes first so a same-timestamp revocation prevents a match.
        for event in batch:
            project = observed_project(event)
            if not project or event.parsed.get("outcome") != "ALLOW":
                continue
            changes = audit_changes(event)
            scope = resource_path(event.parsed.get("resource"))
            if changes:
                if scope != f"projects/{project}" and not BUCKET_PATH.fullmatch(scope):
                    continue
                for binding in changes:
                    member = eligible_member(binding.member)
                    if binding.condition is not None or binding.role not in SENSITIVE or not member:
                        continue
                    grants = active[event.origin, project, member]
                    key = (scope, binding.role)
                    change_key = (event.origin, project, member, *key)
                    if binding.action == "REMOVE":
                        grants.pop(key, None)
                        removed.add(change_key)
                    elif change_key not in removed:
                        grants[key] = event
            elif event.parsed.get("type") != "RESOURCE_PERMISSIONS_CHANGE":
                activities.append((event, project))
        for event, project in activities:
            member = member_id(event.parsed.get("actor"))
            if not member:
                continue
            grants = active.get((event.origin, project, member), {})
            now = datetime.fromisoformat(event.timestamp)
            permissions = list(granted_permissions(event))
            for (scope, role), grant in list(grants.items()):
                elapsed = now - datetime.fromisoformat(grant.timestamp)
                if elapsed > WINDOW:
                    del grants[scope, role]
                    continue
                identity = (grant.id, member, scope, role)
                if elapsed <= timedelta(0) or identity in reported:
                    continue
                match = next(
                    (
                        (p, r)
                        for p, r in sorted(permissions)
                        if p in SENSITIVE[role] and covered(scope, project, r)
                    ),
                    None,
                )
                if match:
                    reported.add(identity)
                    yield (
                        grant,
                        event,
                        {
                            "project": project,
                            "grant_actor": grant.parsed.get("actor"),
                            "beneficiary": member,
                            "role": role,
                            "grant_resource": scope,
                            "permission": match[0],
                            "activity_resource": match[1],
                            "grant_event_id": grant.id,
                            "activity_event_id": event.id,
                            "elapsed_seconds": elapsed.total_seconds(),
                        },
                    )


def change_evidence(event: Event) -> list[Json]:
    return [asdict(binding) for binding in audit_changes(event)]


def revocations(events: Iterable[Event]) -> dict[tuple[str, str, str, str, str], list[Event]]:
    index: dict[tuple[str, str, str, str, str], list[Event]] = defaultdict(list)
    for event in events:
        changes = audit_changes(event)
        if not changes or not (project := observed_project(event)):
            continue
        scope = resource_path(event.parsed.get("resource"))
        for change in changes:
            if change.action == "REMOVE" and change.condition is None:
                if member := eligible_member(change.member):
                    index[event.origin, project, scope, change.role, member].append(event)
    return index
