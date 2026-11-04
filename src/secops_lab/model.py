"""The event envelope keeps laboratory provenance and raw data outside UDM."""

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

Json = dict[str, Any]
MAX_RECORD = 64 * 1024
EVENT_TYPES = {
    "GENERIC_EVENT",
    "USER_LOGIN",
    "RESOURCE_PERMISSIONS_CHANGE",
    "RESOURCE_CREATION",
    "SETTING_MODIFICATION",
    "PROCESS_LAUNCH",
    "REGISTRY_MODIFICATION",
    "NETWORK_DNS",
    "NETWORK_CONNECTION",
    "NETWORK_HTTP",
    "RESOURCE_READ",
}
PROJECTIONS = {
    "actor": "principal.user.userid",
    "target_user": "target.user.userid",
    "target_host": "target.hostname",
    "application": "target.application",
    "src_ip": "principal.ip",
    "dst_ip": "target.ip",
    "host": "principal.hostname",
    "resource": "target.resource.name",
    "command": "target.process.command_line",
    "process": "target.process.file.full_path",
    "parent_process": "principal.process.file.full_path",
    "registry": "target.registry.registry_key",
    "domain": "target.hostname",
    "url": "target.url",
    "country": "principal.location.country_or_region",
    "sent": "network.sent_bytes",
    "dst_port": "target.port",
    "direction": "network.direction",
}


class InvalidEvent(ValueError):
    """A record outside the supported input profile."""


@dataclass(frozen=True)
class Event:
    id: str
    source: str
    origin: str
    timestamp: str
    raw: Json
    parsed: Json
    udm: Json


def canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def get(record: Any, path: str, default: Any = None) -> Any:
    for part in path.split("."):
        if not isinstance(record, dict) or part not in record:
            return default
        record = record[part]
    return record


def put(record: Json, path: str, value: Any) -> None:
    *parents, field = path.split(".")
    for part in parents:
        record = record.setdefault(part, {})
    record[field] = value


def timestamp(value: Any) -> str:
    if not isinstance(value, str) or "T" not in value:
        raise InvalidEvent("timestamp must be RFC3339 with a time zone")
    try:
        result = datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError
        return result.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError) as error:
        raise InvalidEvent("invalid or timezone-naive timestamp") from error


def validate_udm(udm: Json) -> None:
    """Validate the subset emitted by the local normalizer."""
    timestamp(get(udm, "metadata.eventTimestamp"))
    kind = get(udm, "metadata.eventType")
    if not isinstance(kind, str) or kind not in EVENT_TYPES:
        raise InvalidEvent("unsupported UDM event type")
    for field in ("vendorName", "productName", "productEventType"):
        if not isinstance(get(udm, f"metadata.{field}"), str) or not udm["metadata"][field]:
            raise InvalidEvent(f"missing UDM metadata.{field}")
    required = {
        "USER_LOGIN": ("target.user.userid",),
        "PROCESS_LAUNCH": ("target.process.file.fullPath",),
        "REGISTRY_MODIFICATION": ("target.registry.registryKey",),
        "NETWORK_DNS": ("network.dns.questions",),
        "NETWORK_HTTP": ("target.url",),
        "RESOURCE_PERMISSIONS_CHANGE": ("target.resource.name",),
        "RESOURCE_CREATION": ("target.resource.name",),
        "RESOURCE_READ": ("target.resource.name",),
        "SETTING_MODIFICATION": ("target.resource.name",),
    }
    for path in required.get(kind, ()):
        if not get(udm, path):
            raise InvalidEvent(f"missing UDM {path}")
    if kind == "NETWORK_CONNECTION" and not (get(udm, "target.ip") or get(udm, "target.hostname")):
        raise InvalidEvent("connection missing destination")
    if not any(get(udm, noun) for noun in ("principal", "target", "src", "about")):
        raise InvalidEvent("missing UDM participant")
    if kind == "USER_LOGIN" and not (get(udm, "target.hostname") or get(udm, "target.application")):
        raise InvalidEvent("login missing target host or application")
    if kind in (
        "PROCESS_LAUNCH",
        "REGISTRY_MODIFICATION",
        "NETWORK_CONNECTION",
        "NETWORK_DNS",
        "NETWORK_HTTP",
        "SETTING_MODIFICATION",
    ) and not (get(udm, "principal.ip") or get(udm, "principal.hostname")):
        raise InvalidEvent("missing UDM principal machine identifier")
    for role in ("principal", "target"):
        addresses = get(udm, f"{role}.ip", [])
        if not isinstance(addresses, list):
            raise InvalidEvent("UDM IP must be an array")
        for address in addresses:
            if not isinstance(address, str):
                raise InvalidEvent("UDM IP must be a string")
            try:
                ipaddress.ip_address(address)
            except ValueError as error:
                raise InvalidEvent("invalid IP address") from error
    results = udm.get("securityResult", [])
    if not isinstance(results, list):
        raise InvalidEvent("securityResult must be an array")
    for result in results:
        if get(result, "action") not in (["ALLOW"], ["BLOCK"]):
            raise InvalidEvent("unsupported securityResult.action")


def normalize(source: str, origin: str, raw: Json, parsed: Json) -> Event:
    instant = timestamp(parsed.get("time"))
    product_event = parsed.get("action")
    if not isinstance(product_event, str) or not product_event:
        raise InvalidEvent("missing product event type")
    identity = parsed.get("id")
    scope = parsed.get("scope")
    event_id = digest([source, origin, scope, instant, identity if identity else raw])
    udm: Json = {
        "metadata": {
            "eventTimestamp": instant,
            "eventType": parsed["type"],
            "productEventType": product_event,
            "vendorName": parsed["vendor"],
            "productName": parsed["product"],
            "productLogId": str(identity or event_id),
        }
    }
    if parsed["type"] == "USER_LOGIN":
        parsed = parsed | {"target_user": parsed.get("actor"), "actor": None}
    for key, path in PROJECTIONS.items():
        value = parsed.get(key)
        if value in (None, ""):
            continue
        if key in ("sent", "dst_port"):
            limit = 65535 if key == "dst_port" else 2**64 - 1
            digits = str(value)
            if not digits.isascii() or not digits.isdecimal():
                raise InvalidEvent(f"invalid {key}")
            if len(digits) > 20 or int(digits) > limit:
                raise InvalidEvent(f"out-of-range {key}")
            value = str(int(digits)) if key == "sent" else int(digits)
        elif not isinstance(value, str):
            raise InvalidEvent(f"{key} must be a string")
        if key in ("src_ip", "dst_ip"):
            try:
                value = [str(ipaddress.ip_address(value))]
            except ValueError as error:
                raise InvalidEvent("invalid IP address") from error
        if key == "direction" and value not in {"INBOUND", "OUTBOUND", "BROADCAST"}:
            raise InvalidEvent("unsupported network direction")
        parts = path.split(".")
        put(
            udm,
            ".".join(
                seg.split("_")[0] + "".join(s.title() for s in seg.split("_")[1:]) for seg in parts
            ),
            value,
        )
    if (query := parsed.get("query")) is not None:
        if not isinstance(query, str) or not 0 < len(query) <= 254:
            raise InvalidEvent("invalid DNS query name")
        put(udm, "network.dns.questions", [{"name": query.lower()}])
        put(udm, "network.applicationProtocol", "DNS")
    if parsed["type"] == "SETTING_MODIFICATION" and parsed.get("resource"):
        put(udm, "target.resource.resourceType", "SETTING")
    if parsed["type"] == "NETWORK_HTTP":
        put(udm, "network.http.method", product_event)
    if parsed.get("outcome") in ("ALLOW", "BLOCK"):
        udm["securityResult"] = [{"action": [parsed["outcome"]]}]
    validate_udm(udm)
    return Event(event_id, source, origin, instant, raw, parsed, udm)
