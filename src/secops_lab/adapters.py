"""Adapters for bounded, documented subsets of vendor export formats."""

from typing import Any

from .model import Event, InvalidEvent, Json, get, normalize

GCP_IAM = {"iam.googleapis.com", "cloudresourcemanager.googleapis.com"}
GCP_AUDIT = "type.googleapis.com/google.cloud.audit.AuditLog"
SSHD = r"^(Accepted|Failed) (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+(?: ssh2)?$"


def gcp(raw: Json) -> Json:
    payload = raw.get("protoPayload")
    if get(payload, "@type") != GCP_AUDIT:
        raise InvalidEvent("expected a Cloud Audit Logs LogEntry")
    method = get(payload, "methodName")
    service = get(payload, "serviceName")
    if not isinstance(method, str) or not isinstance(service, str) or not service:
        raise InvalidEvent("audit method and service are required")
    suffix = method.rsplit(".", 1)[-1].lower()
    kind = {
        "setiampolicy": "RESOURCE_PERMISSIONS_CHANGE",
        "createserviceaccountkey": "RESOURCE_CREATION",  # pragma: allowlist secret
        "getobject": "RESOURCE_READ",
        "storage.objects.get": "RESOURCE_READ",
        "storage.objects.create": "RESOURCE_CREATION",
        "updatebucket": "SETTING_MODIFICATION",
        "createlogexclusion": "SETTING_MODIFICATION",
        "updateexclusion": "SETTING_MODIFICATION",
        "createexclusion": "SETTING_MODIFICATION",
        "deletesink": "SETTING_MODIFICATION",
        "updatesink": "SETTING_MODIFICATION",
        "createsink": "SETTING_MODIFICATION",
    }.get(method.lower())
    if not kind:
        kind = {
            "setiampolicy": "RESOURCE_PERMISSIONS_CHANGE",
            "createserviceaccountkey": "RESOURCE_CREATION",  # pragma: allowlist secret
            "createexclusion": "SETTING_MODIFICATION",
            "updateexclusion": "SETTING_MODIFICATION",
            "updatesink": "SETTING_MODIFICATION",
            "deletesink": "SETTING_MODIFICATION",
            "createsink": "SETTING_MODIFICATION",
            "insert": "SETTING_MODIFICATION" if ".firewalls." in method else "GENERIC_EVENT",
            "patch": "SETTING_MODIFICATION" if ".firewalls." in method else "GENERIC_EVENT",
        }.get(suffix, "GENERIC_EVENT")
    code = get(payload, "status.code", 0)
    if type(code) is not int:
        raise InvalidEvent("audit status.code must be an integer")
    src = get(payload, "requestMetadata.callerIp")
    if src in ("private", "gce-internal-ip", "redacted"):
        src = None
    if kind == "SETTING_MODIFICATION" and not src:
        kind = "GENERIC_EVENT"
    return dict(
        time=raw.get("timestamp"),
        id=raw.get("insertId"),
        scope=raw.get("logName"),
        action=method,
        type=kind,
        actor=get(payload, "authenticationInfo.principalEmail")
        or get(payload, "authenticationInfo.principalSubject"),
        src_ip=src,
        resource=get(payload, "resourceName"),
        outcome="ALLOW" if code == 0 else "BLOCK",
    )


def workspace(raw: Json) -> Json:
    event = raw.get("events")
    if not isinstance(event, list) or len(event) != 1:
        raise InvalidEvent("split Workspace activities into one event per record")
    action = get(event[0], "name")
    outcomes = {"login_success": "ALLOW", "login_failure": "BLOCK"}
    return dict(
        time=get(raw, "id.time"),
        id=get(raw, "id.uniqueQualifier"),
        scope=get(raw, "id.customerId"),
        action=action,
        type="USER_LOGIN" if action in tuple(outcomes) else "GENERIC_EVENT",
        outcome=outcomes.get(action) if isinstance(action, str) else None,
        actor=get(raw, "actor.email"),
        src_ip=raw.get("ipAddress"),
        application="Google Workspace",
    )


def entra(raw: Json) -> Json:
    code = get(raw, "status.errorCode")
    if type(code) is not int:
        raise InvalidEvent("sign-in status.errorCode must be an integer")
    return dict(
        time=raw.get("createdDateTime"),
        id=raw.get("id"),
        action="SignIn",
        type="USER_LOGIN",
        actor=raw.get("userPrincipalName"),
        src_ip=raw.get("ipAddress"),
        application=raw.get("appDisplayName") or "Microsoft Entra ID",
        country=get(raw, "location.countryOrRegion"),
        outcome="ALLOW" if code == 0 else "BLOCK",
    )


def windows(raw: Json) -> Json:
    code = raw.get("EventID")
    if type(code) is not int or code not in (4624, 4625):
        raise InvalidEvent("expected Windows Security 4624 or 4625")
    return dict(
        time=raw.get("TimeCreated"),
        id=raw.get("EventRecordID"),
        scope=raw.get("Computer"),
        action=str(code),
        type="USER_LOGIN",
        actor=get(raw, "EventData.TargetUserName"),
        target_host=raw.get("Computer"),
        src_ip=get(raw, "EventData.IpAddress") if get(raw, "EventData.IpAddress") != "-" else None,
        outcome="ALLOW" if code == 4624 else "BLOCK",
    )


def sysmon(raw: Json) -> Json:
    code = raw.get("EventID")
    kind = {1: "PROCESS_LAUNCH", 3: "NETWORK_CONNECTION", 13: "REGISTRY_MODIFICATION"}
    if type(code) is not int or code not in kind:
        raise InvalidEvent("expected Sysmon 1, 3 or 13")
    fields = raw.get("EventData")
    return dict(
        time=raw.get("TimeCreated"),
        id=raw.get("EventRecordID"),
        scope=raw.get("Computer"),
        action=str(code),
        type=kind[code],
        actor=get(fields, "User"),
        host=raw.get("Computer"),
        process=get(fields, "Image") if code == 1 else None,
        parent_process=get(fields, "ParentImage")
        if code == 1
        else get(fields, "Image")
        if code == 13
        else None,
        command=get(fields, "CommandLine") if code == 1 else None,
        registry=get(fields, "TargetObject") if code == 13 else None,
        src_ip=get(fields, "SourceIp"),
        dst_ip=get(fields, "DestinationIp"),
        dst_port=get(fields, "DestinationPort"),
    )


def linux(raw: Json) -> Json:
    import re

    message = raw.get("message")
    match = re.fullmatch(SSHD, message) if isinstance(message, str) else None
    if not match:
        raise InvalidEvent("unsupported sshd message")
    action, actor, src = match.groups()
    return dict(
        time=raw.get("timestamp"),
        id=raw.get("id"),
        scope=raw.get("hostname"),
        action=f"sshd {action}",
        type="USER_LOGIN",
        actor=actor,
        src_ip=src,
        target_host=raw.get("hostname"),
        outcome="ALLOW" if action == "Accepted" else "BLOCK",
    )


def falcon(raw: Json) -> Json:
    if get(raw, "metadata.eventType") != "DetectionSummaryEvent":
        raise InvalidEvent("expected Falcon DetectionSummaryEvent")
    ms = get(raw, "metadata.eventCreationTime")
    if type(ms) is not int or not 0 <= ms <= 253402300799999:
        raise InvalidEvent("invalid Falcon eventCreationTime milliseconds")
    from datetime import UTC, datetime, timedelta

    time = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=ms)
    return dict(
        time=time.isoformat(),
        id=get(raw, "event.DetectId"),
        action="DetectionSummaryEvent",
        type="PROCESS_LAUNCH",
        actor=get(raw, "event.UserName"),
        host=get(raw, "event.ComputerName"),
        process=get(raw, "event.FilePath"),
        command=get(raw, "event.CommandLine"),
    )


def fortigate(raw: Json) -> Json:
    if raw.get("type") != "traffic" or raw.get("subtype") != "forward":
        raise InvalidEvent("expected FortiGate forward traffic")
    action = raw.get("action")
    if not isinstance(action, str):
        raise InvalidEvent("missing FortiGate traffic action")
    return dict(
        time=raw.get("timestamp"),
        id=raw.get("record_id"),
        scope=raw.get("devid"),
        action=action,
        type="NETWORK_CONNECTION",
        src_ip=raw.get("srcip"),
        dst_ip=raw.get("dstip"),
        dst_port=raw.get("dstport"),
        sent=raw.get("sentbyte"),
        direction="OUTBOUND"
        if raw.get("dstintfrole") == "wan" and raw.get("srcintfrole") == "lan"
        else None,
        outcome={"accept": "ALLOW", "deny": "BLOCK"}.get(action),
    )


def dns(raw: Json) -> Json:
    return dict(
        time=raw.get("ts"),
        id=raw.get("id"),
        action="dns_query",
        type="NETWORK_DNS",
        src_ip=raw.get("id.orig_h"),
        dst_ip=raw.get("id.resp_h"),
        query=raw.get("query"),
    )


def proxy(raw: Json) -> Json:
    url = raw.get("url")
    from urllib.parse import urlsplit

    parsed = urlsplit(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InvalidEvent("expected absolute HTTP(S) proxy URL")
    return dict(
        time=raw.get("timestamp"),
        id=raw.get("request_id"),
        action=raw.get("method"),
        type="NETWORK_HTTP",
        actor=raw.get("user"),
        src_ip=raw.get("client_ip"),
        dst_ip=raw.get("upstream_ip"),
        domain=parsed.hostname,
        url=url,
        sent=raw.get("request_bytes"),
    )


def aws(raw: Json) -> Json:
    action = raw.get("eventName")
    if not isinstance(action, str):
        raise InvalidEvent("missing CloudTrail eventName")
    src = raw.get("sourceIPAddress")
    if isinstance(src, str) and src.endswith(".amazonaws.com"):
        src = None
    resource = get(raw, "requestParameters.bucketName") or get(raw, "requestParameters.roleName")
    return dict(
        time=raw.get("eventTime"),
        id=raw.get("eventID"),
        action=action,
        type="RESOURCE_READ"
        if action == "GetObject"
        else "RESOURCE_PERMISSIONS_CHANGE"
        if action in ("PutBucketPolicy", "AttachRolePolicy")
        else "GENERIC_EVENT",
        resource=resource,
        actor=get(raw, "userIdentity.arn"),
        src_ip=src,
        outcome="BLOCK" if raw.get("errorCode") else "ALLOW",
    )


def webhook(raw: Json) -> Json:
    return dict(
        time=raw.get("timestamp"),
        id=raw.get("id"),
        action=raw.get("action"),
        type="GENERIC_EVENT",
        actor=raw.get("actor"),
        resource=raw.get("resource"),
        src_ip=raw.get("source_ip"),
    )


ADAPTERS = {
    "gcp_audit": ("Google", "Cloud Audit Logs", gcp),
    "gcp_iam": ("Google", "Cloud Audit Logs", gcp),
    "workspace": ("Google", "Workspace", workspace),
    "entra": ("Microsoft", "Entra ID", entra),
    "windows": ("Microsoft", "Windows Security", windows),
    "sysmon": ("Microsoft", "Sysmon", sysmon),
    "linux": ("OpenSSH", "sshd", linux),
    "falcon": ("CrowdStrike", "Falcon", falcon),
    "fortigate": ("Fortinet", "FortiGate", fortigate),
    "dns": ("Zeek", "DNS", dns),
    "proxy": ("Lab", "HTTP Proxy", proxy),
    "cloudtrail": ("Amazon", "AWS CloudTrail", aws),
    "webhook": ("Lab", "JSON Webhook", webhook),
}


def audit_source(raw: Json) -> str:
    return "gcp_iam" if get(raw, "protoPayload.serviceName") in tuple(GCP_IAM) else "gcp_audit"


def parse(source: Any, origin: Any, raw: Any) -> Event:
    if not isinstance(source, str) or source not in ADAPTERS:
        raise InvalidEvent("unsupported source")
    if origin not in ("synthetic", "real"):
        raise InvalidEvent("invalid origin")
    if not isinstance(raw, dict):
        raise InvalidEvent("expected a raw JSON object")
    vendor, product, adapter = ADAPTERS[source]
    if source.startswith("gcp_"):
        source = audit_source(raw)
    parsed = adapter(raw)
    for key in ("id", "scope"):
        value = parsed.get(key)
        if value is not None and type(value) not in (str, int):
            raise InvalidEvent(f"invalid event {key}")
    return normalize(source, origin, raw, parsed | {"vendor": vendor, "product": product})
