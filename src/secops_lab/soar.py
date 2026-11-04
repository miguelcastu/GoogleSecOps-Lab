"""Deterministic offline enrichment and dry-run response playbooks."""

import ipaddress

from .detection import SEVERITIES, Alert, values
from .model import Event, Json, digest

PLAYBOOKS = {
    "authentication": [
        "Compare the identity, source IP, MFA and managed device history.",
        "Confirm whether the user or a known service made the attempts.",
        "If confirmed, request account containment through the approved process.",
    ],
    "cloud": [
        "Identify the cloud principal, service account and affected resource.",
        "Compare granted roles or key creation with the change ticket and policy history.",
        "If unauthorized, recommend scoped rollback and credential review.",
    ],
    "endpoint": [
        "Inspect the process tree, signer and initiating user.",
        "Correlate host activity with file and network evidence.",
        "If confirmed, request endpoint isolation through the approved process.",
    ],
    "exfiltration": [
        "Identify the datasets, destination and observed transfer size.",
        "Compare the activity with approved backups and scheduled jobs.",
        "If confirmed, request data-owner review and scoped containment.",
    ],
    "configuration": [
        "Retrieve configuration before and after the change.",
        "Verify change approval and assess exposed resources or lost visibility.",
        "If unauthorized, request a reviewed rollback and preserve audit evidence.",
    ],
    "network": [
        "Compare the destination with approved services and resolver baselines.",
        "Review query labels or session counts alongside process and host activity.",
        "If confirmed, submit a reviewed block request to the network owner.",
    ],
}
OFFLINE_IP = {
    "192.0.2.20": "Synthetic client fixture",
    "192.0.2.90": "Synthetic approved backup fixture",
    "198.51.100.17": "Synthetic external service fixture",
}


def group_case(alert: Alert, events: list[Event]) -> str:
    return digest(
        [
            alert.playbook,
            alert.subject,
            alert.timestamp[:10],
            sorted({event.origin for event in events}),
        ]
    )


def classify_address(address: str, synthetic: bool) -> str:
    if synthetic and address in OFFLINE_IP:
        return OFFLINE_IP[address]
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return "loopback"
    return "globally routed address" if ip.is_global else "non-global address"


def enrich(alert: Alert, events: list[Event]) -> Json:
    ip_context = {}
    domain_context = {}
    for event in events:
        for field in ("principal.ip", "target.ip"):
            for ip in values(event.udm, field):
                ip_context[ip] = classify_address(ip, event.origin == "synthetic")
        domains = values(event.udm, "network.dns.questions.name")
        domains += values(event.udm, "target.hostname")
        for domain in domains:
            domain_context[domain] = (
                "reserved lab domain"
                if domain.rstrip(".").endswith(".test")
                else "observed domain; offline reputation unavailable"
            )
    sources = sorted({event.source for event in events})
    confidence = min(90, 45 + len(events) * 4 + (15 if len(sources) > 1 else 0))
    return {
        "mode": "dry-run",
        "sources": sources,
        "confidence": confidence,
        "risk": min(100, (SEVERITIES[alert.severity] * 7 + confidence * 3) // 10),
        "ip_context": ip_context,
        "domain_context": domain_context,
        "attack": [
            {"id": t, "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
            for t in alert.attack
        ],
        "recommendations": PLAYBOOKS[alert.playbook],
    }
