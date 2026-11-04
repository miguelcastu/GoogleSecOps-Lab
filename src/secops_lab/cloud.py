"""Bounded Google Pub/Sub pull with commit-before-ack delivery semantics."""

import base64
import binascii
import re
import sqlite3
from pathlib import Path

from .adapters import audit_source, parse
from .ingestion import check_sensitive, decode
from .model import MAX_RECORD, InvalidEvent, Json, get
from .storage import accept, database, reject

PROJECT = re.compile(r"gsl-[a-z0-9][a-z0-9-]{2,24}[a-z0-9]")
SUBSCRIPTION = "gsl-audit-pull"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def adc_session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=[SCOPE])
    return AuthorizedSession(credentials)


def commit_messages(conn: sqlite3.Connection, received: list[Json], project: str) -> Json:
    ack_ids = []
    metrics = {"accepted": 0, "duplicate": 0, "rejected": 0}
    for index, item in enumerate(received, 1):
        ack_id = item.get("ackId")
        if not isinstance(ack_id, str) or not ack_id:
            raise ValueError("Pub/Sub returned a message without an ack ID")
        source = "gcp_audit"
        try:
            encoded = get(item, "message.data")
            if not isinstance(encoded, str) or len(encoded) > (MAX_RECORD + 2) // 3 * 4:
                raise InvalidEvent("invalid or oversized Pub/Sub payload")
            payload = base64.b64decode(encoded, validate=True)
            if len(payload) > MAX_RECORD:
                raise InvalidEvent("oversized Pub/Sub payload")
            raw = decode(payload)
            if not isinstance(raw, dict):
                raise InvalidEvent("expected a Cloud Logging object")
            log_name = raw.get("logName")
            if not isinstance(log_name, str) or not log_name.startswith(
                f"projects/{project}/logs/"
            ):
                raise InvalidEvent("audit entry belongs to a different project")
            check_sensitive(raw)
            source = audit_source(raw)
            inserted = accept(conn, parse(source, "real", raw))
            metrics["accepted" if inserted else "duplicate"] += 1
        except InvalidEvent as error:
            reject(conn, source, "pubsub", index, str(error))
            metrics["rejected"] += 1
        except (binascii.Error, UnicodeError, ValueError, RecursionError, OverflowError):
            reject(conn, source, "pubsub", index, "invalid Pub/Sub payload")
            metrics["rejected"] += 1
        ack_ids.append(ack_id)
    return metrics | {"ack_ids": ack_ids}


def pull_once(path: Path, project: str, limit: int, session=None) -> Json:
    if not PROJECT.fullmatch(project) or not 1 <= limit <= 20:
        raise ValueError("use a dedicated gsl-* project and a pull limit between 1 and 20")
    if session is None:
        with adc_session() as authenticated:
            return pull_once(path, project, limit, authenticated)
    base = f"https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{SUBSCRIPTION}"
    response = session.post(base + ":pull", json={"maxMessages": limit}, timeout=20)
    response.raise_for_status()
    received = response.json().get("receivedMessages", [])
    if not isinstance(received, list) or len(received) > limit:
        raise ValueError("invalid Pub/Sub pull response")
    with database(path) as conn:
        result = commit_messages(conn, received, project)
    ack_ids = result.pop("ack_ids")
    if ack_ids:
        response = session.post(base + ":acknowledge", json={"ackIds": ack_ids}, timeout=20)
        response.raise_for_status()
    return result
