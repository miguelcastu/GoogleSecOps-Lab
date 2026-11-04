"""Read bounded JSONL batches and preserve accepted input for investigation."""

import json
import math
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from .adapters import parse
from .model import MAX_RECORD, Event, InvalidEvent

MAX_BATCH = 5000
SECRET_KEYS = {
    "authorization",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "token",
    "apikey",
    "privatekey",
    "privatekeydata",
    "sessiontoken",
    "cookie",
    "setcookie",
    "credential",
    "credentials",
}


def check_sensitive(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if re.sub(r"[^a-z0-9]", "", key.lower()) in SECRET_KEYS:
                raise InvalidEvent("sensitive field rejected")
            check_sensitive(item)
    elif isinstance(value, list):
        for item in value:
            check_sensitive(item)
    elif isinstance(value, str) and (
        "PRIVATE KEY-----" in value or re.search(r"\bBearer\s+[A-Za-z0-9._~+/-]{12,}", value, re.I)
    ):
        raise InvalidEvent("sensitive value rejected")


def reject_constant(value: str) -> None:
    raise InvalidEvent("non-finite JSON value")


def finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise InvalidEvent("non-finite JSON value")
    return result


def decode(line: bytes) -> Any:
    return json.loads(
        line.decode("utf-8"), parse_constant=reject_constant, parse_float=finite_float
    )


def records(stream: BinaryIO, limit: int) -> Iterator[tuple[int, bytes]]:
    if not 1 <= limit <= MAX_BATCH:
        raise ValueError(f"limit must be between 1 and {MAX_BATCH}")
    for number in range(1, limit + 1):
        line = stream.readline(MAX_RECORD + 1)
        if not line:
            break
        if len(line) > MAX_RECORD:
            tail = line
            while tail and not tail.endswith(b"\n"):
                tail = stream.readline(MAX_RECORD + 1)
        yield number, line


def read_jsonl(
    path: Path, limit: int, allow_real: bool = False
) -> Iterator[tuple[int, str, Event | str]]:
    with path.open("rb") as stream:
        for line_no, line in records(stream, limit):
            source = "unknown"
            try:
                if len(line) > MAX_RECORD:
                    raise InvalidEvent("record exceeds size limit")
                envelope = decode(line)
                if not isinstance(envelope, dict):
                    raise InvalidEvent("expected an event envelope")
                if isinstance(envelope.get("source"), str):
                    from .adapters import ADAPTERS

                    if envelope["source"] in ADAPTERS:
                        source = envelope["source"]
                origin = envelope.get("origin")
                if origin == "real" and not allow_real:
                    raise InvalidEvent("real data requires --allow-real")
                raw = envelope.get("raw")
                check_sensitive(raw)
                event = parse(source, origin, raw)
                yield line_no, event.source, event
            except (UnicodeError, json.JSONDecodeError, RecursionError):
                yield line_no, source, "invalid or excessively nested JSON"
            except InvalidEvent as error:
                yield line_no, source, str(error)
            except (OverflowError, ValueError):
                yield line_no, source, "invalid record value"
