"""Opt-in regional Chronicle API transport for a future licensed tenant."""

import argparse
import base64
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

from .cloud import adc_session
from .ingestion import check_sensitive
from .model import Json, canonical, timestamp, validate_udm

COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
LOCATION = re.compile(r"[a-z][a-z0-9-]{1,31}")
MAX_IMPORT = 100
MAX_REQUEST = 3_000_000


def component(value: str) -> str:
    if not COMPONENT.fullmatch(value) or value in (".", ".."):
        raise ValueError("invalid Chronicle resource component")
    return value


class Chronicle:
    """Requests are opt-in. Writes require a second, independent switch."""

    def __init__(self, project: str, location: str, instance: str, session, *, allow_write=False):
        if not LOCATION.fullmatch(location):
            raise ValueError("invalid Chronicle location")
        self.parent = (
            f"projects/{component(project)}/locations/{location}/instances/{component(instance)}"
        )
        self.endpoint = f"https://{location}-chronicle.googleapis.com"
        self.session = session
        self.allow_write = allow_write

    @classmethod
    def from_environment(cls):
        if os.environ.get("GSL_ENABLE_CHRONICLE") != "1":
            raise ValueError("set GSL_ENABLE_CHRONICLE=1 for an authorized licensed tenant")
        project = os.environ.get("GSL_CHRONICLE_PROJECT", "")
        location = os.environ.get("GSL_CHRONICLE_LOCATION", "")
        instance = os.environ.get("GSL_CHRONICLE_INSTANCE", "")
        if not (project and location and instance):
            raise ValueError("Chronicle project, location and instance are required")
        return cls(
            project,
            location,
            instance,
            adc_session(),
            allow_write=os.environ.get("GSL_CHRONICLE_WRITE") == "1",
        )

    def request(self, method: str, path: str, *, body=None, params=None, version="v1") -> Json:
        if body is not None and len(canonical(body).encode()) > MAX_REQUEST:
            raise ValueError("request exceeds the laboratory size limit")
        response = self.session.request(
            method,
            f"{self.endpoint}/{version}/{path}",
            json=body,
            params=params,
            timeout=30,
            allow_redirects=False,
        )
        if not 200 <= response.status_code < 300:
            raise ValueError(f"Chronicle request failed with HTTP {response.status_code}")
        return response.json() if response.content else {}

    def require_write(self) -> None:
        if not self.allow_write:
            raise ValueError("Chronicle write operations require GSL_CHRONICLE_WRITE=1")

    def import_raw(self, log_type: str, records: list[tuple[str, str]]) -> Json:
        self.require_write()
        if not 1 <= len(records) <= MAX_IMPORT:
            raise ValueError("send 1 to 100 logs per request")
        parent = f"{self.parent}/logTypes/{component(log_type)}"
        now = timestamp(datetime.now(UTC).isoformat())
        logs = []
        for instant, raw in records:
            check_sensitive(raw)
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError:
                decoded = None
            check_sensitive(decoded)
            instant = timestamp(instant)
            if instant >= now:
                raise ValueError("raw log timestamp must precede collection time")
            logs.append(
                {
                    "data": base64.b64encode(raw.encode()).decode(),
                    "logEntryTime": instant,
                    "collectionTime": now,
                }
            )
        return self.request(
            "POST", parent + "/logs:import", body={"parent": parent, "inlineSource": {"logs": logs}}
        )

    def import_udm(self, records: list[Json]) -> Json:
        self.require_write()
        if not 1 <= len(records) <= MAX_IMPORT:
            raise ValueError("send 1 to 100 UDM events per request")
        for udm in records:
            check_sensitive(udm)
            validate_udm(udm)
        return self.request(
            "POST",
            self.parent + "/events:import",
            body={
                "parent": self.parent,
                "inlineSource": {"events": [{"udm": record} for record in records]},
            },
        )

    def verify_rule(self, source: str) -> Json:
        return self.request("POST", self.parent + ":verifyRuleText", body={"ruleText": source})

    def create_rule(self, source: str) -> Json:
        self.require_write()
        if self.verify_rule(source).get("success") is not True:
            raise ValueError("Chronicle rejected the rule text; nothing was created")
        return self.request("POST", self.parent + "/rules", body={"text": source})

    def deploy_rule(self, rule_id: str, *, enabled: bool) -> Json:
        self.require_write()
        name = f"{self.parent}/rules/{component(rule_id)}/deployment"
        return self.request(
            "PATCH", name, body={"name": name, "enabled": enabled}, params={"updateMask": "enabled"}
        )

    def detections(self, rule_id: str, start: str, end: str, page_token: str = "") -> Json:
        start, end = timestamp(start), timestamp(end)
        if start >= end:
            raise ValueError("detection time range must be increasing")
        return self.request(
            "GET",
            self.parent + "/legacy:legacySearchDetections",
            params={
                "ruleId": component(rule_id),
                "startTime": start,
                "endTime": end,
                "pageSize": 100,
                **({"pageToken": page_token} if page_token else {}),
            },
            version="v1alpha",
        )

    def cases(self, page_token: str = "") -> Json:
        params = {"pageSize": 50} | ({"pageToken": page_token} if page_token else {})
        return self.request("GET", self.parent + "/cases", params=params)

    def case(self, case_id: str) -> Json:
        return self.request("GET", self.parent + f"/cases/{component(case_id)}")

    def case_detections(self, case_id: str) -> Json:
        return self.request(
            "GET", self.parent + f"/cases/{component(case_id)}/detections", version="v1alpha"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify", "create"])
    parser.add_argument("rule", type=Path)
    args = parser.parse_args()
    try:
        if args.rule.suffix != ".yaral" or args.rule.stat().st_size > 64 * 1024:
            raise ValueError("provide one .yaral file of at most 64 KiB")
        source = args.rule.read_text(encoding="utf-8")
        client = Chronicle.from_environment()
        with client.session:
            result = (
                client.verify_rule(source)
                if args.command == "verify"
                else client.create_rule(source)
            )
        print(json.dumps(result, indent=2))
        return int(args.command == "verify" and result.get("success") is not True)
    except (ValueError, OSError) as error:
        parser.exit(2, f"{error}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
