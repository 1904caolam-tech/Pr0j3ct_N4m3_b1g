"""Suricata EVE ingest.

Suricata writes one JSON object per line to `eve.json`. Only `event_type=alert`
becomes a finding; everything else is counted so the operator can see the sensor is
alive. `flow_id` is preserved because it is the only cheap way to tie an alert to
the HTTP/DNS context that preceded it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.attack import extract_attack
from ..canon.text import redact, truncate
from ..domain.models import Finding, parse_ts, utcnow
from ..domain.severity import parse as parse_severity
from .base import Adapter, ParseResult, integer, tool_spec

PRIVATE_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1$|fc|fd)")


def exposure_for(ip: str) -> str:
    return "internal" if PRIVATE_RE.match(ip or "") else "internet"


class SuricataAdapter(Adapter):
    name = "suricata"
    spec = tool_spec("suricata")

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        counts: dict[str, int] = {}

        for file in self.files(path, "eve*.json"):
            for event in self.jsonl(file):
                event_type = str(event.get("event_type") or "unknown")
                counts[event_type] = counts.get(event_type, 0) + 1
                if event_type != "alert":
                    continue
                finding = self._to_finding(event)
                if finding is not None:
                    result.findings.append(finding)

        result.stats = counts
        if not result.findings:
            result.warnings.append("no alert events in capture (flow/http/dns events are counted only)")
        return result

    def _to_finding(self, event: dict[str, Any]) -> Finding | None:
        alert = event.get("alert") or {}
        signature = str(alert.get("signature") or "").strip()
        if not signature:
            return None

        sid = alert.get("signature_id")
        src_ip = str(event.get("src_ip") or "")
        dst_ip = str(event.get("dest_ip") or "")
        dst_port = event.get("dest_port")
        metadata = alert.get("metadata") or {}
        http = event.get("http") or {}
        dns = event.get("dns") or {}
        timestamp = parse_ts(event.get("timestamp")) or utcnow()

        http_context = {
            key: http.get(key)
            for key in ("hostname", "url", "http_method", "status", "user_agent")
            if http.get(key)
        }
        dns_context = {key: dns.get(key) for key in ("rrname", "rrtype", "rcode") if dns.get(key)}

        return Finding(
            source="suricata",
            category="detection",
            title=signature,
            severity=parse_severity(alert.get("severity"), "suricata"),
            asset=asset_for("ip", dst_ip or src_ip, exposure=exposure_for(dst_ip or src_ip)),
            rule_id=f"sid:{sid}" if sid is not None else signature,
            rule_name=signature,
            locator=f"{src_ip}->{dst_ip}:{dst_port}:{sid}",
            attack=extract_attack(metadata, signature),
            tags=[tag for tag in ("ids", alert.get("category"), event.get("proto"), event.get("app_proto")) if tag],
            references=[f"https://sid.erpc.global/?sid={sid}"] if sid else [],
            evidence=redact(
                {
                    "flow_id": event.get("flow_id"),
                    "action": alert.get("action"),
                    "category": alert.get("category"),
                    "gid": alert.get("gid"),
                    "rev": alert.get("rev"),
                    "priority": integer(alert.get("severity")),
                    "src_ip": src_ip,
                    "src_port": event.get("src_port"),
                    "dest_ip": dst_ip,
                    "dest_port": dst_port,
                    "proto": event.get("proto"),
                    "app_proto": event.get("app_proto"),
                    "http": http_context,
                    "dns": dns_context,
                    "payload": truncate(event.get("payload_printable"), 400),
                    "metadata": metadata,
                }
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.8,
        )
