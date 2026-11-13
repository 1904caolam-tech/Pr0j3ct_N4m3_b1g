"""Wazuh alert ingest.

Wazuh is a platform, not a library: it runs its own manager and indexer. P4B reads
`alerts.json` (or receives the same objects over HTTP) and keeps the fields that
matter for correlation: rule level, rule id, MITRE mapping and agent identity.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.attack import extract_attack
from ..canon.text import as_list, redact, truncate
from ..domain.models import Finding, parse_ts, utcnow
from ..domain.severity import parse as parse_severity
from .base import Adapter, ParseResult, integer, tool_spec

DEFAULT_MIN_LEVEL = 7


class WazuhAdapter(Adapter):
    name = "wazuh"
    spec = tool_spec("wazuh")

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        ctx = ctx or {}
        min_level = integer(ctx.get("min_level", DEFAULT_MIN_LEVEL))
        result = ParseResult()
        skipped = 0

        for alert in self.jsonl(path):
            rule = alert.get("rule") or {}
            level = integer(rule.get("level"))
            if level < min_level:
                skipped += 1
                continue
            finding = self._to_finding(alert, rule, level)
            if finding is not None:
                result.findings.append(finding)

        result.stats = {"alerts": len(result.findings), "below_threshold": skipped}
        if skipped:
            result.warnings.append(f"{skipped} alert(s) below rule.level {min_level} were skipped")
        return result

    def _to_finding(self, alert: dict[str, Any], rule: dict[str, Any], level: int) -> Finding | None:
        description = str(rule.get("description") or "Wazuh alert").strip()
        rule_id = str(rule.get("id") or "")
        if not rule_id and not description:
            return None

        agent = alert.get("agent") or {}
        host = str(agent.get("name") or agent.get("id") or "unknown")
        mitre = rule.get("mitre") or {}
        groups = [str(group) for group in as_list(rule.get("groups"))]
        timestamp = parse_ts(alert.get("timestamp")) or utcnow()

        return Finding(
            source="wazuh",
            category="detection",
            title=description,
            severity=parse_severity(level, "wazuh"),
            asset=asset_for("host", host, ip=str(agent.get("ip") or "")),
            rule_id=rule_id or description,
            rule_name=description,
            locator=f"{rule_id}:{host}",
            attack=extract_attack(mitre.get("id"), mitre.get("technique")),
            tags=["hids", "wazuh", *groups],
            references=[url for url in as_list(rule.get("info")) if str(url).startswith("http")],
            evidence=redact(
                {
                    "level": level,
                    "groups": groups,
                    "mitre": mitre,
                    "agent_id": agent.get("id"),
                    "agent_ip": agent.get("ip"),
                    "manager": (alert.get("manager") or {}).get("name"),
                    "decoder": (alert.get("decoder") or {}).get("name"),
                    "location": alert.get("location"),
                    "full_log": truncate(alert.get("full_log"), 1200),
                    "srcip": (alert.get("data") or {}).get("srcip"),
                }
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.85 if level >= 10 else 0.7,
        )
