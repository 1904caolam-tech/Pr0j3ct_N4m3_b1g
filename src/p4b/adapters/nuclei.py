"""Nuclei — ProjectDiscovery. Template-driven active scanning.

Nuclei is the only adapter that deliberately sends traffic to a target, which is why
the scan runner enforces a scope before this ever executes (ADR-006). Here we only
build the command and parse the JSONL it produces.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.attack import extract_attack, extract_cve, extract_cwe
from ..canon.remediation import build as build_remediation
from ..canon.text import as_list, redact, truncate
from ..domain.models import Finding, parse_ts, utcnow
from ..domain.severity import parse as parse_severity
from .base import Adapter, ParseResult, tool_spec


class NucleiAdapter(Adapter):
    name = "nuclei"
    spec = tool_spec("nuclei")

    def build_command(self, target: str, output_path: Path, opts: dict[str, Any]) -> list[str]:
        command = [
            self.executable(),
            "-jsonl",
            "-o",
            str(output_path),
            "-silent",
            "-nc",   # no colour
            "-duc",  # disable update check
        ]
        if target and Path(target).is_file():
            command += ["-l", target]
        else:
            command += ["-u", target]

        for flag, key in (("-severity", "severity"), ("-tags", "tags")):
            value = opts.get(key)
            if value:
                command += [flag, ",".join(value) if isinstance(value, list) else str(value)]
        if opts.get("templates"):
            command += ["-t", str(opts["templates"])]
        if opts.get("rate_limit"):
            command += ["-rl", str(opts["rate_limit"])]
        command += [str(item) for item in opts.get("extra_args") or []]
        return command

    # -- parsing ----------------------------------------------------------- #

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return result

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = list(self.jsonl(path))
        records = payload if isinstance(payload, list) else [payload]

        for record in records:
            if isinstance(record, dict):
                finding = self._to_finding(record)
                if finding is not None:
                    result.findings.append(finding)

        result.stats = {"templates_matched": len(result.findings)}
        return result

    def _to_finding(self, record: dict[str, Any]) -> Finding | None:
        info = record.get("info") or {}
        template_id = str(record.get("template-id") or "")
        if not template_id:
            return None

        classification = info.get("classification") or {}
        tags = [str(tag) for tag in as_list(info.get("tags"))]
        severity = parse_severity(info.get("severity"))
        matched_at = str(record.get("matched-at") or record.get("host") or record.get("url") or "")
        host = str(record.get("host") or record.get("url") or matched_at)
        cve = extract_cve(classification.get("cve-id"), tags, template_id)
        references = [str(url) for url in as_list(info.get("reference"))]
        remediation = str(info.get("remediation") or "").strip()

        category = "exposure"
        if cve or "vuln" in {tag.lower() for tag in tags}:
            category = "vuln"
        if "misconfig" in {tag.lower() for tag in tags}:
            category = "misconfig"

        timestamp = parse_ts(record.get("timestamp")) or utcnow()
        return Finding(
            source="nuclei",
            category=category,
            title=str(info.get("name") or template_id),
            severity=severity,
            asset=asset_for("url", host),
            rule_id=template_id,
            rule_name=str(info.get("name") or template_id),
            locator=matched_at,
            attack=extract_attack(tags, classification.get("cwe-id")),
            cwe=extract_cwe(classification.get("cwe-id")),
            cve=cve,
            tags=tags + [str(record.get("type") or "")],
            references=references,
            remediation=build_remediation(summary=remediation, references=references[:5]),
            evidence=redact(
                {
                    "template": template_id,
                    "matcher": record.get("matcher-name", ""),
                    "type": record.get("type", ""),
                    "matched_at": matched_at,
                    "ip": record.get("ip", ""),
                    "port": record.get("port", ""),
                    "extracted": record.get("extracted-results") or [],
                    "curl": truncate(record.get("curl-command"), 400),
                    "description": truncate(info.get("description"), 800),
                }
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.9 if severity.rank >= 4 else 0.75,
        )
