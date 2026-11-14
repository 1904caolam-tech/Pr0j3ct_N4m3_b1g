"""Zeek log ingest.

Zeek produces many logs. Turning all of them into alerts would be noise, so only
signal-bearing streams become findings: `notice`, `weird`, `intel`, plus one
documented heuristic on DNS. Everything else (`conn`, `http`, `ssl`, ...) is
counted.

Both output flavours are supported: classic TSV with a `#fields` header, and
JSONL when ``LogAscii::use_json=T`` is set.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.attack import extract_attack
from ..canon.text import redact, truncate
from ..domain.models import Finding, entropy, parse_ts, utcnow
from ..domain.severity import Severity
from .base import Adapter, ParseResult, tool_spec

SEPARATOR = "\t"

# Only notices with an unambiguous ATT&CK mapping are translated here. Anything
# else relies on the notice text carrying an explicit T-ID.
ATTACK_BY_NOTE: dict[str, list[str]] = {
    "Scan::Port_Scan": ["T1046"],
    "Scan::Address_Scan": ["T1018"],
    "SSH::Password_Guessing": ["T1110"],
    "Policy::Credential_Stuffing": ["T1110.004"],
    "HTTP::SQL_Injection_Attacker": ["T1190"],
}

SEVERITY_BY_NOTE: dict[str, Severity] = {
    "Intel::Match": Severity.HIGH,
    "Intel::Seen": Severity.MEDIUM,
    "Scan::Port_Scan": Severity.MEDIUM,
    "Scan::Address_Scan": Severity.LOW,
    "SSH::Password_Guessing": Severity.HIGH,
    "Policy::Credential_Stuffing": Severity.HIGH,
    "HTTP::SQL_Injection_Attacker": Severity.HIGH,
    "SSL::Invalid_Server_Cert": Severity.LOW,
}

DNS_QUERY_MIN_LENGTH = 52
DNS_ENTROPY_MIN = 3.6


class ZeekAdapter(Adapter):
    name = "zeek"
    spec = tool_spec("zeek")

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        root = Path(path)
        files = [root] if root.is_file() else sorted(root.glob("*.log"))
        result = ParseResult()
        totals: dict[str, int] = {}

        for file in files:
            log_name = file.name[:-4] if file.name.endswith(".log") else file.stem
            rows = list(self._rows(file, log_name))
            totals[log_name] = totals.get(log_name, 0) + len(rows)
            for row in rows:
                finding = self._to_finding(log_name, row)
                if finding is not None:
                    result.findings.append(finding)

        result.stats = totals
        if not files:
            result.warnings.append(f"no zeek logs found under {root}")
        return result

    # -- readers ----------------------------------------------------------- #

    def _rows(self, file: Path, log_name: str) -> Iterator[dict[str, Any]]:
        fields: list[str] = []
        with file.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.rstrip("\n")
                if not line:
                    continue
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.split(SEPARATOR)[1:]
                    elif line.startswith("#path"):
                        log_name = line.split(SEPARATOR, 1)[-1].strip() or log_name
                    continue
                if line.startswith("{"):
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict):
                        row["_path"] = log_name
                        yield row
                    continue
                if not fields:
                    continue
                parts = line.split(SEPARATOR)
                if len(parts) < len(fields):
                    parts += [""] * (len(fields) - len(parts))
                row = dict(zip(fields, parts, strict=False))
                row["_path"] = log_name
                yield row

    # -- mapping ----------------------------------------------------------- #

    def _to_finding(self, log_name: str, row: dict[str, Any]) -> Finding | None:
        # A single uploaded log may have any filename; the `#path` header is the
        # authority on which log this is.
        effective = str(row.get("_path") or log_name)
        if effective == "notice":
            return self._notice(row)
        if effective == "weird":
            return self._weird(row)
        if effective == "intel":
            return self._intel(row)
        if effective == "dns":
            return self._dns_heuristic(row)
        return None

    def _notice(self, row: dict[str, Any]) -> Finding:
        note = str(row.get("note") or "Notice")
        message = str(row.get("msg") or note)
        origin = str(row.get("id.orig_h") or row.get("src") or "")
        response = str(row.get("id.resp_h") or row.get("dst") or "")
        timestamp = parse_ts(row.get("ts")) or utcnow()

        return Finding(
            source="zeek",
            category="detection",
            title=message,
            severity=SEVERITY_BY_NOTE.get(note, Severity.MEDIUM),
            asset=asset_for("ip", response or origin),
            rule_id=note,
            rule_name=note,
            locator=f"{note}:{origin}:{response}",
            attack=ATTACK_BY_NOTE.get(note) or extract_attack(message, note),
            tags=["network", "zeek", "notice"],
            evidence=redact(
                {
                    "note": note,
                    "msg": message,
                    "sub": row.get("sub"),
                    "uid": row.get("uid"),
                    "orig_h": origin,
                    "orig_p": row.get("id.orig_p"),
                    "resp_h": response,
                    "resp_p": row.get("id.resp_p"),
                    "proto": row.get("proto"),
                    "actions": row.get("actions"),
                    "peer": row.get("peer_descr"),
                }
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.75,
        )

    def _weird(self, row: dict[str, Any]) -> Finding:
        name = str(row.get("name") or "weird")
        origin = str(row.get("id.orig_h") or "")
        response = str(row.get("id.resp_h") or "")
        timestamp = parse_ts(row.get("ts")) or utcnow()

        return Finding(
            source="zeek",
            category="detection",
            title=f"Zeek weird: {name}",
            severity=Severity.LOW,
            asset=asset_for("ip", response or origin),
            rule_id=f"weird:{name}",
            rule_name=name,
            locator=f"weird:{name}:{origin}:{response}",
            tags=["network", "zeek", "weird"],
            evidence=redact(
                {"name": name, "addl": row.get("addl"), "orig_h": origin, "resp_h": response, "uid": row.get("uid")}
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.45,
        )

    def _intel(self, row: dict[str, Any]) -> Finding:
        indicator = str(row.get("indicator") or "")
        timestamp = parse_ts(row.get("ts")) or utcnow()

        return Finding(
            source="zeek",
            category="detection",
            title=f"Threat intel hit: {indicator}",
            severity=Severity.HIGH,
            asset=asset_for("ip", str(row.get("id.resp_h") or "")),
            rule_id="Intel::Match",
            rule_name="Threat intel match",
            locator=f"intel:{indicator}:{row.get('id.resp_h', '')}",
            tags=["network", "zeek", "intel"],
            evidence=redact(
                {
                    "indicator": indicator,
                    "seen_where": row.get("seen_where"),
                    "sources": row.get("sources"),
                }
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.9,
        )

    def _dns_heuristic(self, row: dict[str, Any]) -> Finding | None:
        """Long, high-entropy DNS labels suggest tunneling. Heuristic, not a rule.

        Confidence is deliberately low: this is a lead for an analyst, not a verdict.
        """
        query = str(row.get("query") or "")
        if len(query) < DNS_QUERY_MIN_LENGTH or "." not in query:
            return None
        label = max(query.split("."), key=len)
        score = entropy(label)
        if score < DNS_ENTROPY_MIN:
            return None

        timestamp = parse_ts(row.get("ts")) or utcnow()
        return Finding(
            source="zeek",
            category="detection",
            title=f"Unusually long DNS query (heuristic): {truncate(query, 60)}",
            severity=Severity.MEDIUM,
            asset=asset_for("ip", str(row.get("id.orig_h") or "")),
            rule_id="heuristic:dns-long-query",
            rule_name="DNS long high-entropy query",
            locator=f"dns:{query}",
            attack=["T1071.004"],
            tags=["network", "zeek", "dns", "heuristic"],
            evidence=redact(
                {
                    "query": query,
                    "qtype": row.get("qtype_name"),
                    "label_length": len(label),
                    "entropy": score,
                    "answers": truncate(row.get("answers"), 200),
                }
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.35,
        )
