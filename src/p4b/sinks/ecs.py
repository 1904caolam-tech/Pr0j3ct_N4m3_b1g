"""ECS-lite projection.

Elastic Common Schema, reduced to the fields a SIEM actually queries. `event.severity`
and `event.risk_score` are 0-100 in ECS, while P4B stores a 0-5 rank and a 0-10 risk,
so both are scaled here rather than leaking two conventions into the same index.
"""

from __future__ import annotations

from typing import Any

from ..domain.models import parse_ts

CATEGORY = {
    "vuln": "vulnerability",
    "misconfig": "configuration",
    "secret": "configuration",
    "malware": "malware",
    "exposure": "network",
    "detection": "intrusion_detection",
    "network": "network",
    "identity": "authentication",
    "supply-chain": "package",
    "policy": "configuration",
}

SEVERITY_SCORE = {"unknown": 0, "info": 20, "low": 40, "medium": 60, "high": 80, "critical": 100}


def _ms(value: Any) -> int | None:
    parsed = parse_ts(value)
    return int(parsed.timestamp() * 1000) if parsed else None


def to_ecs(row: dict[str, Any]) -> dict[str, Any]:
    asset = row.get("asset") or {}
    kind = str(asset.get("kind") or "")
    key = str(asset.get("key") or "")
    severity = str(row.get("severity") or "unknown").lower()

    document: dict[str, Any] = {
        "@timestamp": row.get("last_seen"),
        "event": {
            "kind": "alert",
            "category": CATEGORY.get(str(row.get("category")), "configuration"),
            "module": row.get("source"),
            "dataset": f"p4b.{row.get('source')}",
            "severity": SEVERITY_SCORE.get(severity, 0),
            "risk_score": round(float(row.get("risk") or 0.0) * 10, 1),
            "id": row.get("id"),
        },
        "rule": {
            "id": row.get("rule_id") or "",
            "name": row.get("rule_name") or row.get("title") or "",
            "category": row.get("category") or "",
        },
        "observer": {"product": "p4b", "vendor": "p4b", "type": "detection-engine"},
        "message": row.get("title"),
        "tags": list(row.get("tags") or []),
        "p4b": {
            "id": row.get("id"),
            "fingerprint": row.get("fingerprint"),
            "status": row.get("status"),
            "count": row.get("count"),
            "confidence": row.get("confidence"),
            "severity": severity,
            "asset_kind": kind,
            "asset_key": key,
        },
    }

    if kind == "host":
        document["host"] = {"name": asset.get("name") or key, "ip": [asset["ip"]] if asset.get("ip") else []}
    elif kind == "ip":
        document["host"] = {"ip": [key]}
    elif kind == "url":
        document["url"] = {"full": asset.get("name") or key, "domain": key}
    elif kind == "image":
        document["container"] = {"image": {"name": key}}
    elif kind == "repo":
        document["repository"] = {"name": key}
    elif kind in {"filesystem", "cloud"}:
        document["file"] = {"path": key}

    techniques = [str(item) for item in (row.get("attack") or [])]
    if techniques:
        document["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": [{"id": technique} for technique in techniques],
        }

    cves = [str(item) for item in (row.get("cve") or [])]
    if cves:
        document["vulnerability"] = {
            "id": cves[0],
            "description": row.get("title"),
            "severity": severity,
            "reference": list(row.get("references") or [])[:10],
            "classification": [{"cwe_id": cwe} for cwe in (row.get("cwe") or [])],
        }

    if row.get("locator"):
        document.setdefault("file", {}).setdefault("path", row["locator"])

    return document


__all__ = ["SEVERITY_SCORE", "to_ecs"]
