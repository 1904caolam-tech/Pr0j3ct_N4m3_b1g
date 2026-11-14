"""OCSF projection — Detection Finding (class_uid 2004, v1.3).

OCSF is stricter than ECS and much larger. This is an honest subset: the fields a
downstream consumer needs to triage (class/type, severity, finding_info, resources,
attacks, vulnerabilities) plus everything we cannot map kept under `unmapped.p4b`
rather than dropped.
"""

from __future__ import annotations

from typing import Any

from ..domain.models import parse_ts

CLASS_UID = 2004
CLASS_NAME = "Detection Finding"
CATEGORY_UID = 2
CATEGORY_NAME = "Findings"
ACTIVITY_UID = 1
ACTIVITY_NAME = "Create"
TYPE_UID = CLASS_UID * 100 + ACTIVITY_UID
OCSF_VERSION = "1.3.0"

SEVERITY_ID = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
SEVERITY_NAME = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}

RESOURCE_TYPE = {
    "host": "Host",
    "ip": "IP Address",
    "url": "URL",
    "image": "Container Image",
    "repo": "Repository",
    "filesystem": "File",
    "cloud": "Cloud Resource",
}


def _ms(value: Any) -> int | None:
    parsed = parse_ts(value)
    return int(parsed.timestamp() * 1000) if parsed else None


def to_ocsf(row: dict[str, Any]) -> dict[str, Any]:
    asset = row.get("asset") or {}
    kind = str(asset.get("kind") or "unknown")
    key = str(asset.get("key") or "")
    severity_name = str(row.get("severity") or "unknown").lower()
    severity_id = SEVERITY_ID.get(severity_name, 0)

    resource = {
        "type": RESOURCE_TYPE.get(kind, kind),
        "name": asset.get("name") or key,
        "uid": key,
        "labels": [f"p4b.asset_kind:{kind}"],
    }
    if asset.get("ip"):
        resource["ip"] = asset["ip"]

    document: dict[str, Any] = {
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "activity_id": ACTIVITY_UID,
        "activity_name": ACTIVITY_NAME,
        "type_uid": TYPE_UID,
        "type_name": f"{CLASS_NAME}: {ACTIVITY_NAME}",
        "severity_id": severity_id,
        "severity": SEVERITY_NAME[severity_id],
        "time": _ms(row.get("last_seen")),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "P4B", "vendor_name": "P4B", "feature": {"name": "detection-workbench"}},
            "profiles": ["security_control"],
        },
        "finding_info": {
            "uid": row.get("id"),
            "title": row.get("title"),
            "desc": (row.get("remediation") or {}).get("summary") or "",
            "first_seen_time": _ms(row.get("first_seen")),
            "last_seen_time": _ms(row.get("last_seen")),
            "types": [str(row.get("category") or "unknown")],
            "analytic": {
                "type_id": 1,
                "type": "Rule",
                "uid": row.get("rule_id") or "",
                "name": row.get("rule_name") or row.get("title") or "",
                "category": row.get("source") or "",
            },
        },
        "resources": [resource],
        "status_id": 1,
        "status": str(row.get("status") or "open"),
        "confidence_id": 2 if float(row.get("confidence") or 0) >= 0.7 else 1,
        "confidence_score": int(float(row.get("confidence") or 0) * 100),
        "risk_score": round(float(row.get("risk") or 0.0) * 10, 1),
        "unmapped": {
            "p4b": {
                "fingerprint": row.get("fingerprint"),
                "source": row.get("source"),
                "status": row.get("status"),
                "count": row.get("count"),
                "severity": severity_name,
                "locator": row.get("locator"),
            }
        },
    }

    techniques = [str(item) for item in (row.get("attack") or [])]
    if techniques:
        # Tactic is intentionally absent: P4B stores technique IDs only, and guessing
        # the tactic from a technique would invent data.
        document["attacks"] = [
            {"technique": {"uid": technique, "name": ""}} for technique in techniques
        ]

    cves = [str(item) for item in (row.get("cve") or [])]
    if cves:
        document["vulnerabilities"] = [
            {"cve": {"uid": cve, "type": "CVE"}, "is_fix_available": False} for cve in cves
        ]

    if row.get("locator"):
        document["evidences"] = [{"file": {"path": row["locator"]}, "desc": "matched location"}]

    return document


__all__ = ["CLASS_UID", "OCSF_VERSION", "TYPE_UID", "to_ocsf"]
