"""Purple-team validation: did the test actually get detected?

Matching is deliberately strict — same technique, same host when the detection is
host-based, inside a bounded window. A false "missed" costs an afternoon; a false
"detected" costs credibility, so we bias towards the former.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..domain.models import parse_ts


def match_executions(
    executions: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]],
    window_seconds: int = 900,
) -> list[dict[str, Any]]:
    """Attach detection evidence to each test execution.

    Rules:
      * the finding must carry exactly the same ATT&CK technique;
      * when the finding is about a *host* asset and the execution names a host,
        the hosts must match (IP-based network detections are not host-filtered —
        the machine that ran the test is rarely the machine that got alerted);
      * the finding timestamp must fall inside ``±window_seconds`` of the run.
    """
    finding_list = list(findings)
    results: list[dict[str, Any]] = []

    for execution in executions:
        technique = str(execution.get("technique") or "").upper()
        host = str(execution.get("host") or "").lower()
        started = parse_ts(execution.get("started"))

        matched: list[str] = []
        sources: set[str] = set()
        for finding in finding_list:
            techniques = {str(item).upper() for item in (finding.get("attack") or [])}
            if technique not in techniques:
                continue

            asset = finding.get("asset") or {}
            if host and str(asset.get("kind") or "") == "host":
                if str(asset.get("key") or "").lower() != host:
                    continue

            occurred = parse_ts(finding.get("last_seen") or finding.get("first_seen"))
            if started and occurred and abs((occurred - started).total_seconds()) > window_seconds:
                continue

            matched.append(str(finding.get("id") or ""))
            source = str(finding.get("source") or "")
            if source:
                sources.add(source)

        results.append(
            {
                **execution,
                "detected": bool(matched),
                "matched": matched,
                "sources": sorted(sources),
            }
        )
    return results


def score(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(rows)
    detected = sum(1 for item in items if item.get("detected"))
    total = len(items)
    return {
        "tests": total,
        "detected": detected,
        "missed": total - detected,
        "rate": round(100.0 * detected / total, 1) if total else 0.0,
    }
