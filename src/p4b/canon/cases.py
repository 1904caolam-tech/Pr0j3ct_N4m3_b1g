"""Case grouping rules.

A finding is a signal. A case is a unit of work: several signals on the same asset
close in time, so one decision covers them.

The heuristic in v1 is deliberately dumb and explainable (the same asset within a
window). It will over-group occasionally; that is cheaper than an analyst staring at
seventeen unrelated rows.
"""

from __future__ import annotations

from ..domain.severity import Severity

# A single finding on a quiet asset does not deserve its own case; two do.
MIN_FINDINGS_FOR_CASE = 2

PRIORITY_BY_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "low",
    Severity.UNKNOWN: "low",
}


def priority_for(severity: Severity) -> str:
    return PRIORITY_BY_SEVERITY.get(severity, "low")


PRIORITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def higher_priority(current: str, candidate: str) -> str:
    """Never downgrade a case: a later low finding must not lower an open critical."""
    return candidate if PRIORITY_RANK.get(candidate, 0) > PRIORITY_RANK.get(current, 0) else current


def case_title(severity: Severity, asset_key: str) -> str:
    return f"{severity.value.capitalize()} activity on {asset_key}"


def severity_from_rank(rank: int) -> Severity:
    return Severity.from_rank(int(rank or 0))
