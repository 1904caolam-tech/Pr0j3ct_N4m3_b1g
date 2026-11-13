"""Risk scoring.

Deliberately simple and explainable: severity is the base, exposure of the asset
scales it, confidence and exploitation signals nudge it. No black boxes — an
analyst must be able to reconstruct the number by hand.
"""

from __future__ import annotations

from collections.abc import Iterable

from .severity import Severity

BASE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
    Severity.UNKNOWN: 1.0,
}

EXPOSURE: dict[str, float] = {
    "internet": 1.25,
    "cloud": 1.15,
    "dmz": 1.10,
    "internal": 1.00,
    "container": 1.00,
    "repo": 0.90,
}

KEV_TAGS = {"kev", "exploited", "exploit"}


def compute(
    severity: Severity,
    exposure: str = "internal",
    confidence: float = 0.8,
    tags: Iterable[str] = (),
) -> float:
    """Return a 0-10 risk score, rounded to 2 decimals."""
    base = BASE.get(severity, 1.0)
    exposure_multiplier = EXPOSURE.get(exposure, 1.0)
    confidence_multiplier = 0.75 + 0.25 * max(0.0, min(1.0, float(confidence)))
    boost = 1.15 if any(str(t).lower() in KEV_TAGS for t in tags) else 1.0
    return round(min(10.0, base * exposure_multiplier * confidence_multiplier * boost), 2)
