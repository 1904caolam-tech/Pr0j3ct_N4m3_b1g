"""Severity normalization.

Every source speaks its own dialect: text levels, CVSS floats, Wazuh rule levels
(0-15), Suricata priorities (1-3). They all collapse into six values, and
`unknown` is kept distinct instead of being folded into `info`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

RANKS: dict[str, int] = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return RANKS[self.value]

    @classmethod
    def from_rank(cls, rank: int) -> Severity:
        for name, value in RANKS.items():
            if value == rank:
                return cls(name)
        return cls.UNKNOWN


_ALIASES = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "major": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    "negligible": Severity.INFO,
    "trivial": Severity.INFO,
    "unknown": Severity.UNKNOWN,
    "unrated": Severity.UNKNOWN,
}


def parse(value: Any, scale: str = "text") -> Severity:
    """Normalize a severity from any source.

    ``scale`` selects the numeric interpretation when the value is a number:
    ``cvss`` (0-10), ``wazuh`` (0-15), ``suricata`` (1-3 priority).
    """
    if isinstance(value, Severity):
        return value
    if value is None or value == "":
        return Severity.UNKNOWN
    if isinstance(value, bool):
        return Severity.UNKNOWN
    if isinstance(value, (int, float)):
        return _from_number(float(value), scale)

    text = str(value).strip().lower()
    if text in _ALIASES:
        return _ALIASES[text]
    try:
        return _from_number(float(text), "cvss" if scale == "text" else scale)
    except ValueError:
        return Severity.UNKNOWN


def _from_number(number: float, scale: str) -> Severity:
    if scale == "suricata":
        return {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}.get(int(number), Severity.UNKNOWN)
    if scale == "wazuh":
        if number >= 12:
            return Severity.CRITICAL
        if number >= 10:
            return Severity.HIGH
        if number >= 7:
            return Severity.MEDIUM
        if number >= 4:
            return Severity.LOW
        return Severity.INFO
    if number >= 9.0:
        return Severity.CRITICAL
    if number >= 7.0:
        return Severity.HIGH
    if number >= 4.0:
        return Severity.MEDIUM
    if number > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN
