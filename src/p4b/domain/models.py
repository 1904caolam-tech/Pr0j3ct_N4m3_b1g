"""Domain objects.

Plain dataclasses on purpose: no ORM, no framework. They are cheap to construct
in a parser, trivial to compare in tests, and survive a move to another storage
engine without changes.
"""

from __future__ import annotations

import dataclasses
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import risk as risk_model
from .fingerprint import fingerprint as make_fingerprint
from .fingerprint import short_id
from .severity import Severity

ASSET_KINDS = frozenset({"host", "ip", "url", "image", "repo", "filesystem", "cloud", "unknown"})
EXPOSURES = frozenset({"internet", "cloud", "dmz", "internal", "container", "repo"})

_OFFSET_WITHOUT_COLON = re.compile(r"^(.*[+-]\d{2})(\d{2})$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(value: Any) -> datetime | None:
    """Parse the timestamp dialects these tools actually emit.

    Handles ISO-8601 with ``Z``, ``+0000`` (Suricata, Wazuh) and epoch seconds or
    milliseconds (Zeek).
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 1e11:  # milliseconds, not seconds
            number /= 1000.0
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if re.fullmatch(r"\d{10}(\.\d+)?", text):
        return parse_ts(float(text))
    text = text.replace("Z", "+00:00")
    match = _OFFSET_WITHOUT_COLON.match(text)
    if match:
        text = f"{match.group(1)}:{match.group(2)}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def entropy(text: str) -> float:
    """Shannon entropy in bits per character; used by the DNS tunneling heuristic."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 3)


@dataclass(frozen=True)
class Asset:
    """An affected asset. ``key`` is the normalized join key; ``name`` is display."""

    kind: str
    key: str
    name: str = ""
    ip: str = ""
    exposure: str = "internal"

    def __post_init__(self) -> None:
        if self.kind not in ASSET_KINDS:
            object.__setattr__(self, "kind", "unknown")
        if self.exposure not in EXPOSURES:
            object.__setattr__(self, "exposure", "internal")
        if not self.name:
            object.__setattr__(self, "name", self.key)

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclass
class Finding:
    """A normalized detection, independent of the tool that produced it."""

    source: str
    category: str
    title: str
    severity: Severity
    asset: Asset
    rule_id: str = ""
    rule_name: str = ""
    locator: str = ""
    attack: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: dict[str, Any] | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    count: int = 1
    status: str = "open"
    risk: float = 0.0

    # -- identity ---------------------------------------------------------- #

    @property
    def fingerprint(self) -> str:
        return make_fingerprint(
            self.source, self.rule_id, self.title, self.asset.kind, self.asset.key, self.locator
        )

    @property
    def id(self) -> str:
        return short_id(self.fingerprint)

    # -- derived ----------------------------------------------------------- #

    def compute_risk(self) -> float:
        self.risk = risk_model.compute(
            self.severity, self.asset.exposure, self.confidence, self.tags
        )
        return self.risk

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "source": self.source,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "asset": self.asset.to_dict(),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "locator": self.locator,
            "attack": sorted(set(self.attack)),
            "cwe": sorted(set(self.cwe)),
            "cve": sorted(set(self.cve)),
            "tags": sorted(set(self.tags)),
            "references": list(dict.fromkeys(self.references)),
            "remediation": self.remediation,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "risk": self.risk or self.compute_risk(),
            "status": self.status,
            "first_seen": to_iso(self.first_seen),
            "last_seen": to_iso(self.last_seen),
            "count": self.count,
        }
