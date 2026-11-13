"""Coverage: the three-bit model and its eight states.

A technique is not "covered" because a rule exists. It is covered when there is a
rule, there is a test, and the test was actually detected. Everything else is a
named gap, because a named gap can be worked on.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

VALIDATED = "validated"
UNVALIDATED = "unvalidated"
DETECTED = "detected"
RULE_ONLY = "rule-only"
NO_RULE = "no-rule"
TEST_ONLY = "test-only"
GAP = "gap"

STATUS_DESCRIPTIONS = {
    VALIDATED: "rule + test + observed detection",
    UNVALIDATED: "rule and test exist, but the test was not detected",
    DETECTED: "detection observed, but no test to prove it repeats",
    RULE_ONLY: "rule exists and was never tested",
    NO_RULE: "something was detected, but no rule maps this technique",
    TEST_ONLY: "a test exists, nothing detects it",
    GAP: "no rule, no test, nothing observed",
}


@dataclass
class CoverageRow:
    technique: str
    rules: list[dict[str, Any]] = field(default_factory=list)
    tests: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    findings: int = 0
    max_risk: float = 0.0
    status: str = GAP

    @property
    def has_rule(self) -> bool:
        return bool(self.rules)

    @property
    def has_test(self) -> bool:
        return bool(self.tests)

    @property
    def observed(self) -> bool:
        return bool(self.sources)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "rules": self.rules,
            "tests": self.tests,
            "sources": self.sources,
            "findings": self.findings,
            "max_risk": self.max_risk,
            "has_rule": self.has_rule,
            "has_test": self.has_test,
            "observed": self.observed,
            "status": self.status,
            "description": STATUS_DESCRIPTIONS.get(self.status, ""),
        }


def status_for(has_rule: bool, has_test: bool, observed: bool) -> str:
    """The eight-row truth table from docs/ARCHITECTURE.md §7."""
    if has_rule and has_test:
        return VALIDATED if observed else UNVALIDATED
    if has_rule:
        return DETECTED if observed else RULE_ONLY
    if has_test:
        return TEST_ONLY if not observed else NO_RULE
    return GAP if not observed else NO_RULE


def build_coverage(
    rules: Iterable[dict[str, Any]],
    atomics: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]],
) -> list[CoverageRow]:
    rows: dict[str, CoverageRow] = {}

    def row(technique: str) -> CoverageRow:
        key = technique.upper()
        if key not in rows:
            rows[key] = CoverageRow(technique=key)
        return rows[key]

    for rule in rules:
        for technique in rule.get("attack") or []:
            row(str(technique)).rules.append(
                {
                    "id": rule.get("native_id") or rule.get("id"),
                    "title": rule.get("title"),
                    "level": rule.get("level"),
                    "kind": rule.get("kind", "sigma"),
                }
            )

    for test in atomics:
        technique = str(test.get("technique") or "")
        if not technique:
            continue
        row(technique).tests.append(
            {
                "name": test.get("test_name"),
                "platform": test.get("platform", ""),
                "executor": test.get("executor", ""),
            }
        )

    for finding in findings:
        for technique in finding.get("attack") or []:
            entry = row(str(technique))
            source = str(finding.get("source") or "unknown")
            if source not in entry.sources:
                entry.sources.append(source)
            entry.findings += 1
            entry.max_risk = max(entry.max_risk, float(finding.get("risk") or 0.0))

    result = []
    for entry in rows.values():
        entry.sources.sort()
        entry.max_risk = round(entry.max_risk, 2)
        entry.status = status_for(entry.has_rule, entry.has_test, entry.observed)
        result.append(entry)
    return sorted(result, key=lambda item: (item.status != VALIDATED, item.technique))


def summarize(rows: Iterable[CoverageRow]) -> dict[str, Any]:
    items = list(rows)
    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    validated = counts.get(VALIDATED, 0)
    total = len(items)
    return {
        "techniques": total,
        "by_status": counts,
        "validated": validated,
        "score": round(100.0 * validated / total, 1) if total else 0.0,
        "blind": counts.get(TEST_ONLY, 0) + counts.get(GAP, 0),
        "unvalidated": counts.get(UNVALIDATED, 0),
    }
