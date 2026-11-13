"""Coverage and validation."""

from .coverage import (
    DETECTED,
    GAP,
    NO_RULE,
    RULE_ONLY,
    STATUS_DESCRIPTIONS,
    TEST_ONLY,
    UNVALIDATED,
    VALIDATED,
    CoverageRow,
    build_coverage,
    status_for,
    summarize,
)
from .executions import match_executions, score

__all__ = [
    "DETECTED",
    "GAP",
    "NO_RULE",
    "RULE_ONLY",
    "STATUS_DESCRIPTIONS",
    "TEST_ONLY",
    "UNVALIDATED",
    "VALIDATED",
    "CoverageRow",
    "build_coverage",
    "match_executions",
    "score",
    "status_for",
    "summarize",
]
