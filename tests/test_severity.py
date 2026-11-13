from __future__ import annotations

import pytest

from p4b.domain.severity import Severity, parse


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        (" High ", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("informational", Severity.INFO),
        ("unknown", Severity.UNKNOWN),
        ("bogus", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
        ("", Severity.UNKNOWN),
    ],
)
def test_text_aliases(value, expected):
    assert parse(value) is expected


@pytest.mark.parametrize(
    ("number", "expected"),
    [(9.8, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM), (0.4, Severity.LOW), (0, Severity.UNKNOWN)],
)
def test_cvss_scale(number, expected):
    assert parse(number) is expected


@pytest.mark.parametrize(
    ("level", "expected"),
    [(15, Severity.CRITICAL), (12, Severity.CRITICAL), (10, Severity.HIGH), (7, Severity.MEDIUM), (4, Severity.LOW), (2, Severity.INFO)],
)
def test_wazuh_scale(level, expected):
    assert parse(level, scale="wazuh") is expected


@pytest.mark.parametrize(("priority", "expected"), [(1, Severity.HIGH), (2, Severity.MEDIUM), (3, Severity.LOW), (4, Severity.UNKNOWN)])
def test_suricata_scale(priority, expected):
    assert parse(priority, scale="suricata") is expected


def test_rank_roundtrip():
    for name in ("unknown", "info", "low", "medium", "high", "critical"):
        severity = Severity(name)
        assert Severity.from_rank(severity.rank) is severity


def test_rank_order_is_monotonic():
    ranks = [Severity(name).rank for name in ("unknown", "info", "low", "medium", "high", "critical")]
    assert ranks == sorted(ranks)
