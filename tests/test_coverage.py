from __future__ import annotations

import pytest

from p4b.validate.coverage import (
    DETECTED,
    GAP,
    NO_RULE,
    RULE_ONLY,
    TEST_ONLY,
    UNVALIDATED,
    VALIDATED,
    build_coverage,
    status_for,
    summarize,
)


@pytest.mark.parametrize(
    ("has_rule", "has_test", "observed", "expected"),
    [
        (True, True, True, VALIDATED),
        (True, True, False, UNVALIDATED),
        (True, False, True, DETECTED),
        (True, False, False, RULE_ONLY),
        (False, True, True, NO_RULE),
        (False, True, False, TEST_ONLY),
        (False, False, True, NO_RULE),
        (False, False, False, GAP),
    ],
)
def test_truth_table(has_rule, has_test, observed, expected):
    assert status_for(has_rule, has_test, observed) == expected


def test_build_coverage_merges_three_sources():
    rules = [
        {
            "native_id": "0f8b1e42",
            "title": "LSASS dump",
            "level": "high",
            "kind": "sigma",
            "attack": ["T1003.001"],
        }
    ]
    atomics = [{"technique": "T1003.001", "test_name": "dump lsass", "platform": "windows"}]
    findings = [
        {"id": "f1", "source": "wazuh", "attack": ["T1003.001"], "risk": 9.1},
        {"id": "f2", "source": "zeek", "attack": ["T1003.001"], "risk": 4.2},
    ]

    rows = build_coverage(rules, atomics, findings)
    assert len(rows) == 1
    row = rows[0]
    assert row.status == VALIDATED
    assert row.sources == ["wazuh", "zeek"]
    assert row.findings == 2
    assert row.max_risk == 9.1
    assert row.has_rule and row.has_test and row.observed
    assert row.to_dict()["description"]


def test_build_coverage_covers_union_of_techniques():
    rules = [{"native_id": "r", "title": "t", "level": "high", "kind": "yara", "attack": ["T1190"]}]
    atomics = [{"technique": "T1136.001", "test_name": "create user"}]
    findings = [{"id": "f", "source": "suricata", "attack": ["T1071.004"], "risk": 3.0}]

    rows = {row.technique: row for row in build_coverage(rules, atomics, findings)}
    assert set(rows) == {"T1190", "T1136.001", "T1071.004"}
    assert rows["T1190"].status == RULE_ONLY
    assert rows["T1136.001"].status == TEST_ONLY
    assert rows["T1071.004"].status == NO_RULE


def test_ordering_puts_validated_first():
    rules = [
        {"native_id": "r1", "title": "log4j", "level": "high", "kind": "sigma", "attack": ["T1190"]},
        {"native_id": "r2", "title": "lsass", "level": "high", "kind": "sigma", "attack": ["T1003.001"]},
    ]
    atomics = [{"technique": "T1003.001", "test_name": "dump"}]
    findings = [{"id": "f", "source": "wazuh", "attack": ["T1003.001"], "risk": 9.0}]

    rows = build_coverage(rules, atomics, findings)
    assert rows[0].technique == "T1003.001"
    assert rows[0].status == VALIDATED
    assert rows[1].technique == "T1190"


def test_summarize_score_uses_validated_only():
    rules = [{"native_id": "r", "title": "t", "level": "high", "kind": "sigma", "attack": ["T1003.001"]}]
    atomics = [{"technique": "T1003.001", "test_name": "dump"}]
    findings = [{"id": "f", "source": "wazuh", "attack": ["T1003.001"], "risk": 9.0}]
    rows = build_coverage(rules, atomics, findings)

    summary = summarize(rows)
    assert summary["techniques"] == 1
    assert summary["validated"] == 1
    assert summary["score"] == 100.0
    assert summary["by_status"] == {VALIDATED: 1}


def test_summarize_empty():
    summary = summarize([])
    assert summary["techniques"] == 0
    assert summary["score"] == 0.0
