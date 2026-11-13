from __future__ import annotations

from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity


def make(
    asset_key: str = "10.0.4.20",
    title: str = "alert",
    severity: Severity = Severity.HIGH,
    source: str = "suricata",
    kind: str = "ip",
) -> Finding:
    return Finding(
        source=source,
        category="detection",
        title=title,
        severity=severity,
        asset=Asset(kind, asset_key),
        rule_id=f"rule-{title}",
        locator=title,
    )


def test_single_finding_opens_no_case(repos):
    repos.ingest_finding(make())
    assert repos.count_cases() == 0


def test_second_finding_on_same_asset_opens_case(repos):
    repos.ingest_finding(make(title="scan"))
    _created, _finding_id, case_id = repos.ingest_finding(make(title="exploit"))

    assert case_id is not None
    cases = repos.list_cases()
    assert len(cases) == 1
    assert cases[0]["findings"] == 2
    assert cases[0]["status"] == "open"


def test_different_assets_do_not_share_a_case(repos):
    repos.ingest_finding(make(asset_key="10.0.4.20", title="a"))
    repos.ingest_finding(make(asset_key="10.0.4.21", title="b"))
    assert repos.count_cases() == 0


def test_later_findings_join_the_open_case(repos):
    repos.ingest_finding(make(title="a"))
    _, _, first_case = repos.ingest_finding(make(title="b"))
    _, _, second_case = repos.ingest_finding(make(title="c"))

    assert first_case == second_case
    assert repos.count_cases() == 1
    assert repos.list_cases()[0]["findings"] == 3


def test_case_priority_follows_worst_severity(repos):
    repos.ingest_finding(make(title="low", severity=Severity.LOW))
    repos.ingest_finding(make(title="crit", severity=Severity.CRITICAL))

    case = repos.list_cases()[0]
    assert case["priority"] == "critical"
    assert case["title"].startswith("Critical activity on")


def test_get_case_includes_findings(repos):
    repos.ingest_finding(make(title="a"))
    _, _, case_id = repos.ingest_finding(make(title="b"))

    case = repos.get_case(case_id or "")
    assert case is not None
    assert len(case["findings"]) == 2
    assert {item["title"] for item in case["findings"]} == {"a", "b"}


def test_reingest_does_not_duplicate_case_membership(repos):
    finding = make(title="a")
    repos.ingest_finding(finding)
    repos.ingest_finding(make(title="b"))
    repos.ingest_finding(finding)

    assert repos.list_cases()[0]["findings"] == 2
