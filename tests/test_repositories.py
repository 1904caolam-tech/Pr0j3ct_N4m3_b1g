from __future__ import annotations

from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity


def make_finding(**overrides) -> Finding:
    values = {
        "source": "wazuh",
        "category": "detection",
        "title": "LSASS memory access",
        "severity": Severity.HIGH,
        "asset": Asset("host", "win-dc01", name="WIN-DC01"),
        "rule_id": "92000",
        "locator": "92000:WIN-DC01",
        "attack": ["T1003.001"],
    }
    values.update(overrides)
    return Finding(**values)


def test_upsert_creates_then_merges(repos):
    created, finding_id = repos.upsert_finding(make_finding())
    assert created is True

    created_again, same_id = repos.upsert_finding(make_finding())
    assert created_again is False
    assert same_id == finding_id
    assert repos.count_findings() == 1

    row = repos.get_finding(finding_id)
    assert row is not None
    assert row["count"] == 2


def test_merge_escalates_severity_and_unions_attack(repos):
    repos.upsert_finding(make_finding(severity=Severity.MEDIUM))
    _, finding_id = repos.upsert_finding(
        make_finding(severity=Severity.CRITICAL, attack=["T1003.001", "T1003.002"])
    )
    row = repos.get_finding(finding_id)
    assert row["severity"] == "critical"
    assert sorted(row["attack"]) == ["T1003.001", "T1003.002"]


def test_asset_is_reused_across_sources(repos):
    repos.upsert_finding(make_finding())
    repos.upsert_finding(
        make_finding(source="suricata", rule_id="sid:1", title="ET POLICY", locator="1.2.3.4:445")
    )
    rows = repos.list_findings()
    assert len(rows) == 2
    assert len({row["asset"]["id"] for row in rows}) == 1


def test_filtering_and_ordering(repos):
    repos.upsert_finding(make_finding())
    repos.upsert_finding(
        make_finding(
            source="trivy",
            category="vuln",
            title="CVE-2021-44228",
            severity=Severity.CRITICAL,
            asset=Asset("image", "acme/api:1.8.2", exposure="container"),
            rule_id="CVE-2021-44228",
            locator="usr/lib/log4j",
            attack=[],
        )
    )

    by_source = repos.list_findings(sources=["trivy"])
    assert [row["source"] for row in by_source] == ["trivy"]

    critical = repos.list_findings(severities=["critical"])
    assert len(critical) == 1

    by_attack = repos.list_findings(attack="T1003.001")
    assert len(by_attack) == 1

    ranked = repos.list_findings(order="risk")
    assert ranked[0]["risk"] >= ranked[-1]["risk"]

    searched = repos.list_findings(query="log4j")
    assert len(searched) == 1


def test_summary(repos):
    repos.upsert_finding(make_finding())
    repos.upsert_finding(
        make_finding(
            source="nuclei",
            category="vuln",
            title="Log4j RCE",
            severity=Severity.CRITICAL,
            asset=Asset("url", "app.acme.io", exposure="internet"),
            rule_id="CVE-2021-44228",
            locator="https://app.acme.io/api",
            attack=["T1190"],
        )
    )

    summary = repos.summary()
    assert summary["total"] == 2
    assert summary["open"] == 2
    assert summary["by_source"] == {"wazuh": 1, "nuclei": 1}
    assert "T1003.001" in summary["techniques"]
    assert summary["max_risk"] >= 5


def test_runs_are_recorded(repos):
    repos.start_run("run_1", "ingest", profile="default")
    repos.finish_run("run_1", status="ok", stats={"findings": 2}, errors=[])
    runs = repos.list_runs()
    assert runs[0]["id"] == "run_1"
    assert runs[0]["status"] == "ok"
    assert runs[0]["stats"] == {"findings": 2}
