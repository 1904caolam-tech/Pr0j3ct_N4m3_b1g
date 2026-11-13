from __future__ import annotations

from pathlib import Path

import pytest

from p4b.adapters import get
from p4b.adapters.wazuh import WazuhAdapter
from p4b.domain.severity import Severity

FIXTURE = Path(__file__).resolve().parents[1] / "demo" / "fixtures" / "wazuh" / "alerts.json"


@pytest.fixture()
def parsed():
    return WazuhAdapter().parse(FIXTURE)


def test_threshold_filters_low_level_alerts(parsed):
    assert len(parsed.findings) == 2
    assert parsed.stats == {"alerts": 2, "below_threshold": 1}
    assert parsed.warnings and "below rule.level 7" in parsed.warnings[0]


def test_min_level_is_configurable():
    parsed = WazuhAdapter().parse(FIXTURE, {"min_level": 11})
    assert len(parsed.findings) == 1
    assert parsed.findings[0].rule_id == "92000"


def test_level_maps_to_severity(parsed):
    by_rule = {finding.rule_id: finding for finding in parsed.findings}
    assert by_rule["92000"].severity is Severity.CRITICAL
    assert by_rule["5710"].severity is Severity.HIGH


def test_mitre_techniques_are_extracted(parsed):
    techniques = {technique for finding in parsed.findings for technique in finding.attack}
    assert techniques == {"T1003.001", "T1110"}


def test_host_asset_keeps_ip(parsed):
    finding = next(item for item in parsed.findings if item.rule_id == "92000")
    assert finding.asset.kind == "host"
    assert finding.asset.key == "win-dc01"
    assert finding.asset.ip == "10.0.4.31"
    assert finding.asset.exposure == "internal"


def test_findings_are_deterministic(parsed):
    again = WazuhAdapter().parse(FIXTURE)
    assert [item.fingerprint for item in parsed.findings] == [item.fingerprint for item in again.findings]
    assert [item.id for item in parsed.findings] == [item.id for item in again.findings]


def test_registry_exposes_the_adapter():
    adapter = get("wazuh")
    assert adapter.name == "wazuh"
    assert adapter.spec.layer == "telemetry"
