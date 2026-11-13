from __future__ import annotations

from pathlib import Path

import pytest

from p4b.adapters.suricata import SuricataAdapter
from p4b.domain.severity import Severity

FIXTURE = Path(__file__).resolve().parents[1] / "demo" / "fixtures" / "suricata" / "eve.json"


@pytest.fixture()
def parsed():
    return SuricataAdapter().parse(FIXTURE)


def test_only_alerts_become_findings(parsed):
    assert len(parsed.findings) == 2
    # non-alert events are counted so the sensor's output is not silently ignored
    assert parsed.stats == {"alert": 2, "http": 1, "flow": 1}


def test_priority_maps_to_severity(parsed):
    severities = sorted((finding.severity for finding in parsed.findings), key=lambda item: item.rank)
    assert severities == [Severity.MEDIUM, Severity.HIGH]


def test_destination_asset_exposure(parsed):
    assert {finding.asset.key for finding in parsed.findings} == {"10.0.4.20"}
    assert all(finding.asset.exposure == "internal" for finding in parsed.findings)


def test_mitre_metadata_is_extracted(parsed):
    techniques = {technique for finding in parsed.findings for technique in finding.attack}
    assert techniques == {"T1110", "T1190"}


def test_flow_id_and_http_context_are_preserved(parsed):
    log4j = next(item for item in parsed.findings if "Log4j" in item.title)
    assert log4j.evidence["flow_id"] == 222
    assert log4j.evidence["http"]["hostname"] == "app.acme.io"
    assert log4j.evidence["http"]["status"] == 403
    assert log4j.rule_id == "sid:2034567"


def test_locator_is_stable_across_runs(parsed):
    again = SuricataAdapter().parse(FIXTURE)
    assert [item.locator for item in parsed.findings] == [item.locator for item in again.findings]


def test_public_source_is_not_marked_internal():
    from p4b.adapters.suricata import exposure_for

    assert exposure_for("203.0.113.9") == "internet"
    assert exposure_for("10.0.4.20") == "internal"
    assert exposure_for("192.168.1.10") == "internal"
