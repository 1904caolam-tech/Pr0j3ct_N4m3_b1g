from __future__ import annotations

from p4b.domain.fingerprint import fingerprint
from p4b.domain.models import Asset, Finding
from p4b.domain.risk import compute
from p4b.domain.severity import Severity


def test_fingerprint_is_stable():
    first = fingerprint("wazuh", "92000", "LSASS dump", "host", "win-dc01", "92000:WIN-DC01")
    second = fingerprint("wazuh", "92000", "LSASS dump", "host", "win-dc01", "92000:WIN-DC01")
    assert first == second
    assert len(first) == 64


def test_fingerprint_changes_with_identity():
    base = ("wazuh", "92000", "LSASS dump", "host", "win-dc01", "loc")
    assert fingerprint(*base) != fingerprint("wazuh", "92001", "LSASS dump", "host", "win-dc01", "loc")
    assert fingerprint(*base) != fingerprint("wazuh", "92000", "LSASS dump", "host", "win-dc02", "loc")
    assert fingerprint(*base) != fingerprint("wazuh", "92000", "LSASS dump", "host", "win-dc01", "other")
    assert fingerprint(*base) != fingerprint("suricata", "92000", "LSASS dump", "host", "win-dc01", "loc")


def test_finding_id_derives_from_fingerprint():
    finding = Finding(
        source="wazuh",
        category="detection",
        title="LSASS dump",
        severity=Severity.HIGH,
        asset=Asset("host", "win-dc01"),
        rule_id="92000",
    )
    assert finding.id == "fnd_" + finding.fingerprint[:16]
    assert finding.id == finding.id


def test_risk_orders_by_severity_and_exposure():
    critical_internet = compute(Severity.CRITICAL, "internet", 0.9)
    critical_internal = compute(Severity.CRITICAL, "internal", 0.9)
    low_internal = compute(Severity.LOW, "internal", 0.9)
    assert critical_internet > critical_internal > low_internal
    assert 0 <= low_internal <= 10


def test_risk_is_clamped_and_boosted_by_exploitation_tags():
    plain = compute(Severity.HIGH, "internet", 1.0)
    boosted = compute(Severity.HIGH, "internet", 1.0, ["kev"])
    assert boosted >= plain
    assert compute(Severity.CRITICAL, "internet", 1.0, ["kev"]) <= 10.0
