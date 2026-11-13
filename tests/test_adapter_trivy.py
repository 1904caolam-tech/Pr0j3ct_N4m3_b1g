from __future__ import annotations

import json
from pathlib import Path

import pytest

from p4b.adapters.trivy import TrivyAdapter, detect_kind
from p4b.domain.severity import Severity

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"


@pytest.fixture()
def parsed():
    return TrivyAdapter().parse(FIXTURES / "trivy" / "image.json")


def test_counts_by_family(parsed):
    assert len(parsed.findings) == 4
    assert parsed.stats == {"vulnerabilities": 2, "misconfigurations": 1, "secrets": 1}


def test_image_asset_is_normalized(parsed):
    assert {item.asset.kind for item in parsed.findings} == {"image"}
    assert {item.asset.key for item in parsed.findings} == {"acme/payments-api:1.8.2"}
    assert {item.asset.exposure for item in parsed.findings} == {"container"}


def test_vulnerability_finding(parsed):
    vuln = next(item for item in parsed.findings if item.rule_id == "CVE-2021-23337")
    assert vuln.category == "vuln"
    assert vuln.severity is Severity.HIGH
    assert vuln.cve == ["CVE-2021-23337"]
    assert "CWE-78" in vuln.cwe
    assert vuln.remediation is not None
    assert "4.17.21" in vuln.remediation["steps"][0]
    assert vuln.evidence["cvss"] == 7.2


def test_misconfiguration_finding(parsed):
    misconfig = next(item for item in parsed.findings if item.category == "misconfig")
    assert misconfig.rule_id == "AVD-DS-0002"
    assert misconfig.severity is Severity.HIGH
    assert misconfig.remediation is not None
    assert "USER" in misconfig.remediation["summary"]


def test_secret_is_redacted(parsed):
    secret = next(item for item in parsed.findings if item.category == "secret")
    assert secret.severity is Severity.CRITICAL
    assert secret.remediation is not None
    assert secret.remediation["cheat_sheet"] == "Secrets_Management_Cheat_Sheet"

    raw = json.dumps(secret.evidence)
    assert "AKIA-EXAMPLE-DO-NOT-USE" not in raw
    assert secret.evidence["match"].startswith("AKIA")
    assert "(23)" in secret.evidence["match"]


def test_build_command_image_vs_fs():
    adapter = TrivyAdapter()
    image = adapter.build_command("acme/payments-api:1.8.2", Path("out.json"), {})
    assert image[1] == "image"
    assert "--format" in image and "json" in image
    assert image[image.index("--scanners") + 1] == "vuln,misconfig,secret"

    filesystem = adapter.build_command("some/dir", Path("out.json"), {"kind": "fs"})
    assert filesystem[1] == "fs"

    with_severity = adapter.build_command("x/y:1", Path("o.json"), {"severity": ["CRITICAL"], "ignore_unfixed": True})
    assert with_severity[with_severity.index("--severity") + 1] == "CRITICAL"
    assert "--ignore-unfixed" in with_severity


def test_detect_kind(tmp_path):
    assert detect_kind("acme/payments-api:1.8.2") == "image"
    assert detect_kind("docker://alpine:3.19") == "image"
    assert detect_kind(str(tmp_path)) == "fs"


def test_stats_when_nothing_found(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"ArtifactName": "x", "Results": []}), encoding="utf-8")
    parsed = TrivyAdapter().parse(path)
    assert parsed.findings == []
    assert parsed.warnings
