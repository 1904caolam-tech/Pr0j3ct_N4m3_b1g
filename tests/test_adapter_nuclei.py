from __future__ import annotations

import json
from pathlib import Path

import pytest

from p4b.adapters import get, names
from p4b.adapters.nuclei import NucleiAdapter
from p4b.domain.severity import Severity

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"


@pytest.fixture()
def parsed():
    return NucleiAdapter().parse(FIXTURES / "nuclei" / "results.jsonl")


def test_registry_knows_all_adapters():
    assert set(names()) == {
        "atomic",
        "gitleaks",
        "nuclei",
        "suricata",
        "trivy",
        "wazuh",
        "yara",
        "zeek",
    }
    assert get("nuclei").spec.layer == "scanner"


def test_parses_jsonl(parsed):
    assert len(parsed.findings) == 2
    assert parsed.stats == {"templates_matched": 2}


def test_cve_finding(parsed):
    log4j = next(item for item in parsed.findings if "Log4j" in item.title)
    assert log4j.severity is Severity.CRITICAL
    assert log4j.category == "vuln"
    assert log4j.cve == ["CVE-2021-44228"]
    assert "CWE-502" in log4j.cwe
    assert log4j.asset.kind == "url"
    assert log4j.asset.key == "app.acme.io"
    assert log4j.asset.exposure == "internet"
    assert log4j.locator == "https://app.acme.io/api/login"
    assert log4j.remediation is not None
    assert "2.17.1" in log4j.remediation["summary"]


def test_exposure_finding(parsed):
    exposure = next(item for item in parsed.findings if "Git Config" in item.title)
    assert exposure.severity is Severity.MEDIUM
    assert exposure.category == "exposure"
    assert exposure.cve == []


def test_build_command():
    adapter = NucleiAdapter()
    command = adapter.build_command(
        "https://app.acme.io",
        Path("out.jsonl"),
        {"severity": ["critical", "high"], "tags": "cve"},
    )
    assert command[0].endswith("nuclei")
    assert "-jsonl" in command
    assert "-u" in command and "https://app.acme.io" in command
    assert command[command.index("-severity") + 1] == "critical,high"
    assert command[command.index("-tags") + 1] == "cve"


def test_build_command_uses_list_file_for_file_target(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.acme.io\n", encoding="utf-8")
    command = NucleiAdapter().build_command(str(targets), tmp_path / "out.jsonl", {})
    assert "-l" in command


def test_scan_is_skipped_without_binary(monkeypatch):
    import p4b.adapters.base as base

    monkeypatch.setattr(base.shutil, "which", lambda _name: None)
    result = NucleiAdapter().scan("https://app.acme.io", Path("unused.jsonl"), {})
    assert result.skipped is True
    assert "binary not found" in result.error


def test_findings_are_deterministic(parsed):
    again = NucleiAdapter().parse(FIXTURES / "nuclei" / "results.jsonl")
    assert [item.fingerprint for item in parsed.findings] == [item.fingerprint for item in again.findings]


def test_json_array_output_is_also_accepted(tmp_path):
    records = [
        {
            "template-id": "tech-detect",
            "info": {"name": "Nginx detection", "severity": "info", "tags": ["tech"]},
            "host": "https://app.acme.io",
            "matched-at": "https://app.acme.io/",
        }
    ]
    path = tmp_path / "array.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    parsed = NucleiAdapter().parse(path)
    assert len(parsed.findings) == 1
    assert parsed.findings[0].severity is Severity.INFO
