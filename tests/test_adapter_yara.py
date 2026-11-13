from __future__ import annotations

from pathlib import Path

import pytest

from p4b.adapters.yara import YaraAdapter
from p4b.domain.severity import Severity

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"
RULES = FIXTURES / "yara" / "lab_rules.yar"
OUTPUT = FIXTURES / "yara" / "output.txt"


@pytest.fixture()
def parsed():
    return YaraAdapter().parse(OUTPUT, {"rules": str(RULES), "target": "/lab/samples"})


def test_parses_matches_with_metadata(parsed):
    assert len(parsed.findings) == 2
    assert parsed.stats == {"matches": 2, "rules_loaded": 2}


def test_metadata_enriches_the_finding(parsed):
    log4j = next(item for item in parsed.findings if item.rule_id == "Log4j_Exploit_Attempt")
    assert log4j.attack == ["T1190"]
    assert log4j.severity is Severity.HIGH
    assert log4j.category == "detection"
    assert log4j.asset.kind == "filesystem"
    assert log4j.asset.key == "/lab/samples/access.log"
    assert log4j.locator == "Log4j_Exploit_Attempt:/lab/samples/access.log"


def test_malware_tag_changes_category(parsed):
    beacon = next(item for item in parsed.findings if item.rule_id == "CobaltStrike_Beacon")
    assert beacon.category == "malware"
    assert beacon.severity is Severity.CRITICAL
    assert beacon.attack == ["T1071.001"]


def test_without_rule_file_metadata_is_missing(tmp_path):
    parsed = YaraAdapter().parse(OUTPUT, {"target": "/lab"})
    names = {item.rule_id for item in parsed.findings}
    assert names == {"Log4j_Exploit_Attempt", "CobaltStrike_Beacon"}
    assert all(item.title.startswith("YARA match:") for item in parsed.findings)
    # no metadata means no ATT&CK tag either
    assert all(item.attack == [] for item in parsed.findings)


def test_build_command_requires_rules():
    with pytest.raises(ValueError):
        YaraAdapter().build_command("/lab", Path("out.txt"), {})

    command = YaraAdapter().build_command("/lab", Path("out.txt"), {"rules": str(RULES)})
    assert command[0].endswith("yara")
    assert "-r" in command and "-m" in command
    assert command[-2] == str(RULES)


def test_scan_without_rules_is_skipped():
    result = YaraAdapter().scan("/lab", Path("out.txt"), {})
    assert result.skipped is True
    assert "rules" in result.error


def test_scan_is_skipped_without_binary(monkeypatch):
    import p4b.adapters.base as base

    monkeypatch.setattr(base.shutil, "which", lambda _name: None)
    result = YaraAdapter().scan("/lab", Path("out.txt"), {"rules": str(RULES)})
    assert result.skipped is True
    assert "binary not found" in result.error
