from __future__ import annotations

from pathlib import Path

import pytest

from p4b.content import load_yara

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures" / "yara"


@pytest.fixture()
def parsed():
    return load_yara(FIXTURES)


def test_loads_rules(parsed):
    rules, warnings = parsed
    assert len(rules) == 2
    assert warnings == []
    assert {rule.name for rule in rules} == {"Log4j_Exploit_Attempt", "CobaltStrike_Beacon"}


def test_metadata_and_attack(parsed):
    rules, _ = parsed
    by_name = {rule.name: rule for rule in rules}
    log4j = by_name["Log4j_Exploit_Attempt"]
    assert log4j.meta["severity"] == "high"
    assert log4j.attack == ["T1190"]
    assert log4j.severity == "high"

    cobalt = by_name["CobaltStrike_Beacon"]
    assert cobalt.attack == ["T1071.001"]
    assert cobalt.severity == "critical"


def test_to_row_matches_database_shape(parsed):
    rules, _ = parsed
    row = rules[0].to_row()
    assert row["kind"] == "yara"
    assert row["native_id"] == rules[0].name
    assert row["level"] in {"high", "critical"}


def test_body_is_preserved(parsed):
    rules, _ = parsed
    body = rules[0].body
    assert "strings:" in body
    assert "condition:" in body
    assert body.rstrip().endswith("}")
    # the ${jndi:...} string contains a brace; the body must not swallow the next rule
    assert "CobaltStrike" not in body


def test_empty_directory_warns(tmp_path):
    rules, warnings = load_yara(tmp_path)
    assert rules == []
    assert warnings and "no .yar files" in warnings[0]


def test_missing_path_warns(tmp_path):
    rules, warnings = load_yara(tmp_path / "nope")
    assert rules == []
    assert warnings and "does not exist" in warnings[0]


def test_file_without_rules_warns(tmp_path):
    (tmp_path / "empty.yar").write_text("// nothing here\n", encoding="utf-8")
    rules, warnings = load_yara(tmp_path)
    assert rules == []
    assert warnings and "no yara rules" in warnings[0]
