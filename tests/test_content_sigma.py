from __future__ import annotations

from pathlib import Path

import pytest

from p4b.content import load_sigma

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures" / "sigma"


@pytest.fixture()
def parsed():
    return load_sigma(FIXTURES)


def test_loads_every_rule(parsed):
    rules, warnings = parsed
    assert len(rules) == 3
    assert warnings == []


def test_metadata_is_normalized(parsed):
    rules, _ = parsed
    by_id = {rule.native_id: rule for rule in rules}
    lsass = by_id["0f8b1e42-7c3a-4d59-9a2e-1b6c5d4e3f21"]

    assert lsass.title == "LSASS Memory Dump via comsvcs.dll"
    assert lsass.level == "high"
    assert lsass.status == "test"
    assert lsass.attack == ("T1003.001",)
    assert "credential_access" in lsass.tactics
    assert "product=windows" in lsass.logsource_text
    assert "category=process_creation" in lsass.logsource_text
    assert len(lsass.content_hash) == 64


def test_technique_extraction_across_rules(parsed):
    rules, _ = parsed
    techniques = {technique for rule in rules for technique in rule.attack}
    assert techniques == {"T1003.001", "T1059.001", "T1110"}


def test_to_row_matches_database_shape(parsed):
    rules, _ = parsed
    row = rules[0].to_row()
    assert row["kind"] == "sigma"
    assert isinstance(row["attack"], list)
    assert isinstance(row["tags"], list)
    assert row["native_id"]


def test_missing_id_falls_back_to_hash(tmp_path):
    rule = tmp_path / "no-id.yml"
    rule.write_text(
        "title: Rule without id\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image: x.exe\n  condition: selection\n",
        encoding="utf-8",
    )
    rules, _ = load_sigma(rule)
    assert len(rules) == 1
    assert rules[0].native_id.startswith("sigma-")


def test_non_rule_files_are_reported(tmp_path):
    (tmp_path / "readme.yml").write_text("title: not a detection rule\n", encoding="utf-8")
    rules, warnings = load_sigma(tmp_path)
    assert rules == []
    assert warnings and "not a Sigma detection rule" in warnings[0]


def test_missing_path_is_reported(tmp_path):
    rules, warnings = load_sigma(tmp_path / "nope")
    assert rules == []
    assert warnings and "does not exist" in warnings[0]
