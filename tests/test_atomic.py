from __future__ import annotations

import json
from pathlib import Path

import pytest

from p4b.adapters.atomic import AtomicAdapter

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"


@pytest.fixture()
def inventory():
    return AtomicAdapter().parse(FIXTURES / "atomics")


def test_inventory_counts(inventory):
    assert inventory.stats == {"techniques": 5, "tests": 6}
    assert {item["technique"] for item in inventory.rules} == {
        "T1003.001",
        "T1059.001",
        "T1046",
        "T1110",
        "T1136.001",
    }


def test_inventory_fields(inventory):
    lsass = next(item for item in inventory.rules if item["technique"] == "T1003.001")
    assert lsass["test_name"] == "Dump LSASS.exe Memory using comsvcs.dll"
    assert lsass["platform"] == "windows"
    assert lsass["executor"] == "powershell"
    assert lsass["elevation"] is True
    assert "comsvcs" in lsass["command"]


def test_results_parsing():
    parsed = AtomicAdapter().parse(FIXTURES / "atomic-results.json", {"kind": "results"})
    assert parsed.stats == {"executions": 5}
    by_technique = {item["technique"]: item for item in parsed.executions}
    assert set(by_technique) == {"T1003.001", "T1110", "T1059.001", "T1046", "T1136.001"}
    assert by_technique["T1003.001"]["host"] == "WIN-DC01"
    assert by_technique["T1003.001"]["started"] == "2026-11-12T08:05:00Z"
    assert by_technique["T1136.001"]["status"] == "failed"


def test_execution_ids_are_stable():
    first = AtomicAdapter().parse(FIXTURES / "atomic-results.json", {"kind": "results"})
    second = AtomicAdapter().parse(FIXTURES / "atomic-results.json", {"kind": "results"})
    assert [item["id"] for item in first.executions] == [item["id"] for item in second.executions]


def test_flexible_result_keys(tmp_path):
    payload = [
        {
            "attack_technique": "T1046",
            "name": "scan",
            "hostname": "kali",
            "start_time": "2026-11-12T09:00:00Z",
            "execution_success": True,
        }
    ]
    path = tmp_path / "results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = AtomicAdapter().parse(path, {"kind": "results"})
    assert len(parsed.executions) == 1
    execution = parsed.executions[0]
    assert execution["technique"] == "T1046"
    assert execution["test_name"] == "scan"
    assert execution["host"] == "kali"
    assert execution["status"] == "success"


def test_missing_technique_is_reported(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"test_name": "no technique"}]), encoding="utf-8")
    parsed = AtomicAdapter().parse(path, {"kind": "results"})
    assert parsed.executions == []
    assert parsed.warnings and "no technique" in parsed.warnings[0]


def test_empty_inventory_warns(tmp_path):
    parsed = AtomicAdapter().parse(tmp_path)
    assert parsed.rules == []
    assert parsed.warnings and "no atomic test files" in parsed.warnings[0]
