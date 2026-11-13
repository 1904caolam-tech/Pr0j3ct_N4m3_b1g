from __future__ import annotations

from p4b.validate.executions import match_executions, score


def finding(
    ident: str = "fnd_1",
    technique: str = "T1003.001",
    source: str = "wazuh",
    kind: str = "host",
    key: str = "win-dc01",
    seen: str = "2026-11-12T08:05:40Z",
) -> dict:
    return {
        "id": ident,
        "source": source,
        "attack": [technique],
        "asset": {"kind": kind, "key": key},
        "last_seen": seen,
    }


def execution(**overrides) -> dict:
    base = {
        "id": "exe_1",
        "technique": "T1003.001",
        "test_name": "dump lsass",
        "host": "WIN-DC01",
        "started": "2026-11-12T08:05:00Z",
    }
    base.update(overrides)
    return base


def test_match_within_window():
    rows = match_executions([execution()], [finding()], window_seconds=900)
    assert rows[0]["detected"] is True
    assert rows[0]["matched"] == ["fnd_1"]
    assert rows[0]["sources"] == ["wazuh"]


def test_outside_window_is_missed():
    rows = match_executions([execution()], [finding(seen="2026-11-12T10:05:40Z")], window_seconds=900)
    assert rows[0]["detected"] is False
    assert rows[0]["matched"] == []


def test_host_asset_requires_matching_host():
    rows = match_executions([execution(host="WIN-DC02")], [finding()], window_seconds=900)
    assert rows[0]["detected"] is False


def test_ip_asset_is_not_host_filtered():
    rows = match_executions(
        [execution(host="kali-lab", technique="T1046", started="2026-11-12T08:30:05Z")],
        [finding(technique="T1046", source="zeek", kind="ip", key="10.0.4.20", seen="2026-11-12T08:30:12Z")],
        window_seconds=900,
    )
    assert rows[0]["detected"] is True


def test_different_technique_never_matches():
    rows = match_executions(
        [execution(technique="T1110")],
        [finding(technique="T1003.001")],
        window_seconds=900,
    )
    assert rows[0]["detected"] is False


def test_empty_host_disables_host_filter():
    rows = match_executions([execution(host="")], [finding()], window_seconds=900)
    assert rows[0]["detected"] is True


def test_no_findings_means_missed():
    rows = match_executions([execution(), execution(id="exe_2", technique="T1136.001")], [], 900)
    assert [row["detected"] for row in rows] == [False, False]


def test_score():
    rows = [{"detected": True}, {"detected": True}, {"detected": True}, {"detected": False}, {"detected": False}]
    summary = score(rows)
    assert summary == {"tests": 5, "detected": 3, "missed": 2, "rate": 60.0}


def test_score_empty():
    assert score([])["rate"] == 0.0
