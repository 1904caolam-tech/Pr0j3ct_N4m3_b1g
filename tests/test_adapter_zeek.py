from __future__ import annotations

import json
from pathlib import Path

import pytest

from p4b.adapters.zeek import ZeekAdapter

FIXTURE = Path(__file__).resolve().parents[1] / "demo" / "fixtures" / "zeek"


@pytest.fixture()
def parsed():
    return ZeekAdapter().parse(FIXTURE)


def test_every_log_is_counted(parsed):
    assert parsed.stats == {"notice": 2, "conn": 4, "dns": 2}


def test_only_signal_logs_become_findings(parsed):
    # two notices + one DNS heuristic; conn/http stay as counters
    assert len(parsed.findings) == 3


def test_notice_severity_and_technique(parsed):
    notices = {finding.rule_id: finding for finding in parsed.findings if finding.rule_id.startswith(("Scan", "SSH"))}
    assert set(notices) == {"Scan::Port_Scan", "SSH::Password_Guessing"}
    assert notices["Scan::Port_Scan"].severity.value == "medium"
    assert notices["SSH::Password_Guessing"].severity.value == "high"
    assert notices["Scan::Port_Scan"].attack == ["T1046"]
    assert notices["SSH::Password_Guessing"].attack == ["T1110"]
    assert notices["Scan::Port_Scan"].asset.key == "10.0.4.20"


def test_dns_heuristic_is_conservative(parsed):
    dns = [finding for finding in parsed.findings if finding.rule_id == "heuristic:dns-long-query"]
    assert len(dns) == 1
    finding = dns[0]
    assert finding.attack == ["T1071.004"]
    assert finding.confidence < 0.5
    assert finding.tags[-1] == "heuristic"
    assert "aGVsbG8t" in finding.evidence["query"]
    # the short, normal query must not produce a finding
    assert all("app.acme.io" != finding.evidence.get("query") for finding in parsed.findings)


def test_single_file_parsing(parsed):
    result = ZeekAdapter().parse(FIXTURE / "notice.log")
    assert result.stats == {"notice": 2}
    assert len(result.findings) == 2


def test_json_logs_are_supported(tmp_path):
    payload = {
        "ts": 1794472212.5,
        "uid": "Cjson1",
        "id.orig_h": "203.0.113.9",
        "id.resp_h": "10.0.4.20",
        "id.resp_p": 8080,
        "proto": "tcp",
        "note": "Scan::Port_Scan",
        "msg": "scanned 20 ports",
    }
    log = tmp_path / "notice.log"
    log.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    result = ZeekAdapter().parse(log)
    assert len(result.findings) == 1
    assert result.findings[0].attack == ["T1046"]
    assert result.findings[0].first_seen.year == 2026


def test_empty_directory_warns(tmp_path):
    result = ZeekAdapter().parse(tmp_path)
    assert result.findings == []
    assert result.warnings and "no zeek logs" in result.warnings[0]
