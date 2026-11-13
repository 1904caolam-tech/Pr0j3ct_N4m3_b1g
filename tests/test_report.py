from __future__ import annotations

from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity
from p4b.report import build_report


def _finding(title: str, technique: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        source="wazuh",
        category="detection",
        title=title,
        severity=severity,
        asset=Asset("host", "win-dc01"),
        rule_id=f"rule-{title}",
        locator=title,
        attack=[technique],
    )


def test_report_contains_every_section(repos):
    repos.ingest_finding(_finding("LSASS dump", "T1003.001"))
    repos.sync_rules(
        "sigma",
        [
            {
                "native_id": "r1",
                "title": "LSASS",
                "level": "high",
                "attack": ["T1003.001"],
                "tags": [],
                "path": "",
                "content_hash": "",
            }
        ],
    )
    repos.sync_atomics([{"technique": "T1003.001", "test_name": "dump lsass", "platform": "windows"}])

    text = build_report(repos)
    assert text.startswith("# P4B report")
    for section in ("## Summary", "## ATT&CK coverage", "## Purple-team validation", "## Top findings by risk"):
        assert section in text
    assert "T1003.001" in text
    assert "validated" in text


def test_report_handles_empty_database(repos):
    text = build_report(repos)
    assert "# P4B report" in text
    assert "| Findings | 0 |" in text
    assert "0.0%" in text or "0%" in text


def test_report_escapes_pipes_in_titles(repos):
    repos.ingest_finding(_finding("pipe | in | title", "T1003.001"))
    text = build_report(repos)
    assert "pipe / in / title" in text
    assert "pipe | in | title" not in text
