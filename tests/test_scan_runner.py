from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from p4b.adapters.base import Adapter, ParseResult, ScanResult, tool_spec
from p4b.config import Settings
from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity
from p4b.scan import Scope, run_scan


class StubAdapter(Adapter):
    """Adapter that pretends to scan: writes a small artifact and returns findings."""

    name = "nuclei"  # scoped tool, so the runner must check the scope
    spec = tool_spec("nuclei")

    def __init__(self, *, skipped: bool = False):
        self.skipped = skipped

    def parse(self, path: Path, ctx=None) -> ParseResult:
        return ParseResult()

    def scan(self, target: str, output_path: Path, opts=None) -> ScanResult:
        if self.skipped:
            return ScanResult(tool=self.name, skipped=True, error="binary not found: nuclei")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text('{"template-id":"x"}\n', encoding="utf-8")
        result = ScanResult(tool=self.name, ok=True, output_path=str(output_path))
        result.parse.findings = [
            Finding(
                source="nuclei",
                category="vuln",
                title=f"finding for {target}",
                severity=Severity.HIGH,
                asset=Asset("url", "app.acme.io"),
                rule_id="x",
                locator=target,
            )
        ]
        return result


@pytest.fixture()
def settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path, raw_dir=tmp_path / "raw")


def test_denied_target_is_never_executed(repos, settings):
    outcome = run_scan(
        StubAdapter(),
        "https://evil.example",
        scope=Scope(allow=("app.acme.io",)),
        settings=settings,
        repos=repos,
        run_id="run_test",
    )
    assert outcome.allowed is False
    assert outcome.executed is False
    assert "not in the allow list" in outcome.reason
    assert repos.count_findings() == 0
    assert not (settings.raw_dir).exists()


def test_allowed_target_runs_and_persists(repos, settings):
    outcome = run_scan(
        StubAdapter(),
        "https://app.acme.io",
        scope=Scope(allow=("app.acme.io",)),
        settings=settings,
        repos=repos,
        run_id="run_test",
    )
    assert outcome.allowed is True
    assert outcome.executed is True
    assert outcome.findings == 1
    assert outcome.created == 1
    assert repos.count_findings() == 1
    assert repos.count_raw_artifacts() == 1

    raw = Path(outcome.raw_path)
    assert raw.is_file()
    assert outcome.raw_sha256 == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert raw.parent.name == "run_test"


def test_dry_run_writes_nothing(repos, settings):
    outcome = run_scan(
        StubAdapter(),
        "https://app.acme.io",
        scope=Scope(allow=("app.acme.io",)),
        settings=settings,
        repos=repos,
        dry_run=True,
    )
    assert outcome.allowed is True
    assert outcome.executed is False
    assert "dry-run" in outcome.reason
    assert repos.count_findings() == 0
    assert repos.count_raw_artifacts() == 0


def test_missing_binary_is_reported_not_raised(repos, settings):
    outcome = run_scan(
        StubAdapter(skipped=True),
        "https://app.acme.io",
        scope=Scope(allow=("app.acme.io",)),
        settings=settings,
        repos=repos,
    )
    assert outcome.skipped is True
    assert outcome.executed is False
    assert "binary not found" in outcome.error
    assert repos.count_findings() == 0


def test_repeated_scan_deduplicates_findings(repos, settings):
    scope = Scope(allow=("app.acme.io",))
    first = run_scan(StubAdapter(), "https://app.acme.io", scope=scope, settings=settings, repos=repos)
    second = run_scan(StubAdapter(), "https://app.acme.io", scope=scope, settings=settings, repos=repos)

    assert first.created == 1
    assert second.created == 0  # same fingerprint, merged instead
    assert repos.count_findings() == 1
