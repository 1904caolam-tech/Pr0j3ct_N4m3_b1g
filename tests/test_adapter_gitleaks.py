from __future__ import annotations

import json
from pathlib import Path

import pytest

from p4b.adapters.gitleaks import GitleaksAdapter, severity_for
from p4b.domain.severity import Severity

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"


@pytest.fixture()
def parsed():
    return GitleaksAdapter().parse(
        FIXTURES / "gitleaks" / "leaks.json", {"repo": "acme/payments-api"}
    )


def test_parses_all_leaks(parsed):
    assert len(parsed.findings) == 2
    assert parsed.stats == {"leaks": 2}


def test_severity_heuristic(parsed):
    by_rule = {item.rule_id: item for item in parsed.findings}
    assert by_rule["private-key"].severity is Severity.CRITICAL
    assert by_rule["stripe-access-token"].severity is Severity.HIGH


def test_repo_asset_comes_from_context(parsed):
    assert {item.asset.kind for item in parsed.findings} == {"repo"}
    assert {item.asset.key for item in parsed.findings} == {"acme/payments-api"}


def test_secret_never_reaches_evidence(parsed):
    stripe = next(item for item in parsed.findings if item.rule_id == "stripe-access-token")
    raw = json.dumps(stripe.evidence)
    assert "sk_live_FAKE_NOT_A_KEY" not in raw
    assert stripe.evidence["secret_preview"].startswith("sk_")
    assert "(22)" in stripe.evidence["secret_preview"]


def test_locator_uses_fingerprint(parsed):
    stripe = next(item for item in parsed.findings if item.rule_id == "stripe-access-token")
    assert stripe.locator == "a1b2c3:src/payments/stripe.ts:stripe-access-token:12"


def test_build_command_always_redacts():
    command = GitleaksAdapter().build_command("C:/repo", Path("out.json"), {})
    assert command[1] == "detect"
    assert "--redact" in command
    assert "--exit-code" in command and command[command.index("--exit-code") + 1] == "0"


def test_extended_flags():
    command = GitleaksAdapter().build_command(
        "repo", Path("o.json"), {"config": "gitleaks.toml", "no_git": True}
    )
    assert "--config" in command
    assert "--no-git" in command


def test_severity_helper():
    assert severity_for("aws-access-token", []) is Severity.CRITICAL
    assert severity_for("github-pat", []) is Severity.HIGH
    assert severity_for("generic-api-key", []) is Severity.MEDIUM
