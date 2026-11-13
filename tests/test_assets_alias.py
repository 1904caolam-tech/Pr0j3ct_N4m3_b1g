from __future__ import annotations

from p4b.canon.assets import asset_for
from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity


def test_alias_makes_two_tools_describe_one_asset(repos):
    repo_asset_id = repos.get_or_create_asset(asset_for("repo", "acme/payments-api"))
    assert repos.add_alias(repo_asset_id, "image", "acme/payments-api:1.8.2", source="test")

    finding = Finding(
        source="trivy",
        category="secret",
        title="AWS key in image",
        severity=Severity.CRITICAL,
        asset=Asset("image", "acme/payments-api:1.8.2", exposure="container"),
        rule_id="aws-access-key-id",
        locator="app/prod.env:4",
    )
    repos.ingest_finding(finding)

    row = repos.list_findings()[0]
    assert row["asset"]["id"] == repo_asset_id
    assert row["asset"]["kind"] == "repo"
    assert row["asset"]["key"] == "acme/payments-api"


def test_alias_is_idempotent(repos):
    asset_id = repos.get_or_create_asset(asset_for("repo", "acme/api"))
    assert repos.add_alias(asset_id, "image", "acme/api:1") is True
    assert repos.add_alias(asset_id, "image", "acme/api:1") is True


def test_alias_cannot_be_stolen_by_another_asset(repos):
    first = repos.get_or_create_asset(asset_for("repo", "acme/api"))
    second = repos.get_or_create_asset(asset_for("repo", "acme/other"))
    assert repos.add_alias(first, "image", "acme/api:1") is True
    assert repos.add_alias(second, "image", "acme/api:1") is False


def test_alias_makes_case_membership_span_tools(repos):
    repo_asset_id = repos.get_or_create_asset(asset_for("repo", "acme/api"))
    repos.add_alias(repo_asset_id, "image", "acme/api:1")

    repos.ingest_finding(
        Finding(
            source="gitleaks",
            category="secret",
            title="stripe key",
            severity=Severity.HIGH,
            asset=Asset("repo", "acme/api", exposure="repo"),
            rule_id="stripe",
            locator="a:1",
        )
    )
    _, _, case_id = repos.ingest_finding(
        Finding(
            source="trivy",
            category="vuln",
            title="CVE in image",
            severity=Severity.CRITICAL,
            asset=Asset("image", "acme/api:1", exposure="container"),
            rule_id="CVE-2024-0001",
            locator="b:2",
        )
    )

    assert case_id is not None
    cases = repos.list_cases()
    assert len(cases) == 1
    assert cases[0]["findings"] == 2
    assert {item["source"] for item in repos.get_case(case_id)["findings"]} == {"gitleaks", "trivy"}
