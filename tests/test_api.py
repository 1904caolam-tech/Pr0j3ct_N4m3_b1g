from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from p4b.api import create_app
from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity


@pytest.fixture()
def client(repos):
    return TestClient(create_app(repos))


def add_finding(repos, title: str = "LSASS dump", technique: str = "T1003.001", severity: Severity = Severity.HIGH):
    finding = Finding(
        source="wazuh",
        category="detection",
        title=title,
        severity=severity,
        asset=Asset("host", "win-dc01"),
        rule_id=f"rule-{title}",
        locator=title,
        attack=[technique],
    )
    return repos.ingest_finding(finding)


def test_root_serves_the_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "P4B" in response.text
    assert "/api/v1" in response.text

    api_root = client.get("/api/v1")
    assert api_root.status_code == 200
    assert api_root.json()["service"] == "p4b"

    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"


def test_openapi_schema_is_served(client):
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    assert "/api/v1/findings" in schema.json()["paths"]


def test_findings_empty(client):
    response = client.get("/api/v1/findings")
    assert response.status_code == 200
    assert response.json() == []


def test_findings_and_filters(repos, client):
    add_finding(repos, title="lsass", technique="T1003.001")
    add_finding(repos, title="cve", technique="T1190", severity=Severity.CRITICAL)

    all_rows = client.get("/api/v1/findings").json()
    assert len(all_rows) == 2

    critical = client.get("/api/v1/findings", params={"severity": "critical"}).json()
    assert len(critical) == 1
    assert critical[0]["title"] == "cve"

    by_attack = client.get("/api/v1/findings", params={"attack": "T1003.001"}).json()
    assert len(by_attack) == 1

    searched = client.get("/api/v1/findings", params={"q": "lsass"}).json()
    assert len(searched) == 1


def test_finding_detail_and_404(repos, client):
    _, finding_id, _ = add_finding(repos)
    detail = client.get(f"/api/v1/findings/{finding_id}")
    assert detail.status_code == 200
    assert detail.json()["asset"]["key"] == "win-dc01"

    missing = client.get("/api/v1/findings/nope")
    assert missing.status_code == 404


def test_validation_bounds(client):
    assert client.get("/api/v1/findings", params={"limit": 0}).status_code == 422
    assert client.get("/api/v1/findings", params={"order": "bogus"}).status_code == 422


def test_coverage_endpoint(repos, client):
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
    repos.sync_atomics([{"technique": "T1003.001", "test_name": "dump", "platform": "windows"}])
    add_finding(repos)

    payload = client.get("/api/v1/coverage").json()
    assert payload["summary"]["techniques"] == 1
    assert payload["summary"]["validated"] == 1
    assert payload["rows"][0]["status"] == "validated"

    filtered = client.get("/api/v1/coverage", params={"status": "gap"}).json()
    assert filtered["rows"] == []


def test_cases_endpoints(repos, client):
    add_finding(repos, title="a")
    _, _, case_id = add_finding(repos, title="b")

    cases = client.get("/api/v1/cases").json()
    assert len(cases) == 1
    assert cases[0]["findings"] == 2

    detail = client.get(f"/api/v1/cases/{case_id}").json()
    assert len(detail["findings"]) == 2
    assert client.get("/api/v1/cases/nope").status_code == 404


def test_rules_and_executions(repos, client):
    repos.sync_rules(
        "yara",
        [
            {
                "native_id": "CobaltStrike_Beacon",
                "title": "beacon",
                "level": "critical",
                "attack": ["T1071.001"],
                "tags": [],
                "path": "",
                "content_hash": "",
            }
        ],
    )
    rules = client.get("/api/v1/rules", params={"kind": "yara"}).json()
    assert len(rules) == 1
    assert rules[0]["attack"] == ["T1071.001"]

    assert client.get("/api/v1/executions").json() == []


def test_export_endpoint(repos, client):
    add_finding(repos)

    response = client.get("/api/v1/export", params={"format": "ocsf"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment" in response.headers["content-disposition"]

    payload = json.loads(response.text.strip())
    assert payload["class_uid"] == 2004
    assert payload["finding_info"]["uid"]

    assert client.get("/api/v1/export", params={"format": "splunk"}).status_code == 422


def test_report_endpoint(repos, client):
    add_finding(repos)
    response = client.get("/api/v1/report.md")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.text.startswith("# P4B report")
