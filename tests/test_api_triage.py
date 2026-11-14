from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from p4b.api import create_app
from p4b.domain.models import Asset, Finding
from p4b.domain.severity import Severity


@pytest.fixture()
def client(repos):
    return TestClient(create_app(repos))


def add(repos, title: str = "LSASS dump", key: str = "win-dc01", source: str = "wazuh") -> str:
    created, finding_id, _case = repos.ingest_finding(
        Finding(
            source=source,
            category="detection",
            title=title,
            severity=Severity.HIGH,
            asset=Asset("host", key),
            rule_id=f"rule-{title}",
            locator=title,
        )
    )
    assert created
    return finding_id


def test_patch_status_writes_history(repos, client):
    finding_id = add(repos)
    response = client.patch(
        f"/api/v1/findings/{finding_id}", json={"status": "triaged", "assignee": "lam"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "triaged"
    assert response.json()["assignee"] == "lam"

    history = client.get(f"/api/v1/findings/{finding_id}/history").json()
    assert {row["field"] for row in history} == {"status", "assignee"}
    assert {row["actor"] for row in history} == {"anonymous"}
    assert {row["new_value"] for row in history} == {"triaged", "lam"}


def test_repeated_patch_is_not_logged_twice(repos, client):
    finding_id = add(repos)
    client.patch(f"/api/v1/findings/{finding_id}", json={"status": "triaged"})
    client.patch(f"/api/v1/findings/{finding_id}", json={"status": "triaged"})
    assert len(client.get(f"/api/v1/findings/{finding_id}/history").json()) == 1


def test_invalid_status_is_refused(repos, client):
    finding_id = add(repos)
    response = client.patch(f"/api/v1/findings/{finding_id}", json={"status": "done"})
    assert response.status_code == 422


def test_unknown_finding_is_404(client):
    assert client.patch("/api/v1/findings/nope", json={"status": "triaged"}).status_code == 404


def test_case_status_and_membership(repos, client):
    add(repos, title="a")
    _, _, case_id = (
        repos.ingest_finding(
            Finding(
                source="suricata",
                category="detection",
                title="b",
                severity=Severity.HIGH,
                asset=Asset("host", "win-dc01"),
                rule_id="r-b",
                locator="b",
            )
        )
    )
    assert case_id

    patched = client.patch(f"/api/v1/cases/{case_id}", json={"status": "triage", "assignee": "lam"})
    assert patched.status_code == 200
    assert patched.json()["status"] == "triage"

    outsider = add(repos, title="c", key="other-host", source="zeek")
    attached = client.post(f"/api/v1/cases/{case_id}/findings/{outsider}")
    assert attached.status_code == 200
    assert {item["id"] for item in attached.json()["findings"]} >= {outsider}

    detached = client.delete(f"/api/v1/cases/{case_id}/findings/{outsider}")
    assert detached.status_code == 200
    assert all(item["id"] != outsider for item in detached.json()["findings"])


def test_closing_a_case_sets_closed_at(repos, client):
    add(repos, title="a")
    _, _, case_id = repos.ingest_finding(
        Finding(
            source="zeek",
            category="detection",
            title="b",
            severity=Severity.MEDIUM,
            asset=Asset("host", "win-dc01"),
            rule_id="r-b2",
            locator="b2",
        )
    )
    response = client.patch(f"/api/v1/cases/{case_id}", json={"status": "closed"})
    assert response.status_code == 200
    assert response.json()["closed_at"] is not None


def test_invalid_case_status_is_refused(repos, client):
    add(repos, title="a")
    _, _, case_id = repos.ingest_finding(
        Finding(
            source="zeek",
            category="detection",
            title="b",
            severity=Severity.MEDIUM,
            asset=Asset("host", "win-dc01"),
            rule_id="r-b3",
            locator="b3",
        )
    )
    assert client.patch(f"/api/v1/cases/{case_id}", json={"status": "done"}).status_code == 422
