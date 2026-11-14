from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from p4b.api import create_app
from p4b.api.auth import hash_token, new_token


@pytest.fixture()
def secured(repos):
    token = new_token()
    repos.create_token("tester", hash_token(token), ("read", "write"))
    return TestClient(create_app(repos, require_auth=True)), token


def test_health_stays_open(secured):
    client, _token = secured
    assert client.get("/api/v1/health").status_code == 200


def test_reads_require_a_token(secured):
    client, _token = secured
    response = client.get("/api/v1/findings")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_valid_token_is_accepted(secured):
    client, token = secured
    response = client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_invalid_token_is_rejected(secured):
    client, _token = secured
    response = client.get("/api/v1/findings", headers={"Authorization": "Bearer p4b_deadbeef"})
    assert response.status_code == 401


def test_revoked_token_is_rejected(repos):
    token = new_token()
    token_id = repos.create_token("ui", hash_token(token), ("read", "write"))
    client = TestClient(create_app(repos, require_auth=True))
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/v1/findings", headers=headers).status_code == 200
    assert repos.revoke_token(token_id) is True
    assert client.get("/api/v1/findings", headers=headers).status_code == 401


def test_read_only_token_cannot_write(repos):
    token = new_token()
    repos.create_token("viewer", hash_token(token), ("read",))
    client = TestClient(create_app(repos, require_auth=True))
    headers = {"Authorization": f"Bearer {token}"}

    response = client.patch("/api/v1/findings/whatever", json={"status": "triaged"}, headers=headers)
    assert response.status_code == 403
    assert "write" in response.json()["detail"]


def test_last_used_is_recorded(repos):
    token = new_token()
    repos.create_token("ui", hash_token(token), ("read",))
    client = TestClient(create_app(repos, require_auth=True))
    client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"})

    rows = repos.list_tokens()
    assert rows[0]["last_used_at"] is not None
