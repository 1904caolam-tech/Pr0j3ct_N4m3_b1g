from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from p4b.api import create_app
from p4b.api.auth import hash_token, new_token

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"


@pytest.fixture()
def client(repos):
    return TestClient(create_app(repos))


def test_ingest_wazuh_file(client, repos):
    body = (FIXTURES / "wazuh" / "alerts.json").read_bytes()
    response = client.post(
        "/api/v1/ingest/wazuh", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["tool"] == "wazuh"
    assert payload["parsed"] == 2
    assert payload["created"] == 2
    assert payload["merged"] == 0
    assert repos.count_findings() == 2


def test_ingest_is_idempotent(client, repos):
    body = (FIXTURES / "wazuh" / "alerts.json").read_bytes()
    client.post("/api/v1/ingest/wazuh", content=body)
    second = client.post("/api/v1/ingest/wazuh", content=body).json()

    assert second["parsed"] == 2
    assert second["created"] == 0
    assert second["merged"] == 2
    assert repos.count_findings() == 2


def test_ingest_zeek_log_with_arbitrary_filename(client, repos):
    # The uploaded file is named by the server; the Zeek `#path` header decides
    # which log it is.
    body = (FIXTURES / "zeek" / "notice.log").read_bytes()
    response = client.post("/api/v1/ingest/zeek", content=body)
    assert response.status_code == 200
    payload = response.json()
    assert payload["parsed"] == 2
    assert repos.count_findings() == 2


def test_ingest_suricata_and_nuclei(client):
    suricata = (FIXTURES / "suricata" / "eve.json").read_bytes()
    nuclei = (FIXTURES / "nuclei" / "results.jsonl").read_bytes()

    assert client.post("/api/v1/ingest/suricata", content=suricata).json()["parsed"] == 2
    assert client.post("/api/v1/ingest/nuclei", content=nuclei).json()["parsed"] == 2


def test_min_level_query_is_honoured(client):
    body = (FIXTURES / "wazuh" / "alerts.json").read_bytes()
    payload = client.post("/api/v1/ingest/wazuh?min_level=11", content=body).json()
    assert payload["parsed"] == 1


def test_unknown_tool_is_404(client):
    response = client.post("/api/v1/ingest/pentest", content=b"{}")
    assert response.status_code == 404
    assert "no ingest adapter" in response.json()["detail"]


def test_empty_body_is_400(client):
    assert client.post("/api/v1/ingest/wazuh", content=b"").status_code == 400


def test_oversized_body_is_413(repos):
    app = TestClient(create_app(repos, max_body_mb=1))
    body = b"x" * (1024 * 1024 + 10)
    response = app.post("/api/v1/ingest/wazuh", content=body)
    assert response.status_code == 413
    assert "max_body_mb" in response.json()["detail"]


def test_ingest_requires_write_scope(repos):
    token = new_token()
    repos.create_token("reader", hash_token(token), ("read",))
    client = TestClient(create_app(repos, require_auth=True))

    body = (FIXTURES / "wazuh" / "alerts.json").read_bytes()
    denied = client.post(
        "/api/v1/ingest/wazuh", content=body, headers={"Authorization": f"Bearer {token}"}
    )
    assert denied.status_code == 403

    writer = new_token()
    repos.create_token("writer", hash_token(writer), ("read", "write"))
    allowed = client.post(
        "/api/v1/ingest/wazuh", content=body, headers={"Authorization": f"Bearer {writer}"}
    )
    assert allowed.status_code == 200


def test_ingest_requires_token_when_auth_is_on(repos):
    client = TestClient(create_app(repos, require_auth=True))
    body = (FIXTURES / "wazuh" / "alerts.json").read_bytes()
    assert client.post("/api/v1/ingest/wazuh", content=body).status_code == 401
