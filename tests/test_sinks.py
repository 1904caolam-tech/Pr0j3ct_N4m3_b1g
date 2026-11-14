from __future__ import annotations

import json
from pathlib import Path

from p4b.sinks import documents, render_jsonl, write_jsonl
from p4b.sinks.ecs import SEVERITY_SCORE, to_ecs
from p4b.sinks.ocsf import CLASS_UID, OCSF_VERSION, TYPE_UID, to_ocsf


def row(**overrides) -> dict:
    base = {
        "id": "fnd_abc",
        "fingerprint": "a" * 64,
        "source": "wazuh",
        "category": "detection",
        "title": "LSASS memory access",
        "severity": "high",
        "asset": {"id": "ast_1", "kind": "host", "key": "win-dc01", "name": "WIN-DC01", "ip": "10.0.4.31"},
        "rule_id": "92000",
        "rule_name": "LSASS dump",
        "locator": "92000:WIN-DC01",
        "attack": ["T1003.001"],
        "cwe": ["CWE-522"],
        "cve": [],
        "tags": ["hids"],
        "references": ["https://example.invalid/rule"],
        "remediation": {"summary": "Restrict LSASS access."},
        "confidence": 0.85,
        "risk": 7.2,
        "status": "open",
        "first_seen": "2026-11-12T08:05:40Z",
        "last_seen": "2026-11-12T08:06:00Z",
        "count": 2,
    }
    base.update(overrides)
    return base


def test_ecs_mapping_core_fields():
    document = to_ecs(row())
    assert document["@timestamp"] == "2026-11-12T08:06:00Z"
    assert document["event"]["kind"] == "alert"
    assert document["event"]["category"] == "intrusion_detection"
    assert document["event"]["module"] == "wazuh"
    assert document["event"]["dataset"] == "p4b.wazuh"
    assert document["event"]["severity"] == SEVERITY_SCORE["high"]
    assert document["event"]["risk_score"] == 72.0
    assert document["host"]["name"] == "WIN-DC01"
    assert document["host"]["ip"] == ["10.0.4.31"]
    assert document["threat"]["technique"] == [{"id": "T1003.001"}]
    assert document["rule"]["id"] == "92000"
    assert document["p4b"]["fingerprint"] == "a" * 64


def test_ecs_asset_shapes():
    assert to_ecs(row(asset={"kind": "image", "key": "acme/api:1"}))["container"]["image"]["name"] == "acme/api:1"
    assert to_ecs(row(asset={"kind": "repo", "key": "acme/api"}))["repository"]["name"] == "acme/api"
    assert to_ecs(row(asset={"kind": "url", "key": "app.acme.io", "name": "https://app.acme.io"}))["url"]["domain"] == "app.acme.io"
    assert to_ecs(row(asset={"kind": "ip", "key": "10.0.4.20"}))["host"]["ip"] == ["10.0.4.20"]


def test_ecs_vulnerability_block():
    document = to_ecs(row(category="vuln", cve=["CVE-2021-44228"], severity="critical"))
    assert document["vulnerability"]["id"] == "CVE-2021-44228"
    assert document["event"]["severity"] == 100


def test_ocsf_mapping_core_fields():
    document = to_ocsf(row())
    assert document["class_uid"] == CLASS_UID == 2004
    assert document["type_uid"] == TYPE_UID == 200401
    assert document["metadata"]["version"] == OCSF_VERSION
    assert document["severity_id"] == 4
    assert document["severity"] == "High"
    assert document["finding_info"]["uid"] == "fnd_abc"
    assert document["finding_info"]["title"] == "LSASS memory access"
    assert document["resources"][0]["uid"] == "win-dc01"
    assert document["resources"][0]["type"] == "Host"
    assert document["attacks"][0]["technique"]["uid"] == "T1003.001"
    assert "tactic" not in document["attacks"][0]
    assert document["unmapped"]["p4b"]["source"] == "wazuh"


def test_ocsf_severity_ids():
    assert to_ocsf(row(severity="critical"))["severity_id"] == 5
    assert to_ocsf(row(severity="info"))["severity_id"] == 1
    assert to_ocsf(row(severity="unknown"))["severity_id"] == 0
    assert to_ocsf(row(severity="unknown"))["severity"] == "Unknown"


def test_ocsf_times_are_epoch_milliseconds():
    document = to_ocsf(row())
    assert isinstance(document["time"], int)
    assert document["time"] == 1794470760000
    assert document["finding_info"]["first_seen_time"] == 1794470740000


def test_ocsf_vulnerabilities():
    document = to_ocsf(row(cve=["CVE-2021-44228"]))
    assert document["vulnerabilities"][0]["cve"]["uid"] == "CVE-2021-44228"


def test_documents_dispatch_and_unknown_format():
    ecs = list(documents([row()], "ecs"))
    ocsf = list(documents([row()], "ocsf"))
    assert ecs[0]["event"]["kind"] == "alert"
    assert ocsf[0]["class_uid"] == 2004

    try:
        list(documents([row()], "splunk"))
    except ValueError as exc:
        assert "unknown export format" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_write_jsonl_roundtrip(tmp_path):
    target = tmp_path / "out" / "findings.jsonl"
    count = write_jsonl(target, documents([row(), row(id="fnd_def")], "ecs"))
    assert count == 2

    lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert lines[0]["event"]["kind"] == "alert"
    assert lines[1]["p4b"]["id"] == "fnd_def"


def test_render_jsonl_is_newline_terminated():
    body = render_jsonl(documents([row()], "ocsf"))
    assert body.endswith("\n")
    assert len(body.strip().splitlines()) == 1


def test_export_does_not_mutate_input():
    original = row()
    snapshot = json.dumps(original, sort_keys=True)
    to_ecs(original)
    to_ocsf(original)
    assert json.dumps(original, sort_keys=True) == snapshot


def test_write_jsonl_creates_parent_directories(tmp_path):
    target = Path(tmp_path) / "a" / "b" / "c.jsonl"
    assert write_jsonl(target, []) == 0
    assert target.is_file()
