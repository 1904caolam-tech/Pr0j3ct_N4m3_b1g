from __future__ import annotations

import json
from pathlib import Path

import p4b.cli as cli

FIXTURES = Path(__file__).resolve().parents[1] / "demo" / "fixtures"


def _use_tmp_db(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("P4B_DB_URL", f"sqlite:///{(tmp_path / 'p4b.db').as_posix()}")


def test_version(capsys):
    assert cli.main(["version"]) == 0
    assert "p4b 0.1.0" in capsys.readouterr().out


def test_config_json(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("P4B_DB_URL", raising=False)
    assert cli.main(["--json", "config"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["api_port"] == 8080
    assert payload["database_url"].endswith("p4b.db")


def test_init_creates_schema(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    assert cli.main(["init"]) == 0
    output = capsys.readouterr().out
    assert "alembic upgrade head" in output
    assert (tmp_path / "p4b.db").is_file()
    assert (tmp_path / "data" / "rules").is_dir()


def test_doctor_lists_all_tools(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    cli.main(["init"])
    capsys.readouterr()

    assert cli.main(["--json", "doctor"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 10
    assert {row["name"] for row in rows} >= {"nuclei", "wazuh", "sigma", "atomic"}
    assert all("available" in row for row in rows)


def test_ingest_then_list(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    cli.main(["init"])
    capsys.readouterr()

    assert cli.main(["ingest", "wazuh", str(FIXTURES / "wazuh" / "alerts.json")]) == 0
    output = capsys.readouterr().out
    assert "created 2" in output and "stored 2" in output

    # re-ingesting the same file must merge, not duplicate
    assert cli.main(["ingest", "wazuh", str(FIXTURES / "wazuh" / "alerts.json")]) == 0
    assert "created 0" in capsys.readouterr().out

    assert cli.main(["findings", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 2
    assert {row["source"] for row in rows} == {"wazuh"}
    assert max(row["count"] for row in rows) == 2


def test_content_sync_and_list(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    cli.main(["init"])
    capsys.readouterr()

    sigma_dir = FIXTURES / "sigma"
    yara_dir = FIXTURES / "yara"
    assert cli.main(["content", "sync", "--sigma", str(sigma_dir), "--yara", str(yara_dir)]) == 0
    output = capsys.readouterr().out
    assert "3 rule(s)" in output
    assert "2 rule(s)" in output
    assert "splunk" in output

    assert cli.main(["rules", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 5
    assert {row["kind"] for row in rows} == {"sigma", "yara"}


def test_content_translate(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    rule = FIXTURES / "sigma" / "t1003_001_lsass.yml"

    assert cli.main(["--json", "content", "translate", str(rule), "--backend", "kql"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["table"] == "DeviceProcessEvents"
    assert "FolderPath" in payload["query"]


def test_full_validation_flow(monkeypatch, tmp_path, capsys):
    """The M1 acceptance scenario, end to end through the CLI."""
    _use_tmp_db(monkeypatch, tmp_path)
    cli.main(["init"])
    capsys.readouterr()

    for tool, target in (
        ("wazuh", FIXTURES / "wazuh" / "alerts.json"),
        ("suricata", FIXTURES / "suricata" / "eve.json"),
        ("zeek", FIXTURES / "zeek"),
    ):
        assert cli.main(["ingest", tool, str(target)]) == 0
    capsys.readouterr()

    assert (
        cli.main(
            [
                "content",
                "sync",
                "--sigma",
                str(FIXTURES / "sigma"),
                "--yara",
                str(FIXTURES / "yara"),
                "--atomic",
                str(FIXTURES / "atomics"),
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert cli.main(["--json", "validate", "--results", str(FIXTURES / "atomic-results.json")]) == 0
    validation = json.loads(capsys.readouterr().out)
    assert validation["summary"] == {"tests": 5, "detected": 3, "missed": 2, "rate": 60.0}

    assert cli.main(["--json", "coverage"]) == 0
    coverage = json.loads(capsys.readouterr().out)
    summary = coverage["summary"]
    assert summary["techniques"] == 8
    assert summary["validated"] == 2
    assert summary["score"] == 25.0

    by_technique = {row["technique"]: row["status"] for row in coverage["rows"]}
    assert by_technique["T1003.001"] == "validated"
    assert by_technique["T1110"] == "validated"
    assert by_technique["T1059.001"] == "unvalidated"
    assert by_technique["T1046"] == "no-rule"
    assert by_technique["T1136.001"] == "test-only"


def test_demo_runs_the_whole_loop(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    assert cli.main(["--json", "demo", "--reset"]) == 0
    steps = json.loads(capsys.readouterr().out)

    assert steps["validation"]["tests"] == 5
    assert steps["validation"]["detected"] == 3
    assert steps["validation"]["rate"] == 60.0
    assert steps["coverage"]["techniques"] == 8
    assert steps["coverage"]["validated"] == 2
    assert steps["coverage"]["score"] == 25.0
    assert steps["cases"] == 4
    assert steps["aliases"] == 1
    assert steps["tools"] == 2  # sigma + atomic fixtures are present, no binaries
    assert steps["summary"]["total"] == 17
    assert Path(steps["report"]).is_file()

    # a second run is idempotent for findings and cases
    assert cli.main(["--json", "demo"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["summary"]["total"] == 17
    assert second["cases"] == 4
    assert all(info["created"] == 0 for info in second["ingest"].values())


def test_scan_denies_by_default(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    assert (
        cli.main(["--json", "scan", "--tool", "nuclei", "--target", "https://evil.example", "--dry-run"])
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    outcome = payload["outcomes"][0]
    assert outcome["allowed"] is False
    assert "deny-by-default" in outcome["reason"]


def test_scan_allows_an_explicit_scope(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    assert (
        cli.main(
            [
                "--json",
                "scan",
                "--tool",
                "nuclei",
                "--target",
                "https://app.acme.io",
                "--allow",
                "app.acme.io",
                "--dry-run",
            ]
        )
        == 0
    )
    outcome = json.loads(capsys.readouterr().out)["outcomes"][0]
    assert outcome["allowed"] is True
    assert "allowed by rule" in outcome["reason"]


def test_scan_without_binary_reports_skip(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    assert (
        cli.main(
            [
                "--json",
                "scan",
                "--tool",
                "yara",
                "--rules",
                str(FIXTURES / "yara" / "lab_rules.yar"),
                "--target",
                str(FIXTURES / "yara"),
            ]
        )
        == 0
    )
    outcome = json.loads(capsys.readouterr().out)["outcomes"][0]
    assert outcome["allowed"] is True  # yara is not a scoped tool
    assert outcome["skipped"] is True
    assert "binary not found" in outcome["error"]


def test_token_lifecycle(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)

    assert cli.main(["--json", "token", "create", "--name", "ui", "--scopes", "read,write"]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["token"].startswith("p4b_")
    assert created["scopes"] == ["read", "write"]

    assert cli.main(["--json", "token", "list"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    assert "token" not in rows[0]  # only the hash is stored

    assert cli.main(["token", "revoke", created["id"]]) == 0
    capsys.readouterr()
    assert cli.main(["--json", "token", "list"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["revoked_at"] is not None


def test_export_writes_jsonl(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    cli.main(["init"])
    cli.main(["ingest", "wazuh", str(FIXTURES / "wazuh" / "alerts.json")])
    capsys.readouterr()

    target = tmp_path / "exports" / "ocsf.jsonl"
    assert cli.main(["--json", "export", "--format", "ocsf", "--out", str(target)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == 2
    assert target.is_file()

    lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert {line["class_uid"] for line in lines} == {2004}


def test_job_lifecycle(monkeypatch, tmp_path, capsys):
    _use_tmp_db(monkeypatch, tmp_path)
    rules = str(FIXTURES / "yara" / "lab_rules.yar")

    assert (
        cli.main(
            [
                "job",
                "add",
                "--name",
                "nightly",
                "--tool",
                "yara",
                "--target",
                "/lab",
                "--rules",
                rules,
                "--every",
                "30",
            ]
        )
        == 0
    )
    assert "created job_" in capsys.readouterr().out

    assert cli.main(["--json", "job", "list"]) == 0
    jobs = json.loads(capsys.readouterr().out)
    assert len(jobs) == 1
    assert jobs[0]["spec"]["tool"] == "yara"

    assert cli.main(["job", "run", jobs[0]["id"]]) == 0
    run_output = capsys.readouterr().out
    assert "run=run_" in run_output

    # rescheduled, so a worker tick finds nothing due
    assert cli.main(["--json", "worker", "--once"]) == 0
    capsys.readouterr()

    assert cli.main(["job", "disable", jobs[0]["id"]]) == 0
    assert "disabled" in capsys.readouterr().out


def test_unknown_command_exits_2():
    try:
        cli.main([])
    except SystemExit as exc:  # argparse exits for a missing subcommand
        assert exc.code == 2
    else:  # pragma: no cover - argparse always exits here
        raise AssertionError("expected SystemExit")
