from __future__ import annotations

from datetime import timedelta

import pytest

from p4b.config import Settings
from p4b.domain.models import utcnow
from p4b.jobs import run_due, run_job

FIXTURES = __import__("pathlib").Path(__file__).resolve().parents[1] / "demo" / "fixtures"


@pytest.fixture()
def settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path, raw_dir=tmp_path / "raw")


def spec(**overrides) -> dict:
    base = {
        "tool": "yara",
        "targets": ["/lab"],
        "allow": [],
        "deny": [],
        "opts": {"rules": str(FIXTURES / "yara" / "lab_rules.yar")},
    }
    base.update(overrides)
    return base


def test_add_and_list(repos):
    job_id = repos.add_job("nightly", spec(), every_minutes=30)

    jobs = repos.list_jobs()
    assert len(jobs) == 1
    assert jobs[0]["id"] == job_id
    assert jobs[0]["spec"]["tool"] == "yara"
    assert jobs[0]["spec"]["every_minutes"] == 30
    assert jobs[0]["enabled"] is True
    assert jobs[0]["next_run_at"] is not None


def test_job_is_due_immediately_then_rescheduled(repos):
    job_id = repos.add_job("nightly", spec(), every_minutes=15)
    assert len(repos.due_jobs()) == 1

    repos.mark_job_run(job_id, "run_x", utcnow() + timedelta(minutes=15))
    assert repos.due_jobs() == []

    later = utcnow() + timedelta(minutes=16)
    assert len(repos.due_jobs(now=later)) == 1


def test_not_now_delays_first_run(repos):
    repos.add_job("later", spec(), every_minutes=60, run_now=False)
    assert repos.due_jobs() == []
    assert len(repos.due_jobs(now=utcnow() + timedelta(minutes=61))) == 1


def test_disabled_job_is_not_due(repos):
    job_id = repos.add_job("nightly", spec())
    assert repos.set_job_enabled(job_id, False) is True
    assert repos.due_jobs() == []
    assert repos.set_job_enabled(job_id, True) is True
    assert len(repos.due_jobs()) == 1


def test_run_job_without_binary_records_the_attempt(repos, settings):
    job_id = repos.add_job("nightly", spec(), every_minutes=5)
    result = run_job(repos, settings, repos.get_job(job_id))

    assert result.job_id == job_id
    assert result.findings == 0
    assert any("binary not found" in error for error in result.errors)

    runs = repos.list_runs()
    assert runs[0]["id"] == result.run_id
    assert runs[0]["status"] == "partial"
    assert runs[0]["stats"]["targets"] == 1

    # the schedule moved forward, so the same job is not due again immediately
    assert repos.due_jobs() == []


def test_run_job_with_unknown_tool_fails_cleanly(repos, settings):
    job_id = repos.add_job("broken", spec(tool="nope"), every_minutes=5)
    result = run_job(repos, settings, repos.get_job(job_id))

    assert result.errors
    assert "no adapter" in result.errors[0]
    assert repos.list_runs()[0]["status"] == "failed"
    assert repos.due_jobs() == []


def test_run_due_processes_only_due_jobs(repos, settings):
    repos.add_job("due", spec(), every_minutes=5)
    repos.add_job("later", spec(), every_minutes=60, run_now=False)

    results = run_due(repos, settings)
    assert [result.name for result in results] == ["due"]
    assert repos.due_jobs() == []


def test_scope_denial_is_an_error_not_a_crash(repos, settings):
    job_spec = spec(tool="nuclei", targets=["https://evil.example"], allow=["app.acme.io"])
    job_id = repos.add_job("scoped", job_spec, every_minutes=5)

    result = run_job(repos, settings, repos.get_job(job_id))
    assert any("not in the allow list" in error for error in result.errors)
    assert result.findings == 0
