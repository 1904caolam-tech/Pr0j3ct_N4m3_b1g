"""Scheduled scans.

A job is a stored scan specification plus a schedule. The worker reads due jobs,
runs each target through the same scope-enforced runner the CLI uses, records a
`runs` row, and pushes `next_run_at` forward. No cron daemon, no broker: the schedule
lives in the database, so `p4b worker --once` is testable and CI-friendly.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from . import adapters
from .config import Settings
from .domain.models import utcnow
from .scan import Scope, run_scan
from .store.repositories import Repositories


@dataclass
class JobResult:
    job_id: str
    name: str
    run_id: str
    findings: int = 0
    created: int = 0
    targets: int = 0
    errors: list[str] = field(default_factory=list)
    outcomes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_job(repos: Repositories, settings: Settings, job: dict[str, Any]) -> JobResult:
    spec = job.get("spec") or {}
    tool = str(spec.get("tool") or "")
    targets = [str(target) for target in (spec.get("targets") or [])]
    scope = Scope(allow=tuple(spec.get("allow") or ()), deny=tuple(spec.get("deny") or ()))

    run_id = f"run_{time.strftime('%Y%m%d-%H%M%S')}_{str(job.get('id'))[-4:]}"
    result = JobResult(
        job_id=str(job.get("id") or ""),
        name=str(job.get("name") or ""),
        run_id=run_id,
        targets=len(targets),
    )

    repos.start_run(run_id, "scan", profile=f"job:{result.name}")
    try:
        adapter = adapters.get(tool)
    except KeyError as exc:
        result.errors.append(str(exc))
        repos.finish_run(run_id, status="failed", stats={"targets": 0}, errors=result.errors)
        _schedule_next(repos, job, spec, run_id)
        return result

    opts = dict(spec.get("opts") or {})
    for target in targets:
        outcome = run_scan(
            adapter,
            target,
            scope=scope,
            settings=settings,
            repos=repos,
            run_id=run_id,
            opts=opts,
        )
        result.outcomes.append(outcome.to_dict())
        result.findings += outcome.findings
        result.created += outcome.created
        if not outcome.allowed:
            result.errors.append(f"{target}: {outcome.reason}")
        elif outcome.error:
            result.errors.append(f"{target}: {outcome.error}")

    repos.finish_run(
        run_id,
        status="ok" if not result.errors else "partial",
        stats={"targets": result.targets, "findings": result.findings, "created": result.created},
        errors=result.errors,
    )
    _schedule_next(repos, job, spec, run_id)
    return result


def run_due(
    repos: Repositories, settings: Settings, *, limit: int = 10, now=None
) -> list[JobResult]:
    return [run_job(repos, settings, job) for job in repos.due_jobs(now=now, limit=limit)]


def _schedule_next(
    repos: Repositories, job: dict[str, Any], spec: dict[str, Any], run_id: str
) -> None:
    minutes = max(1, int(spec.get("every_minutes") or 60))
    repos.mark_job_run(str(job["id"]), run_id, utcnow() + timedelta(minutes=minutes))


__all__ = ["JobResult", "run_due", "run_job"]
