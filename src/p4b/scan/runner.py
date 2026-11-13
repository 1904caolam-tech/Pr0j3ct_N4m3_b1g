"""Scan runner: scope check, execute, capture raw output, persist findings.

The runner is the only place that decides whether a target may be touched. Adapters
never see a target that failed the scope check.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..adapters.base import Adapter
from ..config import Settings
from ..store.repositories import Repositories
from .scope import SCOPED_TOOLS, Scope

SUFFIX = {
    "nuclei": ".jsonl",
    "trivy": ".json",
    "gitleaks": ".json",
    "yara": ".txt",
}
MEDIA_TYPE = {
    "nuclei": "application/x-ndjson",
    "trivy": "application/json",
    "gitleaks": "application/json",
    "yara": "text/plain",
}


@dataclass
class JobOutcome:
    tool: str
    target: str
    allowed: bool
    reason: str = ""
    executed: bool = False
    skipped: bool = False
    findings: int = 0
    created: int = 0
    duration_s: float = 0.0
    raw_sha256: str = ""
    raw_path: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_scan(
    adapter: Adapter,
    target: str,
    *,
    scope: Scope,
    settings: Settings,
    repos: Repositories | None = None,
    run_id: str = "",
    opts: dict[str, Any] | None = None,
    dry_run: bool = False,
) -> JobOutcome:
    opts = dict(opts or {})
    outcome = JobOutcome(tool=adapter.name, target=target, allowed=True)

    if adapter.name in SCOPED_TOOLS:
        decision = scope.check(target)
        if not decision.allowed:
            outcome.allowed = False
            outcome.reason = decision.reason
            return outcome
        outcome.reason = decision.reason

    if dry_run:
        outcome.reason = f"{outcome.reason}; dry-run, not executed".strip("; ")
        return outcome

    run_id = run_id or f"run_{time.strftime('%Y%m%d-%H%M%S')}"
    output = Path(settings.raw_dir) / run_id / f"{adapter.name}{SUFFIX.get(adapter.name, '.out')}"
    started = time.monotonic()
    result = adapter.scan(target, output, {**opts, "timeout": opts.get("timeout", settings.scan_timeout)})
    outcome.duration_s = round(time.monotonic() - started, 2)
    outcome.executed = not result.skipped
    outcome.skipped = result.skipped
    outcome.error = result.error
    outcome.findings = len(result.findings)

    if output.is_file() and output.stat().st_size:
        digest = _sha256(output)
        outcome.raw_sha256 = digest
        outcome.raw_path = str(output)
        if repos is not None:
            repos.save_raw_artifact(
                sha256=digest,
                source=adapter.name,
                media_type=MEDIA_TYPE.get(adapter.name, "application/octet-stream"),
                size=output.stat().st_size,
                storage_ref=str(output),
                run_id=run_id,
            )

    if repos is not None and result.findings:
        for finding in result.findings:
            created, _finding_id, _case_id = repos.ingest_finding(
                finding, settings.case_window_hours
            )
            outcome.created += int(created)
    return outcome


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
