"""One-command demo.

`p4b demo` runs the whole M1 loop on the bundled fixtures: ingest three telemetry
sources, load Sigma/YARA/Atomic content, score the test runs, compute coverage,
group cases and write a report. No binaries, no network, no lab required.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import adapters
from .config import Settings
from .content import load_sigma, load_yara
from .report import build_report
from .store import Repositories, make_engine
from .store.migrate import upgrade
from .validate import build_coverage, match_executions, score, summarize

INGEST_PLAN: tuple[tuple[str, str], ...] = (
    ("wazuh", "fixtures/wazuh/alerts.json"),
    ("suricata", "fixtures/suricata/eve.json"),
    ("zeek", "fixtures/zeek"),
)


def demo_root() -> Path:
    """Where the bundled fixtures live (overridable for a custom scenario)."""
    override = os.environ.get("P4B_DEMO_ROOT")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "demo"


def run_demo(settings: Settings, reset: bool = False, window_seconds: int = 900) -> dict[str, Any]:
    if reset:
        _reset_sqlite(settings)

    settings.ensure_dirs()
    root = demo_root()
    if not root.is_dir():
        raise FileNotFoundError(f"demo fixtures not found: {root}")

    steps: dict[str, Any] = {"root": str(root), "ingest": {}, "content": {}}
    engine = make_engine(settings.database_url())
    try:
        steps["schema"] = upgrade(engine, settings.database_url())
        repos = Repositories(engine)
        repos.ensure_tenant()

        for tool, relative in INGEST_PLAN:
            parsed = adapters.get(tool).parse(root / relative)
            created = 0
            for finding in parsed.findings:
                was_created, _, _case = repos.ingest_finding(finding, settings.case_window_hours)
                created += int(was_created)
            steps["ingest"][tool] = {
                "parsed": len(parsed.findings),
                "created": created,
                "stats": parsed.stats,
            }

        sigma_rules, sigma_warnings = load_sigma(root / "fixtures" / "sigma")
        yara_rules, yara_warnings = load_yara(root / "fixtures" / "yara")
        atomic = adapters.get("atomic").parse(root / "fixtures" / "atomics")
        steps["content"] = {
            "sigma": repos.sync_rules("sigma", [rule.to_row() for rule in sigma_rules]),
            "yara": repos.sync_rules("yara", [rule.to_row() for rule in yara_rules]),
            "atomic": repos.sync_atomics(atomic.rules),
            "warnings": sigma_warnings + yara_warnings + atomic.warnings,
        }

        results = adapters.get("atomic").parse(
            root / "fixtures" / "atomic-results.json", {"kind": "results"}
        )
        repos.save_executions(results.executions)
        findings = repos.list_findings(limit=100_000)
        validated_rows = match_executions(
            repos.list_executions(), findings, window_seconds=window_seconds
        )
        repos.save_executions(validated_rows)
        steps["validation"] = score(validated_rows)
        steps["validation"]["window_seconds"] = window_seconds

        rows = build_coverage(repos.list_rules(limit=100_000), repos.list_atomics(), findings)
        steps["coverage"] = summarize(rows)
        steps["cases"] = repos.count_cases()
        steps["summary"] = repos.summary()
        report_text = build_report(repos)
    finally:
        engine.dispose()

    report_path = Path(settings.reports_dir) / "report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    steps["report"] = str(report_path)
    return steps


def _reset_sqlite(settings: Settings) -> None:
    url = settings.database_url()
    if not url.startswith("sqlite:///"):
        return
    db_path = Path(url.removeprefix("sqlite:///"))
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
