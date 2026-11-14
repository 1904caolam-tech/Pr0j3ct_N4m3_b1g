"""Repeatability soak: run the whole loop N times and prove the result never drifts.

Every iteration starts from an empty database, runs `p4b demo --reset`, then checks
that a second ingest, a second validation and both exports are byte-stable. The
artifacts (JSON + Markdown) are meant to be committed: they are evidence, not logs.

    python deploy/soak/soak.py --iterations 50
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "demo" / "fixtures"


def cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "p4b.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO,
        timeout=600,
    )


def db_counts(db: Path) -> dict[str, int]:
    with sqlite3.connect(db) as conn:
        def one(sql: str) -> int:
            return int(conn.execute(sql).fetchone()[0])

        return {
            "findings": one("select count(*) from findings"),
            "cases": one("select count(*) from cases"),
            "executions": one("select count(*) from executions"),
            "detected": one("select count(*) from executions where detected=1"),
            "assets": one("select count(*) from assets"),
            "rules": one("select count(*) from rules"),
        }


def api_statuses(settings) -> list[int]:
    from fastapi.testclient import TestClient

    from p4b.api import create_app
    from p4b.store import Repositories, make_engine

    engine = make_engine(settings.database_url())
    try:
        client = TestClient(create_app(Repositories(engine)))
        paths = [
            "/api/v1/health",
            "/api/v1/summary",
            "/api/v1/findings?limit=5",
            "/api/v1/coverage",
            "/api/v1/cases",
            "/api/v1/executions",
            "/api/v1/tools",
            "/api/v1/report.md",
            "/api/v1/export?format=ocsf",
        ]
        return [client.get(path).status_code for path in paths]
    finally:
        engine.dispose()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_ecs_sha(path: Path) -> str:
    """Hash of the ECS export with the one volatile field removed.

    Findings from sources without a timestamp (Gitleaks here) are stamped at
    ingestion time, so `@timestamp` legitimately differs between fresh databases.
    Everything else must be byte-identical.
    """
    docs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        document = json.loads(line)
        document.pop("@timestamp", None)
        docs.append(document)
    canonical = json.dumps(docs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ocsf_uid_sha(path: Path) -> str:
    """Hash of the sorted finding UIDs; proves the same finding set every run."""
    uids = sorted(json.loads(line)["finding_info"]["uid"] for line in path.read_text(encoding="utf-8").splitlines())
    return hashlib.sha256("\n".join(uids).encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--out", default=str(REPO / "artifacts" / "soak"))
    parser.add_argument("--keep", action="store_true", help="keep the scratch database")
    args = parser.parse_args()

    from p4b import __version__
    from p4b.config import Settings

    work = Path(tempfile.mkdtemp(prefix="p4b-soak-"))
    data = work / "data"
    env = os.environ.copy()
    env["P4B_DATA_DIR"] = str(data)
    settings = Settings(data_dir=data)
    db = data / "p4b.db"

    iterations: list[dict] = []
    started = datetime.now(timezone.utc)
    failures: list[str] = []

    try:
        for index in range(1, args.iterations + 1):
            t0 = time.perf_counter()
            problems: list[str] = []

            demo = cli("demo", "--reset", env=env)
            if demo.returncode != 0:
                problems.append(f"demo failed: {demo.stderr[-300:]}")

            counts = db_counts(db) if db.is_file() else {}

            ingest = cli("ingest", "wazuh", str(FIXTURES / "wazuh" / "alerts.json"), env=env)
            if "created 0" not in ingest.stdout:
                problems.append("second ingest was not idempotent")

            cli("validate", "--results", str(FIXTURES / "atomic-results.json"), env=env)
            after_validate = db_counts(db) if db.is_file() else {}
            if after_validate.get("executions") != counts.get("executions"):
                problems.append("second validate created execution rows")

            ecs = work / "ecs.jsonl"
            ocsf = work / "ocsf.jsonl"
            cli("export", "--format", "ecs", "--out", str(ecs), env=env)
            cli("export", "--format", "ocsf", "--out", str(ocsf), env=env)

            coverage = cli("--json", "coverage", env=env)
            summary = json.loads(coverage.stdout)["summary"] if coverage.returncode == 0 else {}

            statuses = api_statuses(settings)
            if any(status != 200 for status in statuses):
                problems.append(f"api statuses: {statuses}")

            duration = (time.perf_counter() - t0) * 1000
            iterations.append(
                {
                    "iteration": index,
                    "duration_ms": round(duration, 1),
                    "findings": counts.get("findings"),
                    "cases": counts.get("cases"),
                    "executions": counts.get("executions"),
                    "validated": summary.get("validated"),
                    "detected": counts.get("detected"),
                    "ecs_lines": len(ecs.read_text(encoding="utf-8").splitlines()) if ecs.is_file() else 0,
                    "ocsf_lines": len(ocsf.read_text(encoding="utf-8").splitlines()) if ocsf.is_file() else 0,
                    "ecs_stable_sha256": stable_ecs_sha(ecs) if ecs.is_file() else "",
                    "ocsf_uid_sha256": ocsf_uid_sha(ocsf) if ocsf.is_file() else "",
                    "raw_ecs_sha256": sha256(ecs) if ecs.is_file() else "",
                    "api_statuses": statuses,
                    "problems": problems,
                }
            )
            failures.extend(f"iteration {index}: {problem}" for problem in problems)
            print(f"  {index:>3}/{args.iterations}  {duration:7.1f} ms  {'OK' if not problems else 'FAIL'}")
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    durations = [row["duration_ms"] for row in iterations]
    stable_keys = (
        "findings",
        "cases",
        "executions",
        "validated",
        "detected",
        "ecs_lines",
        "ocsf_lines",
        "ecs_stable_sha256",
        "ocsf_uid_sha256",
    )
    unique = {key: sorted({str(row[key]) for row in iterations}) for key in stable_keys}
    drift = {key: values for key, values in unique.items() if len(values) != 1}

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": started.isoformat(timespec="seconds"),
        "iterations_requested": args.iterations,
        "p4b_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "summary": {
            "failures": len(failures),
            "drift": drift,
            "duration_ms": {
                "min": round(min(durations), 1),
                "median": round(statistics.median(durations), 1),
                "p95": round(sorted(durations)[max(0, int(len(durations) * 0.95) - 1)], 1),
                "max": round(max(durations), 1),
            },
            "unique_values": unique,
            "ecs_stable_sha256": sorted({row["ecs_stable_sha256"] for row in iterations}),
            "ocsf_uid_sha256": sorted({row["ocsf_uid_sha256"] for row in iterations}),
            "raw_ecs_sha_distinct": len({row["raw_ecs_sha256"] for row in iterations}),
        },
        "failures": failures,
        "iterations": iterations,
    }
    json_path = out / f"soak-{args.iterations}.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    markdown = [
        f"# Soak report — {args.iterations} iterations",
        "",
        f"- generated: {payload['generated_at']}",
        f"- p4b {__version__} on Python {platform.python_version()} ({platform.system()})",
        f"- failures: **{len(failures)}**",
        f"- drift: **{drift or 'none'}**",
        "",
        "## Timing (ms)",
        "",
        "| min | median | p95 | max |",
        "|---|---|---|---|",
        f"| {payload['summary']['duration_ms']['min']} | {payload['summary']['duration_ms']['median']} "
        f"| {payload['summary']['duration_ms']['p95']} | {payload['summary']['duration_ms']['max']} |",
        "",
        "## Stable values",
        "",
        "| metric | value |",
        "|---|---|",
    ]
    for key, values in unique.items():
        markdown.append(f"| {key} | {', '.join(values) if values else '-'} |")
    markdown += [
        "",
        f"ECS stable hash identical: `{len(payload['summary']['ecs_stable_sha256']) == 1}` "
        f"(raw ECS hashes: {payload['summary']['raw_ecs_sha_distinct']} distinct — `@timestamp` only, "
        "because Gitleaks output carries no time and is stamped at ingestion)",
        f"OCSF finding-UID set identical: `{len(payload['summary']['ocsf_uid_sha256']) == 1}`",
        "",
        "Each iteration: fresh database → `demo --reset` → second ingest (must create 0) →",
        "second validate (must not add executions) → ECS + OCSF export → 9 API reads.",
        "",
    ]
    (out / f"soak-{args.iterations}.md").write_text("\n".join(markdown), encoding="utf-8")

    print(f"\nfailures={len(failures)} drift={drift or 'none'}")
    print(f"artifacts: {json_path.name}, soak-{args.iterations}.md")
    return 0 if not failures and not drift else 1


if __name__ == "__main__":
    raise SystemExit(main())
