"""Run the test suite N times and record the pass count and timing.

    python deploy/soak/tests.py --iterations 50
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PASSED = re.compile(r"(\d+) passed")
FAILED = re.compile(r"(\d+) failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--out", default=str(REPO / "artifacts" / "soak"))
    args = parser.parse_args()

    rows = []
    started = datetime.now(timezone.utc)
    # The suite needs no third-party pytest plugins; autoloading them (brownie's
    # web3, for instance) adds seconds per run and warning noise.
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    for index in range(1, args.iterations + 1):
        t0 = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "-m", "pytest"],
            capture_output=True,
            text=True,
            cwd=REPO,
            env=env,
            timeout=900,
        )
        duration = (time.perf_counter() - t0) * 1000
        output = proc.stdout + proc.stderr
        passed = int(PASSED.search(output).group(1)) if PASSED.search(output) else 0
        failed = int(FAILED.search(output).group(1)) if FAILED.search(output) else 0
        rows.append(
            {
                "iteration": index,
                "duration_ms": round(duration, 1),
                "passed": passed,
                "failed": failed,
                "exit_code": proc.returncode,
                "tail": output.strip().splitlines()[-1] if output.strip() else "",
            }
        )
        print(f"  {index:>3}/{args.iterations}  {duration:7.1f} ms  passed={passed} failed={failed}")

    durations = [row["duration_ms"] for row in rows]
    counts = sorted({row["passed"] for row in rows})
    failures = [row for row in rows if row["failed"] or row["exit_code"] != 0]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": started.isoformat(timespec="seconds"),
        "iterations_requested": args.iterations,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "summary": {
            "unique_passed": counts,
            "runs_with_failures": len(failures),
            "duration_ms": {
                "min": round(min(durations), 1),
                "median": round(statistics.median(durations), 1),
                "p95": round(sorted(durations)[max(0, int(len(durations) * 0.95) - 1)], 1),
                "max": round(max(durations), 1),
            },
        },
        "failures": failures,
        "iterations": rows,
    }
    path = out / f"pytest-{args.iterations}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    markdown = [
        f"# Test suite — {args.iterations} consecutive runs",
        "",
        f"- generated: {payload['generated_at']}",
        f"- Python {platform.python_version()} ({platform.system()})",
        f"- pass counts observed: **{counts}**",
        f"- runs with failures: **{len(failures)}**",
        "",
        "| metric | ms |",
        "|---|---|",
        f"| min | {payload['summary']['duration_ms']['min']} |",
        f"| median | {payload['summary']['duration_ms']['median']} |",
        f"| p95 | {payload['summary']['duration_ms']['p95']} |",
        f"| max | {payload['summary']['duration_ms']['max']} |",
        "",
    ]
    (out / f"pytest-{args.iterations}.md").write_text("\n".join(markdown), encoding="utf-8")
    print(f"\nunique pass counts={counts} failing runs={len(failures)}")
    return 0 if len(counts) == 1 and not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
