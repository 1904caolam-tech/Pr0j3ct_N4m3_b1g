"""Atomic Red Team: test inventory and execution results.

Two very different inputs share one adapter:

- **inventory** — `atomics/T1003.001/T1003.001.yaml` from the Atomic repo. Tells us
  which techniques *can* be tested, on which platform, with which executor.
- **results** — JSON written after a run (atomic-operator, Invoke-AtomicRedTeam, or a
  CI job). Tells us which techniques *were* tested, when, and on which host.

The second one is what turns coverage from a claim into evidence.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

from ..domain.models import parse_ts, to_iso, utcnow
from .base import Adapter, ParseResult, tool_spec

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


class AtomicAdapter(Adapter):
    name = "atomic"
    spec = tool_spec("atomic")

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        ctx = ctx or {}
        if str(ctx.get("kind") or "") == "results":
            return self.parse_results(Path(path))
        return self.parse_inventory(Path(path))

    # -- inventory --------------------------------------------------------- #

    def parse_inventory(self, root: Path) -> ParseResult:
        result = ParseResult()
        files = (
            [root]
            if root.is_file()
            else sorted(item for item in root.rglob("*.yaml") if TECHNIQUE_RE.search(item.name))
        )
        if not files:
            result.warnings.append(f"no atomic test files found under {root}")
            return result

        for file in files:
            technique = _technique_from_name(file.name) or _technique_from_parent(file)
            if not technique:
                continue
            try:
                document = yaml.safe_load(file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, yaml.YAMLError):
                result.warnings.append(f"could not read {file}")
                continue
            if not isinstance(document, dict):
                continue

            technique = str(document.get("attack_technique") or technique).upper()
            for test in document.get("atomic_tests") or []:
                if not isinstance(test, dict):
                    continue
                executor = test.get("executor") or {}
                platforms = test.get("supported_platforms") or (
                    [executor.get("name")] if executor.get("name") else []
                )
                result.rules.append(
                    {
                        "technique": technique,
                        "test_name": str(test.get("name") or "unnamed"),
                        "platform": ",".join(str(platform) for platform in platforms),
                        "executor": str(executor.get("name") or ""),
                        "elevation": bool(executor.get("elevation_required")),
                        "command": str(executor.get("command") or "")[:400],
                        "path": str(file),
                    }
                )

        result.stats = {
            "techniques": len({item["technique"] for item in result.rules}),
            "tests": len(result.rules),
        }
        return result

    # -- execution results -------------------------------------------------- #

    def parse_results(self, path: Path) -> ParseResult:
        import json

        result = ParseResult()
        payload = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
        rows = payload.get("results") if isinstance(payload, dict) else payload
        if isinstance(rows, dict):
            rows = [rows]

        for index, row in enumerate(rows if isinstance(rows, list) else []):
            if not isinstance(row, dict):
                continue
            technique = _first(row, "technique", "attack_technique", "technique_id", "mitre_technique")
            match = TECHNIQUE_RE.search(str(technique or ""))
            if not match:
                result.warnings.append(f"execution #{index} has no technique; skipped")
                continue

            technical_id = match.group(0).upper()
            test_name = str(
                _first(row, "test_name", "name", "atomic_test_name", "test") or f"{technical_id} test"
            )
            host = str(_first(row, "host", "hostname", "computer", "agent", "asset") or "")
            started = parse_ts(_first(row, "started", "start_time", "startTime", "timestamp")) or utcnow()
            finished = parse_ts(_first(row, "finished", "end_time", "endTime", "completed"))

            result.executions.append(
                {
                    "id": _execution_id(technical_id, test_name, host, to_iso(started) or ""),
                    "technique": technical_id,
                    "test_name": test_name,
                    "host": host,
                    "started": to_iso(started),
                    "finished": to_iso(finished),
                    "status": _status(row),
                    "note": str(_first(row, "note", "message", "error", "return_code") or "")[:300],
                }
            )

        result.stats = {"executions": len(result.executions)}
        return result


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _execution_id(technique: str, test_name: str, host: str, started: str) -> str:
    digest = hashlib.sha1(f"{technique}|{test_name}|{host}|{started}".encode()).hexdigest()
    return "exe_" + digest[:16]


def _status(row: dict[str, Any]) -> str:
    for key in ("status", "result", "execution_success", "success", "exit_code", "return_code"):
        if key not in row:
            continue
        value = row[key]
        if isinstance(value, bool):
            return "success" if value else "failed"
        if isinstance(value, (int, float)):
            return "success" if value == 0 else "failed"
        text = str(value).strip().lower()
        if text in {"success", "succeeded", "ok", "passed", "true"}:
            return "success"
        if text in {"failed", "failure", "error", "false"}:
            return "failed"
    return "unknown"


def _technique_from_name(name: str) -> str | None:
    match = TECHNIQUE_RE.search(Path(name).stem)
    return match.group(0).upper() if match else None


def _technique_from_parent(path: Path) -> str | None:
    match = TECHNIQUE_RE.search(path.parent.name)
    return match.group(0).upper() if match else None
