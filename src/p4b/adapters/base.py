"""Adapter contract.

An adapter does exactly two things: turn a tool's native output into domain
objects, and (for tools that run) build the command line. It never writes to the
database and never decides risk — both belong to other modules.

``parse`` is pure: same input, same output, no network, no clock dependence beyond
timestamps that come from the source itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..domain.models import Finding
from ..tooling import ToolSpec
from ..tooling import spec as tool_spec

# Most scanners exit non-zero to mean "I found something", which is not an error.
ACCEPTABLE_EXIT_CODES = {0, 1, 2}


@dataclass
class ParseResult:
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)       # detection content
    executions: list[dict[str, Any]] = field(default_factory=list)  # test runs

    def extend(self, other: ParseResult) -> None:
        self.findings.extend(other.findings)
        self.rules.extend(other.rules)
        self.executions.extend(other.executions)
        self.warnings.extend(other.warnings)
        for key, value in other.stats.items():
            self.stats[key] = self.stats.get(key, 0) + int(value)


@dataclass
class ScanResult:
    tool: str
    ok: bool = False
    skipped: bool = False
    exit_code: int | None = None
    duration_s: float = 0.0
    command: list[str] = field(default_factory=list)
    output_path: str = ""
    error: str = ""
    parse: ParseResult = field(default_factory=ParseResult)

    @property
    def findings(self) -> list[Finding]:
        return self.parse.findings


class Adapter(ABC):
    name: str = ""
    spec: ToolSpec

    # -- environment ------------------------------------------------------- #

    def available(self) -> bool:
        if self.spec.binary is None:
            return True
        return shutil.which(self.spec.binary) is not None

    def executable(self) -> str:
        """Resolved binary path, falling back to the bare name for command building."""
        if not self.spec.binary:
            return ""
        return shutil.which(self.spec.binary) or self.spec.binary

    def version(self) -> str:
        if not self.spec.binary or not self.spec.version_args:
            return ""
        path = shutil.which(self.spec.binary)
        if not path:
            return ""
        try:
            proc = subprocess.run(
                [path, *self.spec.version_args], capture_output=True, text=True, timeout=6, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        from ..tooling import VERSION_RE

        match = VERSION_RE.search(f"{proc.stdout}\n{proc.stderr}")
        return match.group(1) if match else ""

    # -- parsing ----------------------------------------------------------- #

    @abstractmethod
    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        ...

    # -- scanning ---------------------------------------------------------- #

    def supports_scan(self) -> bool:
        return self.spec.binary is not None

    def build_command(self, target: str, output_path: Path, opts: dict[str, Any]) -> list[str]:
        raise NotImplementedError(f"{self.name} does not support scanning")

    def scan(self, target: str, output_path: Path, opts: dict[str, Any] | None = None) -> ScanResult:
        """Run the tool and parse what it produced.

        Never raises: a broken tool must degrade to ``ScanResult.error`` so the rest
        of the pipeline keeps working.
        """
        opts = opts or {}
        result = ScanResult(tool=self.name)
        if not self.available():
            result.skipped = True
            result.error = f"binary not found: {self.spec.binary}"
            return result

        command = self.build_command(target, output_path, opts)
        result.command = command
        output_path.parent.mkdir(parents=True, exist_ok=True)
        timeout = int(opts.get("timeout", 1800))

        started = time.monotonic()
        try:
            process = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, check=False, shell=False
            )
            result.exit_code = process.returncode
            result.ok = process.returncode in ACCEPTABLE_EXIT_CODES
            if not result.ok:
                result.error = (process.stderr or process.stdout or "").strip()[:1000]
        except subprocess.TimeoutExpired:
            result.error = f"timeout after {timeout}s"
        except OSError as exc:
            result.error = f"could not run: {exc}"
        result.duration_s = round(time.monotonic() - started, 2)
        result.output_path = str(output_path)

        if output_path.is_file() and output_path.stat().st_size > 0:
            try:
                result.parse = self.parse(output_path, {"target": target, **opts})
            except Exception as exc:  # noqa: BLE001 - a bad parser must not kill the run
                result.parse.warnings.append(f"parse failed: {exc}")
                result.ok = False
        elif not result.error:
            result.error = "tool produced no output"
        return result

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def jsonl(path: Path) -> Iterator[dict[str, Any]]:
        """Iterate JSON Lines, skipping junk instead of failing the whole file."""
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line[0] not in "{[":
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    yield value

    @staticmethod
    def files(path: Path, pattern: str = "*.json") -> list[Path]:
        target = Path(path)
        return [target] if target.is_file() else sorted(target.glob(pattern))


def integer(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


__all__ = ["Adapter", "ParseResult", "integer", "tool_spec"]
