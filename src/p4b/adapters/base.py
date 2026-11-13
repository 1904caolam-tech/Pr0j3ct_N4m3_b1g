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
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..domain.models import Finding
from ..tooling import ToolSpec
from ..tooling import spec as tool_spec


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


class Adapter(ABC):
    name: str = ""
    spec: ToolSpec

    # -- environment ------------------------------------------------------- #

    def available(self) -> bool:
        if self.spec.binary is None:
            return True
        return shutil.which(self.spec.binary) is not None

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
