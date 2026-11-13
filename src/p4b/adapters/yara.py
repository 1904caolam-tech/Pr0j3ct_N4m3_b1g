"""YARA — pattern matching over files.

YARA has no `-o` flag and no machine-readable output, so this adapter overrides
`scan` to capture stdout itself. The text format (`-m`) is:

    RuleName [author="x", severity="high"] /path/to/file

Rule metadata is read from the rule file so findings carry the description and
ATT&CK tag rather than just a name.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.attack import extract_attack
from ..canon.text import redact, truncate
from ..content.yara import parse_text as parse_rule_text
from ..domain.models import Finding, Severity, utcnow
from ..domain.severity import parse as parse_severity
from .base import Adapter, ParseResult, ScanResult, tool_spec

LINE_RE = re.compile(r"^(?P<name>[A-Za-z_]\w*)(?:\s+\[(?P<meta>.*?)\])?\s+(?P<file>.+)$")
MALWARE_TAGS = {"malware", "apt", "ransomware", "trojan", "backdoor", "rat", "webshell", "miner"}


class YaraAdapter(Adapter):
    name = "yara"
    spec = tool_spec("yara")

    def build_command(self, target: str, output_path: Path, opts: dict[str, Any]) -> list[str]:
        rules = opts.get("rules") or opts.get("rule_file")
        if not rules:
            raise ValueError("yara requires opts['rules'] pointing at a .yar file")
        return [
            self.executable(),
            "-r",
            "-w",
            "-m",
            "-f",
            str(rules),
            target,
        ]

    # -- scanning ---------------------------------------------------------- #

    def scan(self, target: str, output_path: Path, opts: dict[str, Any] | None = None) -> ScanResult:
        opts = opts or {}
        result = ScanResult(tool=self.name)
        if not (opts.get("rules") or opts.get("rule_file")):
            result.skipped = True
            result.error = "missing opts['rules']"
            return result
        if not self.available():
            result.skipped = True
            result.error = f"binary not found: {self.spec.binary}"
            return result

        command = self.build_command(target, output_path, opts)
        result.command = command
        output_path.parent.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=int(opts.get("timeout", 900)),
                check=False,
                shell=False,
            )
            output_path.write_text(process.stdout or "", encoding="utf-8", errors="replace")
            result.exit_code = process.returncode
            result.ok = process.returncode in (0, 1)  # 1 means "matched"
            if not result.ok:
                result.error = (process.stderr or "").strip()[:1000]
        except subprocess.TimeoutExpired:
            result.error = f"timeout after {opts.get('timeout', 900)}s"
        except OSError as exc:
            result.error = f"could not run: {exc}"

        result.duration_s = round(time.monotonic() - started, 2)
        result.output_path = str(output_path)
        if output_path.is_file() and output_path.stat().st_size:
            try:
                result.parse = self.parse(output_path, {"target": target, **opts})
            except Exception as exc:  # noqa: BLE001
                result.parse.warnings.append(f"parse failed: {exc}")
        return result

    # -- parsing ----------------------------------------------------------- #

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        ctx = ctx or {}
        result = ParseResult()
        metadata = self._rule_metadata(ctx.get("rules") or ctx.get("rule_file"))
        target = str(ctx.get("target") or "")

        text = Path(path).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("0x", "error:", "warning:")):
                continue
            match = LINE_RE.match(line)
            if not match:
                continue

            name = match.group("name")
            info = metadata.get(name, {})
            meta = info.get("meta", {})
            tags = info.get("tags", [])
            severity = parse_severity(meta.get("severity")) if meta.get("severity") else _severity_from_tags(tags)
            file_path = match.group("file").strip()

            result.findings.append(
                Finding(
                    source="yara",
                    category="malware" if MALWARE_TAGS & {tag.lower() for tag in tags} else "detection",
                    title=str(meta.get("description") or f"YARA match: {name}"),
                    severity=severity,
                    asset=asset_for("filesystem", file_path or target),
                    rule_id=name,
                    rule_name=str(meta.get("description") or name),
                    locator=f"{name}:{file_path or target}",
                    attack=extract_attack(*meta.values(), name, match.group("meta") or ""),
                    tags=["yara", *tags],
                    references=[meta["reference"]] if meta.get("reference") else [],
                    evidence=redact(
                        {
                            "rule": name,
                            "file": file_path or target,
                            "meta": truncate(match.group("meta"), 300),
                            "author": meta.get("author", ""),
                            "description": meta.get("description", ""),
                        }
                    ),
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                    confidence=0.85,
                )
            )

        result.stats = {"matches": len(result.findings), "rules_loaded": len(metadata)}
        if not result.findings:
            result.warnings.append("yara produced no matches")
        return result

    @staticmethod
    def _rule_metadata(rules_path: Any) -> dict[str, dict[str, Any]]:
        if not rules_path:
            return {}
        path = Path(str(rules_path))
        if not path.is_file():
            return {}
        rules = parse_rule_text(path.read_text(encoding="utf-8", errors="replace"), str(path))
        return {
            rule.name: {"meta": rule.meta, "tags": list(rule.tags), "attack": rule.attack}
            for rule in rules
        }


def _severity_from_tags(tags: list[str]) -> Severity:
    lowered = {tag.lower() for tag in tags}
    if lowered & {"apt", "ransomware", "backdoor", "rat"}:
        return Severity.CRITICAL
    if lowered & {"malware", "trojan", "exploit", "webshell", "miner"}:
        return Severity.HIGH
    return Severity.MEDIUM
