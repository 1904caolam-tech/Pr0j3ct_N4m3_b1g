"""Gitleaks — secrets in git history and working trees.

The report can contain the secret verbatim, so this adapter never trusts it: the
value is masked at parse time and `--redact` is always passed to the tool. A secret
scanner that leaks secrets into a database is an own goal.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.remediation import build as build_remediation
from ..canon.text import as_list, mask_secret, redact, truncate
from ..domain.models import Finding, Severity, parse_ts, utcnow
from .base import Adapter, ParseResult, tool_spec

SECRET_SHEET = "Secrets_Management_Cheat_Sheet"
SECRET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"

CRITICAL_HINTS = ("private-key", "aws", "gcp", "azure", "ssh", "pgp", "rsa", "pkcs8", "root")
HIGH_HINTS = ("github", "gitlab", "slack", "stripe", "twilio", "sendgrid", "npm", "pypi", "jwt", "oauth")


def severity_for(rule_id: str, tags: list[str]) -> Severity:
    blob = f"{rule_id} {' '.join(tags)}".lower()
    if any(hint in blob for hint in CRITICAL_HINTS):
        return Severity.CRITICAL
    if any(hint in blob for hint in HIGH_HINTS):
        return Severity.HIGH
    return Severity.MEDIUM


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    spec = tool_spec("gitleaks")

    def build_command(self, target: str, output_path: Path, opts: dict[str, Any]) -> list[str]:
        command = [
            self.executable(),
            "detect",
            "--source",
            target,
            "--report-format",
            "json",
            "--report-path",
            str(output_path),
            "--no-banner",
            "--redact",
            "--exit-code",
            "0",
        ]
        if opts.get("config"):
            command += ["--config", str(opts["config"])]
        if opts.get("no_git"):
            command += ["--no-git"]
        if opts.get("baseline"):
            command += ["--baseline-path", str(opts["baseline"])]
        command += [str(item) for item in opts.get("extra_args") or []]
        return command

    # -- parsing ----------------------------------------------------------- #

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        ctx = ctx or {}
        result = ParseResult()
        payload = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
        leaks = payload if isinstance(payload, list) else [payload]

        repo = str(ctx.get("repo") or ctx.get("target") or "unknown")
        asset = asset_for("repo", repo)

        for leak in leaks:
            if isinstance(leak, dict):
                result.findings.append(self._to_finding(leak, asset))

        result.stats = {"leaks": len(result.findings)}
        return result

    def _to_finding(self, leak: dict[str, Any], asset) -> Finding:
        rule_id = str(leak.get("RuleID") or "generic")
        tags = [str(tag) for tag in as_list(leak.get("Tags"))]
        file_path = str(leak.get("File") or "")
        start = leak.get("StartLine")
        secret = str(leak.get("Secret") or leak.get("Match") or "")
        fingerprint = str(leak.get("Fingerprint") or f"{file_path}:{start}:{rule_id}")
        timestamp = parse_ts(leak.get("Date")) or utcnow()
        evidence = redact(
            {
                "file": file_path,
                "start_line": start,
                "end_line": leak.get("EndLine"),
                "commit": leak.get("Commit"),
                "author": leak.get("Author"),
                "email": leak.get("Email"),
                "date": leak.get("Date"),
                "entropy": leak.get("Entropy"),
                "match": truncate(leak.get("Match"), 200),
            }
        )
        # Already masked; running redact over it again would mask the mask.
        evidence["secret_preview"] = mask_secret(secret, 3)

        return Finding(
            source="gitleaks",
            category="secret",
            title=str(leak.get("Description") or f"Committed secret: {rule_id}"),
            severity=severity_for(rule_id, tags),
            asset=asset,
            rule_id=rule_id,
            rule_name=str(leak.get("Description") or rule_id),
            locator=fingerprint,
            tags=["secret", *tags],
            evidence=evidence,
            remediation=build_remediation(
                summary=f"Rotate the `{rule_id}` credential and purge it from git history.",
                steps=[
                    "Rotate or revoke the credential (assume it is compromised).",
                    "Rewrite history with git filter-repo, then force-push carefully.",
                    "Enable Gitleaks in pre-commit and CI to block recurrence.",
                ],
                references=["https://github.com/gitleaks/gitleaks"],
                cheat_sheet=SECRET_SHEET,
                cheat_sheet_url=SECRET_URL,
            ),
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=0.9,
        )
