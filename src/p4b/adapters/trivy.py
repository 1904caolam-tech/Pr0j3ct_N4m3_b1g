"""Trivy — Aqua Security. One source, three finding families.

`trivy image` returns vulnerabilities (CVEs inside packages), misconfigurations
(AVD-* rules) and secrets (credentials baked into an image layer). Each family has a
different shape and a different remediation story, so the parser keeps them apart.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..canon.assets import asset_for
from ..canon.attack import extract_cwe
from ..canon.remediation import build as build_remediation
from ..canon.text import as_list, redact
from ..domain.models import Finding, parse_ts, utcnow
from ..domain.severity import parse as parse_severity
from .base import Adapter, ParseResult, tool_spec

IMAGE_HINT = re.compile(r"^(docker://|oci://|[\w.\-]+/[\w.\-/]+)")
SECRET_SHEET = "Secrets_Management_Cheat_Sheet"
SECRET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"


def detect_kind(target: str) -> str:
    """`image` vs `fs` without asking the user, unless they override it."""
    if target.startswith(("docker://", "oci://")):
        return "image"
    if Path(target).exists():
        return "fs"
    if target[1:3] == ":\\":  # Windows path that does not exist yet
        return "fs"
    return "image" if IMAGE_HINT.match(target) or target.count("/") >= 1 else "fs"


class TrivyAdapter(Adapter):
    name = "trivy"
    spec = tool_spec("trivy")

    def build_command(self, target: str, output_path: Path, opts: dict[str, Any]) -> list[str]:
        kind = str(opts.get("kind") or detect_kind(target))
        subcommand = {"image": "image", "rootfs": "rootfs", "repo": "repo", "config": "config"}.get(
            kind, "fs"
        )
        command = [
            self.executable(),
            subcommand,
            target,
            "--format",
            "json",
            "--output",
            str(output_path),
            "--quiet",
            "--no-progress",
            "--scanners",
            str(opts.get("scanners") or "vuln,misconfig,secret"),
        ]
        if opts.get("severity"):
            value = opts["severity"]
            command += ["--severity", ",".join(value) if isinstance(value, list) else str(value)]
        if opts.get("ignore_unfixed"):
            command += ["--ignore-unfixed"]
        if opts.get("cache_dir"):
            command += ["--cache-dir", str(opts["cache_dir"])]
        command += [str(item) for item in opts.get("extra_args") or []]
        return command

    # -- parsing ----------------------------------------------------------- #

    def parse(self, path: Path, ctx: dict[str, Any] | None = None) -> ParseResult:
        ctx = ctx or {}
        import json

        result = ParseResult()
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))

        artifact = str(data.get("ArtifactName") or ctx.get("target") or "unknown")
        artifact_type = str(data.get("ArtifactType") or "filesystem")
        kind = (
            "image"
            if artifact_type == "container_image"
            else "repo"
            if artifact_type == "repository"
            else "filesystem"
        )
        asset = asset_for(kind, artifact)

        counts = {"vulnerabilities": 0, "misconfigurations": 0, "secrets": 0}
        for section in data.get("Results") or []:
            if not isinstance(section, dict):
                continue
            target = str(section.get("Target") or artifact)

            for vulnerability in section.get("Vulnerabilities") or []:
                result.findings.append(self._vulnerability(vulnerability, asset, target))
                counts["vulnerabilities"] += 1

            for misconfiguration in section.get("Misconfigurations") or []:
                if str(misconfiguration.get("Status", "")).upper() in {"PASS", "IGNORED"}:
                    continue
                result.findings.append(self._misconfiguration(misconfiguration, asset, target))
                counts["misconfigurations"] += 1

            for secret in section.get("Secrets") or []:
                result.findings.append(self._secret(secret, asset, target))
                counts["secrets"] += 1

        result.stats = counts
        if not result.findings:
            result.warnings.append("trivy reported no vulnerabilities, misconfigurations or secrets")
        return result

    # -- builders ---------------------------------------------------------- #

    def _vulnerability(self, vulnerability: dict[str, Any], asset, target: str) -> Finding:
        vulnerability_id = str(vulnerability.get("VulnerabilityID") or "UNKNOWN")
        package = str(vulnerability.get("PkgName") or "")
        installed = str(vulnerability.get("InstalledVersion") or "")
        fixed = str(vulnerability.get("FixedVersion") or "")
        score = _cvss(vulnerability)
        references = [str(url) for url in as_list(vulnerability.get("References")) if url]

        if fixed:
            step = f"Upgrade `{package}` from {installed} to {fixed}."
        else:
            step = f"No fixed version for `{package}` {installed}; apply compensating controls."

        tags = ["cve", package] if vulnerability_id.upper().startswith("CVE-") else ["vuln", package]
        for extra in (str(vulnerability.get("Status") or ""), "critical-cvss" if score >= 9 else ""):
            if extra:
                tags.append(extra)

        return Finding(
            source="trivy",
            category="vuln",
            title=str(vulnerability.get("Title") or f"{vulnerability_id} in {package}"),
            severity=parse_severity(vulnerability.get("Severity")),
            asset=asset,
            rule_id=vulnerability_id,
            rule_name=str(vulnerability.get("Title") or ""),
            locator=f"{target}:{vulnerability_id}:{package}",
            cwe=extract_cwe(vulnerability.get("CweIDs")),
            cve=[vulnerability_id.upper()] if vulnerability_id.upper().startswith("CVE-") else [],
            tags=tags,
            references=([str(vulnerability["PrimaryURL"])] if vulnerability.get("PrimaryURL") else [])
            + references[:10],
            remediation=build_remediation(summary=step, steps=[step], references=references[:5]),
            evidence=redact(
                {
                    "package": package,
                    "installed_version": installed,
                    "fixed_version": fixed,
                    "status": vulnerability.get("Status"),
                    "cvss": score,
                    "target": target,
                    "severity_source": vulnerability.get("SeveritySource", ""),
                }
            ),
            first_seen=parse_ts(vulnerability.get("PublishedDate")) or utcnow(),
            last_seen=utcnow(),
            confidence=0.95,
        )

    def _misconfiguration(self, misconfiguration: dict[str, Any], asset, target: str) -> Finding:
        rule_id = str(misconfiguration.get("AVDID") or misconfiguration.get("ID") or "MISCONFIG")
        resolution = str(misconfiguration.get("Resolution") or "").strip()
        references = [str(url) for url in as_list(misconfiguration.get("References")) if url]
        if misconfiguration.get("PrimaryURL"):
            references.insert(0, str(misconfiguration["PrimaryURL"]))

        return Finding(
            source="trivy",
            category="misconfig",
            title=str(misconfiguration.get("Title") or rule_id),
            severity=parse_severity(misconfiguration.get("Severity")),
            asset=asset,
            rule_id=rule_id,
            rule_name=str(misconfiguration.get("Title") or rule_id),
            locator=f"{target}:{rule_id}",
            tags=["misconfig", str(misconfiguration.get("Namespace") or "")],
            references=references[:10],
            remediation=build_remediation(
                summary=resolution,
                steps=[resolution] if resolution else [],
                references=references[:5],
            ),
            evidence=redact(
                {
                    "id": rule_id,
                    "message": misconfiguration.get("Message", ""),
                    "namespace": misconfiguration.get("Namespace", ""),
                    "target": target,
                    "resource": (misconfiguration.get("CauseMetadata") or {}).get("Resource", ""),
                    "provider": (misconfiguration.get("CauseMetadata") or {}).get("Provider", ""),
                }
            ),
            confidence=0.85,
        )

    def _secret(self, secret: dict[str, Any], asset, target: str) -> Finding:
        rule_id = str(secret.get("RuleID") or "secret")
        path = str(secret.get("Path") or target)
        line = secret.get("StartLine")

        return Finding(
            source="trivy",
            category="secret",
            title=str(secret.get("Title") or f"Secret in image: {rule_id}"),
            severity=parse_severity(secret.get("Severity") or "HIGH"),
            asset=asset,
            rule_id=rule_id,
            rule_name=str(secret.get("Category") or rule_id),
            locator=f"{path}:{line}:{rule_id}",
            tags=["secret", str(secret.get("Category") or "")],
            evidence=redact(
                {
                    "path": path,
                    "start_line": line,
                    "end_line": secret.get("EndLine"),
                    "match": secret.get("Match", ""),
                    "layer": (secret.get("Layer") or {}).get("DiffID", ""),
                }
            ),
            remediation=build_remediation(
                summary="Rotate the credential, remove it from the image, and block it in CI.",
                steps=[
                    "Rotate the secret now; assume it is compromised.",
                    "Rebuild the image without the file that carried it.",
                    "Add .trivyignore / a pre-commit hook to prevent recurrence.",
                ],
                cheat_sheet=SECRET_SHEET,
                cheat_sheet_url=SECRET_URL,
            ),
            confidence=0.9,
        )


def _cvss(vulnerability: dict[str, Any]) -> float:
    scores: list[float] = []
    for source in (vulnerability.get("CVSS") or {}).values():
        if not isinstance(source, dict):
            continue
        for key in ("V3Score", "V2Score"):
            try:
                if source.get(key):
                    scores.append(float(source[key]))
            except (TypeError, ValueError):
                continue
    return max(scores) if scores else 0.0
