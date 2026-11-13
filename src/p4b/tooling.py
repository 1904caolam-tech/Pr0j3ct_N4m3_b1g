"""Inventory of the ten tools P4B integrates.

Detection lives here rather than in the adapters so `p4b doctor` works before any
adapter is implemented. Each adapter later reuses the same spec.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    layer: str          # scanner | telemetry | detection | validation | knowledge
    repo: str
    binary: str | None
    license: str
    version_args: tuple[str, ...] = ()
    note: str = ""


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("nuclei", "scanner", "projectdiscovery/nuclei", "nuclei", "MIT", ("-version",)),
    ToolSpec("trivy", "scanner", "aquasecurity/trivy", "trivy", "Apache-2.0", ("--version",)),
    ToolSpec("gitleaks", "scanner", "gitleaks/gitleaks", "gitleaks", "MIT", ("version",)),
    ToolSpec("yara", "detection", "VirusTotal/yara", "yara", "BSD-3-Clause", ("--version",)),
    ToolSpec("zeek", "telemetry", "zeek/zeek", "zeek", "BSD-3-Clause", ("--version",)),
    ToolSpec("suricata", "telemetry", "OISF/suricata", "suricata", "GPL-2.0", ("--build-info",)),
    ToolSpec("wazuh", "telemetry", "wazuh/wazuh", "wazuh-manager", "GPL-2.0", ("--version",)),
    ToolSpec("sigma", "detection", "SigmaHQ/sigma", None, "DRL-1.1", note="content only"),
    ToolSpec("atomic", "validation", "redcanaryco/atomic-red-team", None, "Apache-2.0", note="content only"),
    ToolSpec("owasp-cheatsheets", "knowledge", "OWASP/CheatSheetSeries", None, "CC-BY-SA-4.0", note="links only"),
)

LAYERS = {
    "scanner": "active scan",
    "detection": "detection content",
    "telemetry": "telemetry / sensor",
    "validation": "validation (purple team)",
    "knowledge": "knowledge / remediation",
}

_BY_NAME: dict[str, ToolSpec] = {tool.name: tool for tool in TOOLS}


def spec(name: str) -> ToolSpec:
    """Look up a tool by name; used by adapters so specs stay in one place."""
    try:
        return _BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown tool '{name}' (known: {', '.join(sorted(_BY_NAME))})") from None


def detect(spec: ToolSpec, *, path_hint: str | Path | None = None, timeout: int = 6) -> dict:
    """Return availability, resolved path and version for one tool.

    Content repositories (Sigma, Atomic, cheatsheets) have no binary; for those,
    ``path_hint`` points at the checkout and existence is the availability check.
    """
    row = asdict(spec)
    row["available"] = False
    row["path"] = ""
    row["version"] = ""

    if spec.binary is None:
        if path_hint is not None:
            hint = Path(path_hint)
            row["available"] = hint.exists()
            row["path"] = str(hint) if hint.exists() else ""
            if not hint.exists():
                row["note"] = f"content path not found: {hint}"
        return row

    path = shutil.which(spec.binary)
    if not path:
        return row
    row["available"] = True
    row["path"] = path
    try:
        proc = subprocess.run(
            [path, *spec.version_args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        match = VERSION_RE.search(f"{proc.stdout}\n{proc.stderr}")
        if match:
            row["version"] = match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return row


def detect_all(paths: dict[str, str | Path] | None = None) -> list[dict]:
    paths = paths or {}
    return [detect(spec, path_hint=paths.get(spec.name)) for spec in TOOLS]
