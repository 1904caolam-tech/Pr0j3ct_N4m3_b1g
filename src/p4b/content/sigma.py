"""Sigma rule inventory.

Reads a checkout of SigmaHQ/sigma (or any directory of rules) and turns each rule
into a normalized record: id, title, level, logsource, ATT&CK techniques, and a
content hash so a later sync can tell what changed.

The raw rule is kept in memory for translation but is not persisted, which keeps the
database small and avoids copying rule text we do not own (DRL 1.1).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RULE_SUFFIXES = (".yml", ".yaml")
SKIP_DIRS = {".git", ".github", "tests", "test", "docs", "tools", "contrib", "images", "rules-emerging-threats"}

ATTACK_TAG = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_TAG = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)


@dataclass(frozen=True)
class SigmaRule:
    native_id: str
    title: str
    level: str
    status: str
    description: str
    logsource: dict[str, str]
    tags: tuple[str, ...]
    attack: tuple[str, ...]
    tactics: tuple[str, ...]
    path: str
    content_hash: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def logsource_text(self) -> str:
        if not self.logsource:
            return ""
        return ", ".join(f"{key}={value}" for key, value in sorted(self.logsource.items()))

    def to_row(self) -> dict[str, Any]:
        return {
            "kind": "sigma",
            "native_id": self.native_id,
            "title": self.title,
            "level": self.level,
            "status": self.status,
            "logsource": self.logsource_text,
            "attack": list(self.attack),
            "tags": list(self.tags),
            "path": self.path,
            "content_hash": self.content_hash,
        }


def attack_from_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    techniques: set[str] = set()
    tactics: set[str] = set()
    for tag in tags:
        attack_match = ATTACK_TAG.match(tag)
        if attack_match:
            techniques.add("T" + attack_match.group(1).upper())
            continue
        tactic_match = TACTIC_TAG.match(tag)
        if tactic_match and not attack_match:
            tactics.add(tactic_match.group(1).lower())
    return sorted(techniques), sorted(tactics)


def normalize(document: dict[str, Any], path: Path, digest: str) -> SigmaRule | None:
    title = str(document.get("title") or "").strip()
    detection = document.get("detection")
    if not title or not isinstance(detection, dict):
        return None

    raw_tags = [str(tag) for tag in (document.get("tags") or [])]
    techniques, tactics = attack_from_tags(raw_tags)
    level = str(document.get("level") or "medium").strip().lower()
    if level == "informational":
        level = "info"

    native_id = str(document.get("id") or "").strip()
    if not native_id:
        native_id = "sigma-" + hashlib.sha1(f"{path}:{title}".encode()).hexdigest()[:12]  # noqa: S324

    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {"raw": str(logsource)}

    return SigmaRule(
        native_id=native_id,
        title=title,
        level=level,
        status=str(document.get("status") or ""),
        description=str(document.get("description") or "").strip(),
        logsource={str(key): str(value) for key, value in logsource.items()},
        tags=tuple(raw_tags),
        attack=tuple(techniques),
        tactics=tuple(tactics),
        path=str(path),
        content_hash=digest,
        raw=document,
    )


def load_file(path: Path) -> Iterator[SigmaRule]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        documents = list(yaml.safe_load_all(text))
    except (OSError, yaml.YAMLError):
        return
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    for document in documents:
        if not isinstance(document, dict):
            continue
        rule = normalize(document, Path(path), digest)
        if rule is not None:
            yield rule


def load_directory(root: Path) -> tuple[list[SigmaRule], list[str]]:
    """Walk a rule tree. Returns the rules and warnings for files we could not read."""
    base = Path(root)
    if not base.exists():
        return [], [f"path does not exist: {base}"]

    rules: list[SigmaRule] = []
    warnings: list[str] = []
    files = [base] if base.is_file() else sorted(
        item for item in base.rglob("*") if item.is_file() and item.suffix.lower() in RULE_SUFFIXES
    )
    for file in files:
        if any(part in SKIP_DIRS for part in file.parts):
            continue
        loaded = list(load_file(file))
        if not loaded:
            warnings.append(f"skipped (not a Sigma detection rule): {file}")
            continue
        rules.extend(loaded)
    return rules, warnings
