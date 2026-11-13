"""YARA rule inventory.

A light parser: it reads rule names, tags and metadata (including ATT&CK identifiers
placed in `meta`), but never compiles or executes rules. Compilation belongs to the
YARA engine at scan time (M2).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

RULE_START = re.compile(
    r"^\s*(?:(?:private|global)\s+)*rule\s+(?P<name>[A-Za-z_]\w*)\s*(?::\s*(?P<tags>[\w\s]+?))?\s*\{",
    re.MULTILINE,
)
META_LINE = re.compile(r'^\s*(?P<key>[A-Za-z_]\w*)\s*=\s*(?P<value>"(?:[^"\\]|\\.)*"|\d+)', re.MULTILINE)
ATTACK_IN_VALUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass(frozen=True)
class YaraRule:
    name: str
    tags: tuple[str, ...]
    meta: dict[str, str]
    path: str
    content_hash: str = ""
    body: str = field(default="", repr=False, compare=False)

    @property
    def attack(self) -> list[str]:
        found: set[str] = set()
        for value in self.meta.values():
            found.update(ATTACK_IN_VALUE.findall(str(value)))
        found.update(ATTACK_IN_VALUE.findall(self.name))
        return sorted(found)

    @property
    def severity(self) -> str:
        return self.meta.get("severity", "")

    def to_row(self) -> dict:
        return {
            "kind": "yara",
            "native_id": self.name,
            "title": self.meta.get("description") or self.name,
            "level": self.meta.get("severity") or "medium",
            "status": "",
            "logsource": ",".join(self.tags),
            "attack": self.attack,
            "tags": list(self.tags),
            "path": self.path,
            "content_hash": self.content_hash,
        }


def _balanced_body(text: str, opening: int) -> int:
    """Find the closing brace of a rule body.

    Brace counting alone is wrong: YARA strings such as ``"${jndi:ldap://"`` contain
    braces, which would extend the body into the next rule. Track string state.
    """
    depth = 0
    in_string = False
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def parse_text(text: str, path: str = "") -> list[YaraRule]:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    rules: list[YaraRule] = []
    for match in RULE_START.finditer(text):
        opening = match.end() - 1
        closing = _balanced_body(text, opening)
        end = closing + 1 if closing < len(text) else closing
        body = text[opening:end]
        meta_block = body.split("strings:", 1)[0]

        meta: dict[str, str] = {}
        for line in META_LINE.finditer(meta_block):
            meta[line.group("key")] = line.group("value").strip().strip('"')

        rules.append(
            YaraRule(
                name=match.group("name"),
                tags=tuple((match.group("tags") or "").split()),
                meta=meta,
                path=path,
                content_hash=digest,
                body=body,
            )
        )
    return rules


def load_directory(root: Path) -> tuple[list[YaraRule], list[str]]:
    base = Path(root)
    if not base.exists():
        return [], [f"path does not exist: {base}"]

    rules: list[YaraRule] = []
    warnings: list[str] = []
    files = [base] if base.is_file() else sorted(
        item for item in base.rglob("*") if item.is_file() and item.suffix.lower() in {".yar", ".yara"}
    )
    if not files:
        warnings.append(f"no .yar files found under {base}")
    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"could not read {file}: {exc}")
            continue
        parsed = parse_text(text, str(file))
        if not parsed:
            warnings.append(f"no yara rules found in {file}")
        rules.extend(parsed)
    return rules, warnings
