"""ATT&CK / CWE / CVE extraction.

Tools put technique identifiers in wildly different places: Wazuh in
``rule.mitre.id``, Suricata in rule metadata, Sigma in tags, YARA in rule meta.
Everything funnels through these three functions so the join key stays consistent.
"""

from __future__ import annotations

import re
from typing import Any

from .text import as_list

ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_attack(*values: Any) -> list[str]:
    found: set[str] = set()
    for value in values:
        for item in as_list(value):
            found.update(match.upper() for match in ATTACK_RE.findall(str(item)))
    return sorted(found)


def extract_cwe(*values: Any) -> list[str]:
    found: set[str] = set()
    for value in values:
        for item in as_list(value):
            found.update(match.upper() for match in CWE_RE.findall(str(item)))
    return sorted(found)


def extract_cve(*values: Any) -> list[str]:
    found: set[str] = set()
    for value in values:
        for item in as_list(value):
            found.update(match.upper() for match in CVE_RE.findall(str(item)))
    return sorted(found)
