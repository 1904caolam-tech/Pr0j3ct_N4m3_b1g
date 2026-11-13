"""Remediation payloads.

Adapters produce a plain dict, not a class: the same shape goes to SQLite (JSON
column), the API and the markdown report, and a dict survives all three without a
serializer. This helper keeps the shape in one place.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def build(
    *,
    summary: str = "",
    steps: Iterable[str] = (),
    references: Iterable[str] = (),
    cheat_sheet: str = "",
    cheat_sheet_url: str = "",
) -> dict[str, Any] | None:
    data = {
        "summary": (summary or "").strip(),
        "steps": [step for step in (steps or []) if step],
        "references": [reference for reference in (references or []) if reference],
        "cheat_sheet": cheat_sheet,
        "cheat_sheet_url": cheat_sheet_url,
    }
    if not any((data["summary"], data["steps"], data["references"], data["cheat_sheet"])):
        return None
    return data
