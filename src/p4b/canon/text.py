"""Text helpers shared by every adapter.

Redaction lives here on purpose: masking at parse time means secrets never reach
the database, the API or the UI (ADR-007).
"""

from __future__ import annotations

import re
from typing import Any

SECRET_KEYS = re.compile(
    r"(secret|password|passwd|token|api[_-]?key|private[_-]?key|credential|auth|match|snippet)",
    re.IGNORECASE,
)


def mask_secret(value: str, keep: int = 4) -> str:
    """``AKIA-EXAMPLE-DO-NOT-USE`` -> ``AKIA...(20)``: comparable, not usable."""
    text = str(value or "")
    if len(text) <= keep:
        return "*" * len(text)
    return f"{text[:keep]}...({len(text)})"


def redact(value: Any, key: str = "") -> Any:
    """Recursively mask values under sensitive-looking keys."""
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, key) for item in value]
    if isinstance(value, str) and key and SECRET_KEYS.search(key):
        return mask_secret(value)
    return value


def as_list(value: Any) -> list[str]:
    """Normalize a scalar-or-list field into a list of non-empty strings."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def truncate(value: Any, limit: int = 600) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def deep_get(data: Any, path: str, default: Any = None) -> Any:
    """Fetch ``a.b.0.c`` from nested dicts and lists."""
    current = data
    for part in path.split("."):
        if current is None:
            return default
        if isinstance(current, (list, tuple)):
            if not part.isdigit() or int(part) >= len(current):
                return default
            current = current[int(part)]
            continue
        if not isinstance(current, dict):
            return default
        current = current.get(part)
    return default if current is None else current
