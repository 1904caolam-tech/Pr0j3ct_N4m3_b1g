"""Export sinks: write normalized findings for another system to consume."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .ecs import to_ecs
from .ocsf import to_ocsf

FORMATS = ("ecs", "ocsf")


def documents(rows: Iterable[dict[str, Any]], fmt: str) -> Iterator[dict[str, Any]]:
    if fmt == "ecs":
        for row in rows:
            yield to_ecs(row)
    elif fmt == "ocsf":
        for row in rows:
            yield to_ocsf(row)
    else:
        raise ValueError(f"unknown export format '{fmt}' (available: {', '.join(FORMATS)})")


def write_jsonl(path: str | Path, docs: Iterable[dict[str, Any]]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for document in docs:
            handle.write(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def render_jsonl(docs: Iterable[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n" for document in docs
    )


__all__ = ["FORMATS", "documents", "render_jsonl", "write_jsonl"]
