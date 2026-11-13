"""Finding identity.

The fingerprint is what makes ingest idempotent and dedupe possible. It must be
stable across runs, across process restarts, and across re-parses of the same
raw artifact — so it only contains values that come from the source itself.
"""

from __future__ import annotations

import hashlib
import json


def fingerprint(
    source: str,
    rule_id: str,
    title: str,
    asset_kind: str,
    asset_key: str,
    locator: str = "",
) -> str:
    material = {
        "s": source,
        "r": rule_id or title,
        "a": f"{asset_kind}:{asset_key}",
        "l": locator,
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def short_id(digest: str, prefix: str = "fnd") -> str:
    return f"{prefix}_{digest[:16]}"
