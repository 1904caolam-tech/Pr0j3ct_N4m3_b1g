"""Asset key normalization.

The asset registry (see ARCHITECTURE §5.1) only works if the same asset produces
the same key no matter which tool reported it. This module is the pure part: no
database, no I/O — just normalization rules that can be unit-tested.
"""

from __future__ import annotations

import re

from ..domain.models import Asset

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_URL = re.compile(r"^(?P<scheme>https?)://(?P<host>[^/:?#]+)(?::\d+)?", re.IGNORECASE)
_GIT_SSH = re.compile(r"^git@(?P<host>[^:]+):(?P<path>.+)$")


def normalize_key(kind: str, raw: str) -> str:
    """Return the canonical key for an asset of ``kind``.

    - host: lowercase, no trailing dot
    - ip:   strip brackets and port
    - url:  host only (path is a locator, not an identity)
    - image: drop digest and tag (tags move; digest is a separate identity)
    - repo: strip scheme, ``.git`` and credentials, lowercase
    """
    value = (raw or "").strip()
    if kind == "host":
        return value.lower().rstrip(".")
    if kind == "ip":
        if value.startswith("["):
            return value[1 : value.index("]")] if "]" in value else value[1:]
        if value.count(":") == 1:  # 10.0.4.31:445
            return value.split(":")[0]
        return value  # bare IPv4, or bare IPv6 (no port to strip)
    if kind == "url":
        match = _URL.match(value)
        host = match.group("host") if match else value
        return host.lower().rstrip(".")
    if kind == "image":
        return value.split("@")[0]
    if kind == "repo":
        ssh = _GIT_SSH.match(value)
        if ssh:
            value = f"{ssh.group('host')}/{ssh.group('path')}"
        value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
        value = re.sub(r"^[^@/]+@", "", value)  # credentials in the URL
        value = value.removesuffix(".git")
        return value.strip("/").lower()
    if kind in {"filesystem", "cloud", "unknown"}:
        return value
    return value


def asset_for(kind: str, raw: str, *, exposure: str = "", ip: str = "") -> Asset:
    """Build an :class:`Asset` with a normalized key.

    Exposure is inferred only when it is obvious: URLs are internet-facing,
    images are containers, repos are repositories. Everything else is internal
    until an operator says otherwise.
    """
    key = normalize_key(kind, raw)
    if not exposure:
        exposure = {
            "url": "internet",
            "image": "container",
            "repo": "repo",
            "cloud": "cloud",
        }.get(kind, "internal")
    if not ip and _IPV4.match(key):
        ip = key
    return Asset(kind=kind, key=key, name=raw.strip(), ip=ip, exposure=exposure)
