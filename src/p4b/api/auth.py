"""API tokens.

A token is shown once and stored as a SHA-256 hash. SHA-256 is enough here because
the token itself is 192 bits of randomness — there is nothing to brute force, and we
avoid pulling in a password-hashing dependency for a bearer credential.

Scopes are intentionally coarse: `read`, `write`, `admin`.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

TOKEN_PREFIX = "p4b_"
SCOPES = frozenset({"read", "write", "admin"})


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_hex(24)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_scopes(value: str | None) -> tuple[str, ...]:
    items = {item.strip() for item in (value or "read").split(",") if item.strip()}
    unknown = items - SCOPES
    if unknown:
        raise ValueError(f"unknown scope(s): {', '.join(sorted(unknown))}")
    return tuple(sorted(items))


@dataclass(frozen=True)
class Principal:
    name: str
    scopes: tuple[str, ...]

    def can(self, scope: str) -> bool:
        return "admin" in self.scopes or scope in self.scopes


def bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()
