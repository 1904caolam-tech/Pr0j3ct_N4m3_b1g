"""Canonicalization: normalization rules that do not touch the database."""

from .assets import asset_for, normalize_key

__all__ = ["asset_for", "normalize_key"]
