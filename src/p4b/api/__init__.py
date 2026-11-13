"""HTTP API (read-only in M1-M2; auth and writes arrive in M3)."""

from .app import create_app

__all__ = ["create_app"]
