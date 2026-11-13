"""Engine construction.

SQLite needs two pragmas to behave: foreign keys are off by default, and WAL makes
concurrent reads from the API while the worker writes actually work.
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from sqlalchemy import event


def make_engine(db_url: str, *, echo: bool = False) -> sa.Engine:
    engine = sa.create_engine(db_url, echo=echo, future=True, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":
        _install_sqlite_pragmas(engine)
    return engine


def _install_sqlite_pragmas(engine: sa.Engine) -> None:
    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection, _record):  # noqa: ANN001 - sqlalchemy signature
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()


def sqlite_url(path: str | Path) -> str:
    """Build a portable SQLite URL (Windows paths need forward slashes)."""
    return f"sqlite:///{Path(path).as_posix()}"


def memory_engine() -> sa.Engine:
    """In-memory engine for tests. Static pool keeps one connection alive."""
    engine = sa.create_engine(
        "sqlite://", future=True, connect_args={"check_same_thread": False}, poolclass=sa.pool.StaticPool
    )
    _install_sqlite_pragmas(engine)
    return engine
