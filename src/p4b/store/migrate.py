"""Schema migrations.

Alembic is the single source of truth for the schema. The migration directory is
located by, in order: ``P4B_MIGRATIONS``, the repository checkout, the working
directory. If none is found (for example a wheel install without migrations), we
fall back to ``metadata.create_all`` and say so loudly, because that path cannot
upgrade an existing database.
"""

from __future__ import annotations

import os
from pathlib import Path

import sqlalchemy as sa

from . import tables


def migrations_dir() -> Path | None:
    candidates: list[Path] = []
    env = os.environ.get("P4B_MIGRATIONS")
    if env:
        candidates.append(Path(env))
    repo_root = Path(__file__).resolve().parents[3]
    candidates.extend([repo_root / "migrations", Path.cwd() / "migrations"])
    for candidate in candidates:
        if (candidate / "env.py").is_file():
            return candidate
    return None


def upgrade(engine: sa.Engine, db_url: str) -> str:
    """Bring the database to head. Returns a short description of the path taken."""
    directory = migrations_dir()
    if directory is None:
        tables.metadata.create_all(engine)
        return "create_all (migrations directory not found)"

    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(directory))
    config.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(config, "head")
    return "alembic upgrade head"
