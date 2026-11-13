"""Alembic environment.

Kept intentionally small: the URL comes from the caller (``p4b init`` sets it) or
from ``alembic.ini`` when run by hand. ``render_as_batch`` keeps SQLite happy when
columns change later.
"""

from __future__ import annotations

from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context

from p4b.store.tables import metadata

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or "sqlite:///data/p4b.db"


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = sa.create_engine(_url(), future=True)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
