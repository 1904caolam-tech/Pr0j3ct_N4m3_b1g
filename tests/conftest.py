"""Shared fixtures: an in-memory database with the full schema."""

from __future__ import annotations

import pytest

from p4b.store import Repositories, memory_engine
from p4b.store.tables import create_all


@pytest.fixture()
def engine():
    eng = memory_engine()
    create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def repos(engine) -> Repositories:
    repository = Repositories(engine)
    repository.ensure_tenant()
    return repository
