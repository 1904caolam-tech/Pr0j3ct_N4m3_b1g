"""Adapter registry.

One place knows which tools exist. Adding a tool means adding an adapter module and
one line here — nothing else in the codebase changes.
"""

from __future__ import annotations

from .atomic import AtomicAdapter
from .base import Adapter, ParseResult
from .suricata import SuricataAdapter
from .wazuh import WazuhAdapter
from .zeek import ZeekAdapter

_INSTANCES: tuple[Adapter, ...] = (
    WazuhAdapter(),
    SuricataAdapter(),
    ZeekAdapter(),
    AtomicAdapter(),
)

ADAPTERS: dict[str, Adapter] = {adapter.name: adapter for adapter in _INSTANCES}


def get(name: str) -> Adapter:
    try:
        return ADAPTERS[name]
    except KeyError:
        raise KeyError(f"no adapter '{name}' (available: {', '.join(sorted(ADAPTERS))})") from None


def names() -> list[str]:
    return sorted(ADAPTERS)


def all_adapters() -> list[Adapter]:
    return list(_INSTANCES)


__all__ = ["ADAPTERS", "Adapter", "ParseResult", "all_adapters", "get", "names"]
