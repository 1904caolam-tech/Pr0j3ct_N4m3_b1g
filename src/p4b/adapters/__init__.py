"""Adapter registry.

One place knows which tools exist. Adding a tool means adding an adapter module and
one line here — nothing else in the codebase changes.
"""

from __future__ import annotations

from .atomic import AtomicAdapter
from .base import Adapter, ParseResult, ScanResult
from .gitleaks import GitleaksAdapter
from .nuclei import NucleiAdapter
from .suricata import SuricataAdapter
from .trivy import TrivyAdapter
from .wazuh import WazuhAdapter
from .yara import YaraAdapter
from .zeek import ZeekAdapter

_INSTANCES: tuple[Adapter, ...] = (
    WazuhAdapter(),
    SuricataAdapter(),
    ZeekAdapter(),
    AtomicAdapter(),
    NucleiAdapter(),
    TrivyAdapter(),
    GitleaksAdapter(),
    YaraAdapter(),
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


__all__ = ["ADAPTERS", "Adapter", "ParseResult", "ScanResult", "all_adapters", "get", "names"]
