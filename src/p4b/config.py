"""Configuration: defaults <- p4b.yaml <- environment variables.

Deliberately dependency-light (dataclass + PyYAML). Everything is explicit so a
reviewer can see all knobs in one screen.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ENV_PREFIX = "P4B_"
CONFIG_NAMES = ("p4b.yaml", "p4b.yml")


@dataclass
class Settings:
    data_dir: Path = Path("data")
    db_url: str = ""
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    require_auth: bool = False
    case_window_hours: int = 24
    min_wazuh_level: int = 7
    scan_timeout: int = 1800
    max_body_mb: int = 64
    sigma_path: Path = Path("vendor/sigma")
    atomic_path: Path = Path("vendor/atomic-red-team")
    cheatsheet_path: Path = Path("vendor/CheatSheetSeries")
    rules_dir: Path = Path("data/rules")
    reports_dir: Path = Path("data/reports")
    raw_dir: Path = Path("data/raw")

    # -- derived ----------------------------------------------------------- #

    def database_url(self) -> str:
        if self.db_url:
            return self.db_url
        return f"sqlite:///{(self.data_dir / 'p4b.db').as_posix()}"

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.rules_dir, self.reports_dir, self.raw_dir):
            Path(path).mkdir(parents=True, exist_ok=True)
        if self.database_url().startswith("sqlite:///"):
            db_path = Path(self.database_url().removeprefix("sqlite:///"))
            db_path.parent.mkdir(parents=True, exist_ok=True)

    # -- loading ----------------------------------------------------------- #

    @classmethod
    def load(cls, path: str | Path | None = None) -> Settings:
        settings = cls()
        config_path = Path(path) if path else _first_existing(CONFIG_NAMES)
        if config_path and Path(config_path).is_file():
            data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
            settings.apply(data)
        settings.apply(_env_overrides())
        return settings

    def apply(self, data: dict[str, Any]) -> None:
        for key, value in (data or {}).items():
            if not hasattr(self, key) or value is None:
                continue
            current = getattr(self, key)
            if isinstance(current, Path):
                value = Path(value)
            elif isinstance(current, int) and not isinstance(current, bool):
                value = int(value)
            setattr(self, key, value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_dir": str(self.data_dir),
            "db_url": self.db_url,
            "database_url": self.database_url(),
            "api_host": self.api_host,
            "api_port": self.api_port,
            "require_auth": self.require_auth,
            "case_window_hours": self.case_window_hours,
            "min_wazuh_level": self.min_wazuh_level,
            "scan_timeout": self.scan_timeout,
            "max_body_mb": self.max_body_mb,
            "sigma_path": str(self.sigma_path),
            "atomic_path": str(self.atomic_path),
            "cheatsheet_path": str(self.cheatsheet_path),
            "rules_dir": str(self.rules_dir),
            "reports_dir": str(self.reports_dir),
            "raw_dir": str(self.raw_dir),
        }


def _first_existing(names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return candidate
    return None


def _env_overrides() -> dict[str, Any]:
    mapping = {
        "DB_URL": "db_url",
        "DATA_DIR": "data_dir",
        "HOST": "api_host",
        "PORT": "api_port",
        "CASE_WINDOW_HOURS": "case_window_hours",
        "MIN_WAZUH_LEVEL": "min_wazuh_level",
        "SCAN_TIMEOUT": "scan_timeout",
        "SIGMA_PATH": "sigma_path",
        "ATOMIC_PATH": "atomic_path",
        "CHEATSHEET_PATH": "cheatsheet_path",
    }
    out: dict[str, Any] = {}
    for env_name, attr in mapping.items():
        value = os.environ.get(f"{ENV_PREFIX}{env_name}")
        if value:
            out[attr] = value

    truthy = {"1", "true", "yes", "on"}
    auth = os.environ.get(f"{ENV_PREFIX}REQUIRE_AUTH")
    if auth is not None:
        out["require_auth"] = auth.strip().lower() in truthy
    return out
