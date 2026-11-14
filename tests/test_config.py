from __future__ import annotations

from pathlib import Path

from p4b.config import Settings


def test_defaults():
    settings = Settings()
    assert settings.require_auth is False
    assert settings.api_port == 8080
    assert settings.database_url().startswith("sqlite:///")


def test_yaml_file_is_loaded(tmp_path):
    config = tmp_path / "p4b.yaml"
    config.write_text(
        "api_port: 9090\nrequire_auth: true\ndata_dir: /srv/p4b\ncase_window_hours: 12\n",
        encoding="utf-8",
    )
    settings = Settings.load(config)
    assert settings.api_port == 9090
    assert settings.require_auth is True
    assert settings.data_dir == Path("/srv/p4b")
    assert settings.case_window_hours == 12


def test_environment_beats_yaml(monkeypatch, tmp_path):
    config = tmp_path / "p4b.yaml"
    config.write_text("api_port: 9090\n", encoding="utf-8")
    monkeypatch.setenv("P4B_PORT", "9100")
    monkeypatch.setenv("P4B_DB_URL", f"sqlite:///{(tmp_path / 'x.db').as_posix()}")

    settings = Settings.load(config)
    assert settings.api_port == 9100
    assert settings.database_url().endswith("x.db")


def test_require_auth_env_parsing(monkeypatch):
    monkeypatch.setenv("P4B_REQUIRE_AUTH", "true")
    assert Settings.load().require_auth is True

    monkeypatch.setenv("P4B_REQUIRE_AUTH", "off")
    assert Settings.load().require_auth is False


def test_unknown_keys_are_ignored(tmp_path):
    config = tmp_path / "p4b.yaml"
    config.write_text("not_a_setting: 1\napi_port: 8081\n", encoding="utf-8")
    settings = Settings.load(config)
    assert settings.api_port == 8081
