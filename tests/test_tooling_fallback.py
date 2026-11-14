from __future__ import annotations

from p4b import tooling


def test_resolve_binary_prefers_path(monkeypatch):
    monkeypatch.setattr(tooling.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert tooling.resolve_binary("zeek") == "/usr/bin/zeek"


def test_resolve_binary_falls_back_to_known_locations(monkeypatch, tmp_path):
    fake = tmp_path / "zeek"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(tooling.shutil, "which", lambda name: None)
    monkeypatch.setitem(tooling.FALLBACK_PATHS, "zeek", (str(fake),))
    assert tooling.resolve_binary("zeek") == str(fake)


def test_resolve_binary_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(tooling.shutil, "which", lambda name: None)
    monkeypatch.setitem(tooling.FALLBACK_PATHS, "zeek", ("/nonexistent/zeek",))
    assert tooling.resolve_binary("zeek") is None


def test_detect_reports_the_fallback_path(monkeypatch):
    import sys

    # A real executable (the test interpreter) so version parsing is exercised on
    # every platform; the point of the test is the fallback path, not the binary.
    fake = tooling.ToolSpec(
        "zeek",
        "telemetry",
        "zeek/zeek",
        "python",
        "BSD-3-Clause",
        ("-c", "print('zeek version 9.0.1')"),
    )
    monkeypatch.setattr(tooling.shutil, "which", lambda name: None)
    monkeypatch.setitem(tooling.FALLBACK_PATHS, "python", (sys.executable,))

    row = tooling.detect(fake)
    assert row["available"] is True
    assert row["path"] == sys.executable
    assert row["version"] == "9.0.1"
