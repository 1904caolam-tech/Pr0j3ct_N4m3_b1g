from __future__ import annotations

from datetime import datetime, timezone

import pytest

from p4b.domain.models import parse_ts, to_iso


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-12T08:05:40Z",
        "2026-11-12T08:05:40.000+0000",
        "2026-11-12T08:05:40+00:00",
        "2026-11-12 08:05:40",
        1794470740.0,
    ],
)
def test_supported_dialects(value):
    parsed = parse_ts(value)
    assert parsed is not None
    assert parsed.year == 2026
    assert parsed.tzinfo is not None


def test_offset_without_colon_is_parsed():
    parsed = parse_ts("2026-11-12T08:05:40.123456+0000")
    assert parsed == datetime(2026, 11, 12, 8, 5, 40, 123456, tzinfo=timezone.utc)


def test_zeek_epoch_seconds():
    parsed = parse_ts("1794472212.512345")
    assert parsed == datetime(2026, 11, 12, 8, 30, 12, 512345, tzinfo=timezone.utc)


def test_garbage_returns_none():
    assert parse_ts("not a timestamp") is None
    assert parse_ts(None) is None
    assert parse_ts("") is None


def test_roundtrip_to_iso():
    parsed = parse_ts("2026-11-12T08:05:40+0000")
    assert to_iso(parsed) == "2026-11-12T08:05:40Z"
