from __future__ import annotations

import pytest

from p4b.canon.assets import asset_for, normalize_key


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("host", "WIN-DC01.", "win-dc01"),
        ("host", " app.acme.io ", "app.acme.io"),
        ("ip", "10.0.4.31", "10.0.4.31"),
        ("ip", "10.0.4.31:445", "10.0.4.31"),
        ("ip", "[2001:db8::1]:443", "2001:db8::1"),
        ("url", "https://App.ACME.io/api/login", "app.acme.io"),
        ("url", "http://203.0.113.9:8080/x", "203.0.113.9"),
        ("image", "acme/payments-api:1.8.2", "acme/payments-api:1.8.2"),
        ("image", "acme/payments-api@sha256:deadbeef", "acme/payments-api"),
        ("repo", "https://github.com/acme/payments-api.git", "github.com/acme/payments-api"),
        ("repo", "git@github.com:acme/payments-api.git", "github.com/acme/payments-api"),
        ("repo", "https://token@github.com/acme/x", "github.com/acme/x"),
    ],
)
def test_normalize_key(kind, raw, expected):
    assert normalize_key(kind, raw) == expected


def test_image_tag_is_part_of_the_key_but_digest_is_not():
    tagged = normalize_key("image", "acme/api:1.8.2")
    digest = normalize_key("image", "acme/api@sha256:" + "a" * 64)
    assert tagged != digest
    assert digest == "acme/api"


def test_asset_infers_exposure():
    assert asset_for("url", "https://app.acme.io").exposure == "internet"
    assert asset_for("image", "acme/api:1").exposure == "container"
    assert asset_for("repo", "github.com/acme/x").exposure == "repo"
    assert asset_for("host", "WIN-DC01").exposure == "internal"


def test_asset_fills_ip_from_ip_key():
    asset = asset_for("ip", "10.0.4.31")
    assert asset.ip == "10.0.4.31"


def test_unknown_kind_falls_back():
    asset = asset_for("nonsense", "x")
    assert asset.kind == "unknown"
