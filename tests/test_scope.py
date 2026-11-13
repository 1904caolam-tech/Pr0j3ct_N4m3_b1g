from __future__ import annotations

import pytest

from p4b.scan.scope import Scope, extract_host


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://app.acme.io/api/login", "app.acme.io"),
        ("app.acme.io", "app.acme.io"),
        ("APP.ACME.IO.", "app.acme.io"),
        ("10.0.4.31", "10.0.4.31"),
        ("10.0.4.31:445", "10.0.4.31"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("", ""),
    ],
)
def test_extract_host(target, expected):
    assert extract_host(target) == expected


def test_deny_by_default():
    decision = Scope().check("https://app.acme.io")
    assert decision.allowed is False
    assert "deny-by-default" in decision.reason


def test_exact_allow():
    decision = Scope(allow=("app.acme.io",)).check("https://app.acme.io/login")
    assert decision.allowed is True
    assert "allowed by rule" in decision.reason


def test_wildcard_allow():
    scope = Scope(allow=("*.acme.io",))
    assert scope.check("https://app.acme.io").allowed is True
    assert scope.check("https://deep.app.acme.io").allowed is True
    assert scope.check("https://acme.io").allowed is False
    assert scope.check("https://notacme.io").allowed is False


def test_cidr_allow():
    scope = Scope(allow=("10.0.4.0/24",))
    assert scope.check("10.0.4.20:445").allowed is True
    assert scope.check("10.0.5.20").allowed is False


def test_deny_wins_over_allow():
    scope = Scope(allow=("*.acme.io",), deny=("admin.acme.io",))
    assert scope.check("https://app.acme.io").allowed is True
    denied = scope.check("https://admin.acme.io")
    assert denied.allowed is False
    assert "denied by rule" in denied.reason


def test_metadata_endpoint_is_hard_blocked():
    scope = Scope(allow=("*",))
    for target in ("http://169.254.169.254/latest/meta-data", "http://metadata.google.internal/"):
        decision = scope.check(target)
        assert decision.allowed is False
        assert "hard-blocked" in decision.reason


def test_link_local_is_hard_blocked_even_when_allowed():
    decision = Scope(allow=("169.254.0.0/16",)).check("169.254.1.1")
    assert decision.allowed is False
    assert "hard-blocked" in decision.reason


def test_localhost_needs_an_explicit_allow():
    assert Scope().check("http://127.0.0.1:8080").allowed is False
    assert Scope(allow=("127.0.0.1",)).check("http://127.0.0.1:8080").allowed is True


def test_decision_is_serializable():
    payload = Scope(allow=("app.acme.io",)).check("https://app.acme.io").to_dict()
    assert payload["allowed"] is True
    assert isinstance(payload["reason"], str)
