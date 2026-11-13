"""Scope enforcement for active scanning.

Nuclei sends real attack traffic. A typo in a target list must never turn into a scan
of the Internet, a cloud metadata endpoint, or a colleague's workstation. This module
is therefore deny-by-default and refuses to be clever:

* no allow entry matches  → refused
* any deny entry matches  → refused (deny wins over allow)
* hard-blocked address    → refused regardless of allow
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

# Tools that actively probe a network target. Local tools (yara, gitleaks) and
# read-only pulls (trivy) do not need a scope.
SCOPED_TOOLS = frozenset({"nuclei"})

HARD_DENY_HOSTS = frozenset(
    {
        "*",
        "0.0.0.0",
        "::",
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "169.254.170.2",    # ECS task metadata
        "fd00:ec2::254",    # IMDS over IPv6
        "metadata",
        "metadata.google.internal",
    }
)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"allowed": self.allowed, "reason": self.reason}


def extract_host(target: str) -> str:
    """Best-effort host extraction from a URL, host:port, CIDR-free hostname or IP."""
    text = (target or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        return (parsed.hostname or "").lower().rstrip(".")
    if text.startswith("["):  # [2001:db8::1]:443
        closing = text.find("]")
        return text[1:closing].lower() if closing > 0 else text[1:].lower()
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            return host.lower().rstrip(".")
    return text.lower().rstrip(".")


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_hard_denied(host: str) -> bool:
    if host in HARD_DENY_HOSTS:
        return True
    address = _as_ip(host)
    if address is None:
        return False
    return bool(
        address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def _matches(pattern: str, host: str) -> bool:
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != pattern[2:]
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
        address = _as_ip(host)
        return address is not None and address.version == network.version and address in network
    return False


@dataclass(frozen=True)
class Scope:
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()

    def check(self, target: str) -> Decision:
        host = extract_host(target)
        if not host:
            return Decision(False, "could not determine a host from the target")

        if _is_hard_denied(host):
            return Decision(False, f"hard-blocked address: {host}")

        for pattern in self.deny:
            if _matches(pattern, host):
                return Decision(False, f"denied by rule: {pattern}")

        if not self.allow:
            return Decision(False, "deny-by-default: no allow entry was provided")

        for pattern in self.allow:
            if _matches(pattern, host):
                return Decision(True, f"allowed by rule: {pattern}")

        return Decision(False, f"{host} is not in the allow list")
