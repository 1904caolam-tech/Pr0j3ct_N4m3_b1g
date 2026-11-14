#!/usr/bin/env python3
"""Wazuh integratord -> P4B shipper.

Wazuh calls integration scripts for alerts above a configured level. The alert
arrives either as a file path in argv[1] (integratord's usual contract) or on stdin;
both are accepted so the script works across Wazuh versions and manual tests.

Environment:
  P4B_URL    base URL of the P4B API       (default http://192.168.56.10:8080)
  P4B_TOKEN  bearer token with write scope (optional on localhost labs)
  P4B_TIMEOUT seconds                      (default 10)

Exit codes: 0 shipped, 1 bad payload, 2 transport error. Wazuh logs the stderr line.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

P4B_URL = os.environ.get("P4B_URL", "http://192.168.56.10:8080").rstrip("/")
P4B_TOKEN = os.environ.get("P4B_TOKEN", "")
TIMEOUT = float(os.environ.get("P4B_TIMEOUT", "10"))


def read_alert() -> str:
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], encoding="utf-8") as handle:
            return handle.read()
    return sys.stdin.read()


def ship(raw: str) -> int:
    try:
        payload = json.loads(raw)
    except ValueError:
        print("p4b-shipper: alert is not valid JSON", file=sys.stderr)
        return 1

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if P4B_TOKEN:
        headers["Authorization"] = f"Bearer {P4B_TOKEN}"

    request = urllib.request.Request(
        f"{P4B_URL}/api/v1/ingest/wazuh", data=body, method="POST", headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            result = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        print(f"p4b-shipper: HTTP {exc.code} from P4B", file=sys.stderr)
        return 2
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"p4b-shipper: {exc}", file=sys.stderr)
        return 2

    print(
        f"p4b-shipper: parsed={result.get('parsed', 0)} created={result.get('created', 0)}"
        f" merged={result.get('merged', 0)}"
    )
    return 0


def main() -> int:
    raw = read_alert().strip()
    if not raw:
        print("p4b-shipper: empty alert", file=sys.stderr)
        return 1
    return ship(raw)


if __name__ == "__main__":
    raise SystemExit(main())
