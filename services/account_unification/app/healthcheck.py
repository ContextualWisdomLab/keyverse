"""Container healthcheck: ``python -m app.healthcheck``.

Exits 0 when the local service answers /healthz with status ok, else 1.
Uses only the stdlib so it works inside a minimal image.
"""
from __future__ import annotations

import json
import sys
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8099/healthz"


def main(url: str = DEFAULT_URL) -> int:
    """Check the configured health endpoint and return a shell status code."""
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- container healthcheck against a hardcoded loopback default (127.0.0.1); any override is a deployment-controlled target, not user input.
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
            body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # pragma: no cover - network failure path
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1
    if body.get("status") == "ok":
        print("ok")
        return 0
    print(f"not ready: {body}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
