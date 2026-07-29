"""Container healthcheck: ``python -m app.healthcheck``.

Exits 0 when the local service answers /healthz with status ok, else 1.
Uses only the stdlib so it works inside a minimal image.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from urllib.parse import urlparse

DEFAULT_URL = "http://127.0.0.1:8099/healthz"

# The healthcheck only ever contacts the local HTTP(S) /healthz endpoint.
# Restricting the scheme keeps urllib from being pointed at the local
# filesystem via ``file://`` (the risk flagged by Semgrep
# python.lang.security.audit.dynamic-urllib-use-detected).
_ALLOWED_SCHEMES = ("http", "https")


def main(url: str = DEFAULT_URL) -> int:
    """Check the configured health endpoint and return a shell status code."""
    if urlparse(url).scheme not in _ALLOWED_SCHEMES:
        print(f"healthcheck failed: unsupported URL scheme in {url!r}", file=sys.stderr)
        return 1
    try:
        # The scheme is restricted to http(s) above and this only probes the
        # local /healthz endpoint, so the dynamic-URL audit finding is mitigated.
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
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
