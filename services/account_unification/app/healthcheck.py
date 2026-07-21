"""Container healthcheck: ``python -m app.healthcheck``.

Exits 0 when the local service answers /healthz with status ok, else 1.
Uses only the stdlib so it works inside a minimal image, and deliberately
avoids the broad ``urllib.request.urlopen`` opener (which accepts ``file://``
and other schemes): the probe target is scheme-validated and requested over an
explicit plain-HTTP client because it only ever talks to the local listener.
"""
from __future__ import annotations

import http.client
import json
import sys
from urllib.parse import urlsplit

DEFAULT_URL = "http://127.0.0.1:8099/healthz"


def main(url: str = DEFAULT_URL) -> int:
    """Check the configured health endpoint and return a shell status code."""
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname:
        print(f"healthcheck failed: unsupported probe url {url!r}", file=sys.stderr)
        return 1
    try:
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port or 80, timeout=5
        )
        try:
            connection.request("GET", parsed.path or "/")
            response = connection.getresponse()
            body = json.loads(response.read().decode("utf-8"))
        finally:
            connection.close()
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
