"""Container healthcheck: ``python -m app.healthcheck``.

Exits 0 when the local service answers /healthz with status ok, else 1.
Uses only the stdlib so it works inside a minimal image.
"""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8099/healthz"
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class _HttpOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Drop redirects whose target scheme is not HTTP(S)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        """Return an HTTP(S) redirect request, or reject another scheme."""
        if urllib.parse.urlsplit(newurl).scheme.lower() not in _ALLOWED_SCHEMES:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_http_only_opener() -> urllib.request.OpenerDirector:
    """Build an opener that can speak only HTTP(S), without file/FTP handlers."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    opener.add_handler(_HttpOnlyRedirectHandler())
    # OpenerDirector has no implicit default handlers. Register this before the
    # error processor so non-2xx responses raise HTTPError instead of returning
    # ``None`` to the context manager below.
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


def _open_health_url(url: str):  # noqa: ANN202
    """Open an HTTP(S) health URL through the restricted opener."""
    return _build_http_only_opener().open(url, timeout=5)


def main(url: str = DEFAULT_URL) -> int:
    """Check the configured health endpoint and return a shell status code."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        print(f"healthcheck failed: unsupported URL scheme {scheme!r}", file=sys.stderr)
        return 1
    try:
        # The initial and redirected schemes are constrained to HTTP(S), and the
        # opener carries no handler for file, FTP, or data URLs.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with _open_health_url(url) as response:  # noqa: S310
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
