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
    """Redirect handler that drops any redirect whose target scheme is not HTTP(S).

    The initial-URL scheme check does not cover a ``Location`` header, so an
    ``http:// -> ftp://`` (or ``file://``) redirect would otherwise be followed
    by whichever protocol handler the opener carries.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102
        if urllib.parse.urlsplit(newurl).scheme.lower() not in _ALLOWED_SCHEMES:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_http_only_opener() -> urllib.request.OpenerDirector:
    """Build an opener that can speak only HTTP(S) -- no ftp/file/data handlers.

    Even if a redirect target slipped past :class:`_HttpOnlyRedirectHandler`, the
    opener has no handler able to open it, so ``ftp://``/``file://`` fail closed.
    """
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    opener.add_handler(_HttpOnlyRedirectHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


def _open_health_url(url: str):  # noqa: ANN202
    """Open an HTTP(S) health URL through the scheme-restricted, ftp/file-less opener."""
    return _build_http_only_opener().open(url, timeout=5)


def main(url: str = DEFAULT_URL) -> int:
    """Check the configured health endpoint and return a shell status code."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        # Reject non-HTTP(S) schemes so a stray value can never coerce urlopen into
        # reading a local ``file://`` path or reaching another protocol handler.
        print(f"healthcheck failed: unsupported URL scheme {scheme!r}", file=sys.stderr)
        return 1
    try:
        # Internal container self-probe. Both the initial scheme (above) and any
        # redirect target are constrained to http/https, and the opener carries no
        # ftp/file handler, so this cannot reach another protocol handler.
        # nosemgrep: dynamic-urllib-use-detected
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
