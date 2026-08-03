"""Container healthcheck command behavior."""
from __future__ import annotations

import urllib.request

from app import healthcheck


class _Response:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def test_healthcheck_returns_zero_for_ok_status(monkeypatch, capsys):
    def fake_open(url: str) -> _Response:
        assert url == "http://service/healthz"
        return _Response(b'{"status":"ok"}')

    monkeypatch.setattr(healthcheck, "_open_health_url", fake_open)

    assert healthcheck.main("http://service/healthz") == 0
    assert capsys.readouterr().out == "ok\n"


def test_healthcheck_returns_one_for_non_ok_status(monkeypatch, capsys):
    def fake_open(url: str) -> _Response:
        return _Response(b'{"status":"starting"}')

    monkeypatch.setattr(healthcheck, "_open_health_url", fake_open)

    assert healthcheck.main("http://service/healthz") == 1
    assert "not ready" in capsys.readouterr().err


def test_healthcheck_returns_one_for_request_error(monkeypatch, capsys):
    def fake_open(url: str) -> _Response:
        raise OSError("connection refused")

    monkeypatch.setattr(healthcheck, "_open_health_url", fake_open)

    assert healthcheck.main("http://service/healthz") == 1
    assert "healthcheck failed: connection refused" in capsys.readouterr().err


def test_healthcheck_rejects_non_http_scheme(monkeypatch, capsys):
    """A non-HTTP(S) URL is rejected before urllib ever opens it."""
    def fail_open(*args: object, **kwargs: object) -> _Response:
        raise AssertionError("the opener must not run for a rejected scheme")

    monkeypatch.setattr(healthcheck, "_open_health_url", fail_open)

    assert healthcheck.main("file:///etc/passwd") == 1
    assert "unsupported URL scheme 'file'" in capsys.readouterr().err


def test_healthcheck_opener_drops_non_http_redirect_target():
    """A ``http:// -> ftp://`` redirect is dropped, and no ftp/file handler exists."""
    handler = healthcheck._HttpOnlyRedirectHandler()
    dropped = handler.redirect_request(
        urllib.request.Request("http://127.0.0.1:8099/healthz"),
        None,
        302,
        "Found",
        {},
        "ftp://127.0.0.1/secret",
    )
    assert dropped is None
    # A same-scheme redirect is still honoured (returns a Request, not None).
    kept = handler.redirect_request(
        urllib.request.Request("http://127.0.0.1:8099/healthz"),
        None,
        302,
        "Found",
        {},
        "http://127.0.0.1:8099/ready",
    )
    assert kept is not None
    # The opener carries no protocol handler that could open ftp/file targets.
    opener = healthcheck._build_http_only_opener()
    assert not any(
        type(h).__name__ in {"FTPHandler", "FileHandler", "DataHandler"}
        for h in opener.handlers
    )
