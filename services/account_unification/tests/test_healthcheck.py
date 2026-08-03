"""Container healthcheck command behavior."""
from __future__ import annotations

import urllib.request

from app import healthcheck


class _Response:
    """Small context-managed HTTP response test double."""

    def __init__(self, payload: bytes) -> None:
        """Store one response payload."""
        self._payload = payload

    def __enter__(self) -> "_Response":
        """Enter the response context."""
        return self

    def __exit__(self, *args: object) -> None:
        """Exit the response context without suppressing errors."""
        return None

    def read(self) -> bytes:
        """Return the stored response payload."""
        return self._payload


def test_healthcheck_returns_zero_for_ok_status(monkeypatch, capsys) -> None:
    """A ready service produces a successful shell exit status."""

    def fake_open(url: str) -> _Response:
        """Return one ready JSON response."""
        assert url == "http://service/healthz"
        return _Response(b'{"status":"ok"}')

    monkeypatch.setattr(healthcheck, "_open_health_url", fake_open)

    assert healthcheck.main("http://service/healthz") == 0
    assert capsys.readouterr().out == "ok\n"


def test_healthcheck_returns_one_for_non_ok_status(monkeypatch, capsys) -> None:
    """A valid non-ready body produces a failed shell status."""

    def fake_open(url: str) -> _Response:
        """Return one starting JSON response."""
        return _Response(b'{"status":"starting"}')

    monkeypatch.setattr(healthcheck, "_open_health_url", fake_open)

    assert healthcheck.main("http://service/healthz") == 1
    assert "not ready" in capsys.readouterr().err


def test_healthcheck_returns_one_for_request_error(monkeypatch, capsys) -> None:
    """Transport errors are converted into a failed shell status."""

    def fake_open(url: str) -> _Response:
        """Raise one deterministic connection error."""
        raise OSError("connection refused")

    monkeypatch.setattr(healthcheck, "_open_health_url", fake_open)

    assert healthcheck.main("http://service/healthz") == 1
    assert "healthcheck failed: connection refused" in capsys.readouterr().err


def test_healthcheck_rejects_non_http_scheme(monkeypatch, capsys) -> None:
    """A non-HTTP(S) URL is rejected before urllib ever opens it."""

    def fail_open(*args: object, **kwargs: object) -> _Response:
        """Fail if a rejected scheme reaches the opener."""
        raise AssertionError("the opener must not run for a rejected scheme")

    monkeypatch.setattr(healthcheck, "_open_health_url", fail_open)

    assert healthcheck.main("file:///etc/passwd") == 1
    assert "unsupported URL scheme 'file'" in capsys.readouterr().err


def test_healthcheck_opener_drops_non_http_redirect_target() -> None:
    """A redirect cannot escape HTTP(S), file, FTP, or error boundaries."""
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
    kept = handler.redirect_request(
        urllib.request.Request("http://127.0.0.1:8099/healthz"),
        None,
        302,
        "Found",
        {},
        "http://127.0.0.1:8099/ready",
    )
    assert kept is not None
    opener = healthcheck._build_http_only_opener()
    handler_names = {type(item).__name__ for item in opener.handlers}
    assert not handler_names & {"FTPHandler", "FileHandler", "DataHandler"}
    assert "HTTPDefaultErrorHandler" in handler_names
    assert "HTTPErrorProcessor" in handler_names
