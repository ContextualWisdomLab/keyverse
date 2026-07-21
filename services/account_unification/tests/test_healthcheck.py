"""Container healthcheck command behavior."""
from __future__ import annotations

from app import healthcheck


class _Response:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


class _Connection:
    """Recorded stand-in for the explicit plain-HTTP probe client."""

    last: "_Connection | None" = None

    def __init__(
        self, host: str, port: int, timeout: int, payload: bytes, error: Exception | None
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requested_path: str | None = None
        self.closed = False
        self._payload = payload
        self._error = error
        _Connection.last = self

    def request(self, method: str, path: str) -> None:
        assert method == "GET"
        self.requested_path = path
        if self._error is not None:
            raise self._error

    def getresponse(self) -> _Response:
        return _Response(self._payload)

    def close(self) -> None:
        self.closed = True


def _patch_connection(
    monkeypatch, payload: bytes = b"{}", error: Exception | None = None
) -> None:
    def factory(host: str, port: int, timeout: int) -> _Connection:
        return _Connection(host, port, timeout, payload, error)

    monkeypatch.setattr(healthcheck.http.client, "HTTPConnection", factory)


def test_healthcheck_returns_zero_for_ok_status(monkeypatch, capsys):
    _patch_connection(monkeypatch, payload=b'{"status":"ok"}')

    assert healthcheck.main("http://service/healthz") == 0
    assert capsys.readouterr().out == "ok\n"
    connection = _Connection.last
    assert connection is not None
    assert (connection.host, connection.port) == ("service", 80)
    assert connection.timeout == 5
    assert connection.requested_path == "/healthz"
    assert connection.closed is True


def test_healthcheck_returns_one_for_non_ok_status(monkeypatch, capsys):
    _patch_connection(monkeypatch, payload=b'{"status":"starting"}')

    assert healthcheck.main("http://service/healthz") == 1
    assert "not ready" in capsys.readouterr().err


def test_healthcheck_returns_one_for_request_error(monkeypatch, capsys):
    _patch_connection(monkeypatch, error=OSError("connection refused"))

    assert healthcheck.main("http://service/healthz") == 1
    assert "healthcheck failed: connection refused" in capsys.readouterr().err


def test_healthcheck_rejects_non_http_probe_schemes(monkeypatch, capsys):
    # The probe must never act as a broad URL opener: file:// and other
    # schemes are refused before any request is issued.
    def unexpected_factory(*args: object, **kwargs: object) -> None:
        raise AssertionError("no connection may be opened for non-http URLs")

    monkeypatch.setattr(healthcheck.http.client, "HTTPConnection", unexpected_factory)

    assert healthcheck.main("file:///etc/passwd") == 1
    assert "unsupported probe url" in capsys.readouterr().err
