"""Container healthcheck command behavior."""
from __future__ import annotations

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
    def fake_urlopen(url: str, *, timeout: int) -> _Response:
        assert url == "http://service/healthz"
        assert timeout == 5
        return _Response(b'{"status":"ok"}')

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fake_urlopen)

    assert healthcheck.main("http://service/healthz") == 0
    assert capsys.readouterr().out == "ok\n"


def test_healthcheck_returns_one_for_non_ok_status(monkeypatch, capsys):
    def fake_urlopen(url: str, *, timeout: int) -> _Response:
        return _Response(b'{"status":"starting"}')

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fake_urlopen)

    assert healthcheck.main("http://service/healthz") == 1
    assert "not ready" in capsys.readouterr().err


def test_healthcheck_returns_one_for_request_error(monkeypatch, capsys):
    def fake_urlopen(url: str, *, timeout: int) -> _Response:
        raise OSError("connection refused")

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fake_urlopen)

    assert healthcheck.main("http://service/healthz") == 1
    assert "healthcheck failed: connection refused" in capsys.readouterr().err
