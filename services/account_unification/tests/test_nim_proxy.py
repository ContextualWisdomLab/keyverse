"""Security-boundary tests for the loopback NVIDIA NIM credential broker."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _repository_root() -> Path:
    """Return the Keyverse repository root from this test module."""
    return Path(__file__).resolve().parents[3]


def _load_proxy() -> ModuleType:
    """Load the repository-local proxy without making scripts a package."""
    path = _repository_root() / "scripts" / "ci" / "nim_proxy.py"
    spec = importlib.util.spec_from_file_location("keyverse_nim_proxy", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_proxy_accepts_only_unambiguous_nim_v1_paths() -> None:
    """Absolute URLs, traversal, nested escapes, and controls never reach NIM."""
    proxy = _load_proxy()

    assert proxy._validate_path("/v1/chat/completions") == "/v1/chat/completions"
    assert proxy._validate_path("/v1/models?limit=10") == "/v1/models?limit=10"

    unsafe_paths = (
        "https://attacker.example/v1/chat/completions",
        "/v1/../secrets",
        "/v1/%2e%2e/secrets",
        "/v1/%252fsecrets",
        "/v1/%2fsecrets",
        "/v1/%00",
        "/v2/chat/completions",
        "/healthz?forward=true",
    )
    for path in unsafe_paths:
        with pytest.raises(proxy.ProxyConfigurationError):
            proxy._validate_path(path)


def test_proxy_rejects_missing_or_unsafe_credentials() -> None:
    """The broker refuses empty, whitespace-bearing, or control-bearing keys."""
    proxy = _load_proxy()

    for api_key in ("", "contains space", "line\nbreak", "tab\tvalue", "del\x7f"):
        with pytest.raises(proxy.ProxyConfigurationError):
            proxy.NimUpstreamClient(api_key)

    client = proxy.NimUpstreamClient("valid-nim-key")
    assert "valid-nim-key" not in repr(client)


def test_proxy_binds_only_to_ipv4_loopback_and_bounds_concurrency() -> None:
    """The credential broker cannot listen on an externally reachable address."""
    proxy = _load_proxy()

    server = proxy.create_server("valid-nim-key", host="127.0.0.1", port=0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()

    for host in ("0.0.0.0", "::1", "localhost"):
        with pytest.raises(proxy.ProxyConfigurationError):
            proxy.create_server("valid-nim-key", host=host, port=0)
    for concurrency in (0, -1, True):
        with pytest.raises(proxy.ProxyConfigurationError):
            proxy.create_server(
                "valid-nim-key",
                host="127.0.0.1",
                port=0,
                max_concurrency=concurrency,
            )


def test_proxy_sanitizes_forwarded_header_values() -> None:
    """Untrusted upstream and caller header text cannot inject response headers."""
    proxy = _load_proxy()

    assert proxy._safe_header("application/json", "fallback") == "application/json"
    assert proxy._safe_header("bad\r\nInjected: yes", "fallback") == "fallback"
    assert proxy._safe_header(None, "fallback") == "fallback"
    assert proxy._safe_header("x" * 513, "fallback") == "fallback"
