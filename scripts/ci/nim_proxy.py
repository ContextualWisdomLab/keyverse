"""Loopback-only credential broker for NVIDIA NIM agent requests.

The autonomous model receives a non-secret placeholder key and talks only to
this local server. The broker injects the real NIM credential into a fixed
upstream host, strips caller-controlled authorization, bounds request and
response sizes, and never logs prompt or response content.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import ssl
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final
from urllib.parse import unquote

UPSTREAM_HOST: Final = "integrate.api.nvidia.com"
DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 8765
MAX_REQUEST_BYTES: Final = 16 * 1024 * 1024
MAX_RESPONSE_BYTES: Final = 32 * 1024 * 1024
MAX_PATH_CHARACTERS: Final = 4096
_PATH_RE = re.compile(r"^/v1(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?$")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PATH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_HEADER_RE = re.compile(r"^[\x20-\x7e]{1,512}$")
_REAL_HTTPS_CONNECTION = http.client.HTTPSConnection


class ProxyConfigurationError(ValueError):
    """Raised when the local proxy cannot enforce its fixed trust boundary."""


class UpstreamProxyError(RuntimeError):
    """Raised when the fixed NIM upstream cannot return a bounded response."""


@dataclass(frozen=True, slots=True)
class UpstreamResult:
    """A bounded upstream response ready for the loopback HTTP handler."""

    status: int
    reason: str
    content_type: str
    cache_control: str | None
    body: bytes


def _safe_header(value: str | None, default: str) -> str:
    """Return one bounded visible-ASCII header value or a safe default."""
    if value is None or _SAFE_HEADER_RE.fullmatch(value) is None:
        return default
    return value


def _validate_path(path: str) -> str:
    """Return one unambiguous fixed-upstream API target or reject it."""
    if len(path) > MAX_PATH_CHARACTERS or _PATH_RE.fullmatch(path) is None:
        raise ProxyConfigurationError("request path is outside the NVIDIA NIM v1 API")
    if _INVALID_PERCENT_ESCAPE_RE.search(path) is not None:
        raise ProxyConfigurationError("request path contains malformed percent encoding")

    path_component = path.partition("?")[0]
    for segment in path_component.split("/"):
        try:
            decoded = unquote(segment, errors="strict")
        except UnicodeDecodeError as exc:
            raise ProxyConfigurationError(
                "request path contains invalid percent-encoded UTF-8"
            ) from exc
        routing_segment = decoded.partition(";")[0]
        if routing_segment in {".", ".."}:
            raise ProxyConfigurationError("request path contains a dot segment")
        if any(separator in decoded for separator in ("/", "\\", "%")):
            raise ProxyConfigurationError(
                "request path contains an encoded separator or nested escape"
            )
        if _PATH_CONTROL_RE.search(decoded) is not None:
            raise ProxyConfigurationError("request path contains an encoded control")
    return path


def _open_https_connection(context: ssl.SSLContext) -> http.client.HTTPSConnection:
    """Create the verified fixed-host connection or an injected test transport."""
    factory = http.client.HTTPSConnection
    if factory is _REAL_HTTPS_CONNECTION:
        return factory(UPSTREAM_HOST, 443, timeout=180, context=context)
    return factory(UPSTREAM_HOST, 443, timeout=180)


class NimUpstreamClient:
    """Forward bounded requests to the one configured NVIDIA NIM endpoint."""

    def __init__(self, api_key: str) -> None:
        """Store one non-empty credential without exposing it through repr output."""
        invalid_character = any(
            ord(character) < 33 or ord(character) == 127 for character in api_key
        )
        if not api_key or invalid_character:
            raise ProxyConfigurationError(
                "NIM API key is missing or contains unsafe characters"
            )
        self._api_key = api_key

    def request(
        self,
        method: str,
        path: str,
        body: bytes,
        request_headers: Mapping[str, str],
    ) -> UpstreamResult:
        """Forward one GET or POST and buffer a bounded upstream response."""
        if method not in {"GET", "POST"}:
            raise ProxyConfigurationError("only GET and POST requests are supported")
        safe_path = _validate_path(path)
        if len(body) > MAX_REQUEST_BYTES:
            raise ProxyConfigurationError("request body exceeded the proxy byte limit")

        content_type = _safe_header(
            request_headers.get("Content-Type"), "application/json"
        )
        accept = _safe_header(request_headers.get("Accept"), "application/json")
        tls_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = _open_https_connection(tls_context)
        try:
            connection.request(
                method,
                safe_path,
                body=body if method == "POST" else None,
                headers={
                    "Accept": accept,
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": content_type,
                    "User-Agent": "Keyverse-NIM-Broker/1",
                },
            )
            response = connection.getresponse()
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise UpstreamProxyError("NIM response exceeded the proxy byte limit")
            return UpstreamResult(
                status=response.status,
                reason=_safe_header(response.reason, "NIM response"),
                content_type=_safe_header(
                    response.getheader("Content-Type"), "application/json"
                ),
                cache_control=(
                    _safe_header(response.getheader("Cache-Control"), "no-store")
                    if response.getheader("Cache-Control") is not None
                    else None
                ),
                body=response_body,
            )
        except (OSError, http.client.HTTPException) as exc:
            raise UpstreamProxyError("NVIDIA NIM upstream request failed") from exc
        finally:
            connection.close()


class NimProxyServer(ThreadingHTTPServer):
    """A loopback HTTP server carrying one fixed-upstream NIM client."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        client: NimUpstreamClient,
        max_concurrency: int = 4,
    ) -> None:
        """Bind only to loopback and initialize a bounded request semaphore."""
        host, _port = address
        if host != DEFAULT_HOST:
            raise ProxyConfigurationError("NIM broker must bind to IPv4 loopback")
        invalid_concurrency = (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or max_concurrency <= 0
        )
        if invalid_concurrency:
            raise ProxyConfigurationError(
                "max_concurrency must be a positive integer"
            )
        self.client = client
        self.request_slots = threading.BoundedSemaphore(max_concurrency)
        super().__init__(address, NimProxyHandler)


class NimProxyHandler(BaseHTTPRequestHandler):
    """Handle loopback health, GET, and POST requests without content logging."""

    protocol_version = "HTTP/1.1"
    server_version = "KeyverseNimBroker/1"
    sys_version = ""

    @property
    def nim_server(self) -> NimProxyServer:
        """Return the typed server instance for this handler."""
        if not isinstance(self.server, NimProxyServer):
            raise ProxyConfigurationError("handler is attached to an invalid server")
        return self.server

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress default request logging so prompts never enter Actions logs."""

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        """Send one bounded response with explicit anti-cache and framing headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def _send_error_json(self, status: int, message: str) -> None:
        """Send a fixed-shape JSON error without upstream or credential details."""
        payload = json.dumps({"error": message}, separators=(",", ":")).encode()
        self._send(status, payload, "application/json")

    def _read_body(self) -> bytes:
        """Read a non-chunked body while enforcing the configured byte limit."""
        if self.headers.get("Transfer-Encoding") is not None:
            raise ProxyConfigurationError("chunked request bodies are not accepted")
        raw_length = self.headers.get("Content-Length")
        if self.command == "GET" and raw_length is None:
            return b""
        if raw_length is None:
            raise ProxyConfigurationError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ProxyConfigurationError("Content-Length is invalid") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ProxyConfigurationError("request body exceeded the proxy byte limit")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ProxyConfigurationError("request body ended before Content-Length")
        return body

    def _forward(self) -> None:
        """Forward one bounded request while limiting concurrent upstream calls."""
        try:
            path = _validate_path(self.path)
            body = self._read_body()
        except ProxyConfigurationError as exc:
            self._send_error_json(400, str(exc))
            return

        if not self.nim_server.request_slots.acquire(blocking=False):
            self._send_error_json(429, "NIM broker concurrency limit reached")
            return
        try:
            result = self.nim_server.client.request(
                self.command,
                path,
                body,
                {key: value for key, value in self.headers.items()},
            )
        except (ProxyConfigurationError, UpstreamProxyError):
            self._send_error_json(502, "NVIDIA NIM upstream request failed")
            return
        finally:
            self.nim_server.request_slots.release()

        self.send_response(result.status, result.reason)
        self.send_header("Content-Type", result.content_type)
        self.send_header("Content-Length", str(len(result.body)))
        self.send_header("Cache-Control", result.cache_control or "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(result.body)
        self.close_connection = True

    def do_GET(self) -> None:
        """Serve health locally or forward one bounded NIM GET request."""
        if self.path == "/healthz":
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return
        self._forward()

    def do_POST(self) -> None:
        """Forward one bounded NIM POST request."""
        self._forward()

    def do_HEAD(self) -> None:
        """Return health metadata without a response body."""
        if self.path == "/healthz":
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return
        self._send_error_json(405, "method not allowed")

    def do_PUT(self) -> None:
        """Reject unsupported mutation methods."""
        self._send_error_json(405, "method not allowed")

    do_PATCH = do_PUT
    do_DELETE = do_PUT
    do_OPTIONS = do_PUT


def create_server(
    api_key: str,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    max_concurrency: int = 4,
) -> NimProxyServer:
    """Create a loopback broker with validated address and concurrency settings."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65_535:
        raise ProxyConfigurationError("port must be an integer from 0 through 65535")
    return NimProxyServer(
        (host, port), NimUpstreamClient(api_key), max_concurrency=max_concurrency
    )


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser for the loopback broker."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--api-key-env", default="NIM_UPSTREAM_API_KEY")
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate configuration and optionally serve until the process is stopped."""
    args = _parser().parse_args(argv)
    api_key = os.environ.get(args.api_key_env, "")
    try:
        server = create_server(api_key, host=args.host, port=args.port)
    except (OSError, ProxyConfigurationError) as exc:
        print(f"nim proxy: {exc}", file=sys.stderr)
        return 2
    if args.check:
        server.server_close()
        return 0
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
