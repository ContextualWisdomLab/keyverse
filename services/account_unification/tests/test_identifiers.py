"""Path-segment identifier validation blocks Admin REST path traversal."""
from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.identifiers import (  # noqa: E402
    InvalidIdentifierError,
    validate_path_segment,
)
from app.keycloak_client import HttpAdminApi  # noqa: E402


@pytest.mark.parametrize(
    "bad_value",
    [
        "",
        ".",
        "..",
        "../victim",
        "a/b",
        "a\\b",
        "%2e%2e",
        "a%2fb",
        "line\nbreak",
        "null\x00byte",
    ],
)
def test_validate_path_segment_rejects_unsafe(bad_value):
    with pytest.raises(InvalidIdentifierError):
        validate_path_segment(bad_value, field_name="user_id")


def test_validate_path_segment_accepts_uuid_and_slug():
    assert validate_path_segment("f70ac86c-dbc9-4b55-bace-c3486827a136") == (
        "f70ac86c-dbc9-4b55-bace-c3486827a136"
    )
    assert validate_path_segment("employer-adfs") == "employer-adfs"


def test_admin_client_guard_rejects_traversal_before_request():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(200, json={"id": "x"})

    api = HttpAdminApi(
        server_url="http://keycloak.test",
        realm="cwl",
        client_id="account-unification-svc",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    )

    # A traversal id must be rejected before any user request is issued.
    with pytest.raises(InvalidIdentifierError):
        api.get_user("../users/victim")
    assert not any("victim" in path for path in seen)


def test_admin_client_allows_safe_id():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(200, json={"id": "safe-id", "username": "u"})

    api = HttpAdminApi(
        server_url="http://keycloak.test",
        realm="cwl",
        client_id="account-unification-svc",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    )
    user = api.get_user("safe-id")
    assert user.user_id == "safe-id"
