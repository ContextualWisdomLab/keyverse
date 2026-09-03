"""Path-segment validation blocks Keycloak Admin REST route confusion."""
from __future__ import annotations

import httpx
import pytest

from app.identifiers import (
    InvalidIdentifierError,
    validate_path_segment,
)
from app.product_keycloak_client import ProductHttpAdminApi


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
        "a?admin=true",
        "a#fragment",
        "line\nbreak",
        "null\x00byte",
    ],
)
def test_validate_path_segment_rejects_unsafe(bad_value):
    """Unsafe path and URI syntax is rejected as an opaque identifier."""
    with pytest.raises(InvalidIdentifierError):
        validate_path_segment(bad_value, field_name="user_id")


def test_validate_path_segment_accepts_uuid_and_slug():
    """Expected Keycloak UUID and slug identifiers remain valid."""
    assert validate_path_segment(
        "f70ac86c-dbc9-4b55-bace-c3486827a136"
    ) == "f70ac86c-dbc9-4b55-bace-c3486827a136"
    assert validate_path_segment("employer-adfs") == "employer-adfs"


def test_product_admin_client_rejects_cleartext_server_url():
    """Product credentials cannot be bound to a cleartext Keycloak origin."""
    with pytest.raises(ValueError, match="server_url must be an absolute HTTPS URI"):
        ProductHttpAdminApi(
            server_url="http://keycloak.test",
            realm="cwl",
            client_id="account-unification-svc",
            client_secret="secret",
            transport=httpx.MockTransport(
                lambda request: pytest.fail(f"unexpected request: {request.url}")
            ),
        )


def test_product_admin_client_rejects_route_confusion_before_request():
    """An extra path segment cannot change the intended Admin REST operation."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(200, json={"id": "x"})

    api = ProductHttpAdminApi(
        server_url="https://keycloak.test",
        realm="cwl",
        client_id="account-unification-svc",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    )
    api._token = "t"

    with pytest.raises(InvalidIdentifierError):
        api.get_user("victim/federated-identity")
    assert seen == []


def test_product_admin_client_allows_safe_id():
    """A safe opaque user id reaches exactly the intended endpoint."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(
            200,
            json={"id": "safe-id", "username": "u"},
        )

    api = ProductHttpAdminApi(
        server_url="https://keycloak.test",
        realm="cwl",
        client_id="account-unification-svc",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    )
    api._token = "t"

    user = api.get_user("safe-id")

    assert user.user_id == "safe-id"
    assert seen == ["/admin/realms/cwl/users/safe-id"]
