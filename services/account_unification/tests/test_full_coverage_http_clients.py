"""Coverage regressions for core and product Keycloak HTTP adapters."""
from __future__ import annotations

from types import MethodType

import httpx
import pytest

from app.identifiers import InvalidIdentifierError
from app.keycloak_client import HttpAdminApi, _parse_user
from app.models import UserAccount
from app.product_keycloak_client import ProductHttpAdminApi


def _token_response(request: httpx.Request) -> httpx.Response | None:
    """Return a deterministic bearer token for token endpoint requests."""
    if request.url.path.endswith("/protocol/openid-connect/token"):
        return httpx.Response(200, json={"access_token": "coverage-token"})
    return None


def test_core_username_lookup_returns_none_without_exact_match() -> None:
    """Username lookup ignores inexact Keycloak search results."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Return one nonmatching user after authenticating."""
        token = _token_response(request)
        if token is not None:
            return token
        return httpx.Response(
            200,
            json=[{"id": "u1", "username": "different-user"}],
        )

    api = HttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    assert api.find_user_by_username("missing-user") is None
    api.close()


def test_core_create_user_falls_back_to_username_lookup() -> None:
    """A create response without Location falls back to exact username lookup."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Create without Location and return the user on lookup."""
        token = _token_response(request)
        if token is not None:
            return token
        if request.method == "POST":
            return httpx.Response(201)
        return httpx.Response(
            200,
            json=[{"id": "created-id", "username": "new-user"}],
        )

    api = HttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    assert api.create_user(
        UserAccount(user_id="", user_name="new-user")
    ) == "created-id"
    api.close()


def test_core_create_user_returns_empty_when_fallback_lookup_misses() -> None:
    """A create response without Location or exact lookup returns an empty ID."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Create without Location and return no lookup result."""
        token = _token_response(request)
        if token is not None:
            return token
        if request.method == "POST":
            return httpx.Response(201)
        return httpx.Response(200, json=[])

    api = HttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    assert api.create_user(
        UserAccount(user_id="", user_name="missing-user")
    ) == ""
    api.close()


@pytest.mark.parametrize(
    ("attribute_value", "expected"),
    [
        ([], None),
        ("survivor", "survivor"),
        ({"unexpected": "shape"}, None),
    ],
)
def test_core_user_attribute_handles_all_keycloak_shapes(
    attribute_value,
    expected: str | None,
) -> None:
    """Attribute reads handle empty lists, bare strings, and invalid shapes."""
    api = object.__new__(HttpAdminApi)

    def fake_get(self, path: str, params=None):
        """Return the configured attribute representation."""
        return {"attributes": {"merged_into_user_id": attribute_value}}

    api._get = MethodType(fake_get, api)

    assert api.get_user_attribute(
        "user-1", "merged_into_user_id"
    ) == expected


def test_core_transport_helpers_cover_json_empty_and_mutating_responses() -> None:
    """The base adapter's authenticated HTTP helpers cover every response path."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return deterministic responses for every base transport helper."""
        calls.append(request)
        token = _token_response(request)
        if token is not None:
            return token
        if request.method == "GET":
            return httpx.Response(200, json={"ok": True})
        if request.method == "POST" and request.url.path.endswith("/json"):
            return httpx.Response(200, json={"created": True})
        return httpx.Response(204)

    api = HttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    assert api._get("/admin/realms/cwl/users") == {"ok": True}
    assert api._post("/admin/realms/cwl/json", {"value": 1}) == {
        "created": True
    }
    assert api._post("/admin/realms/cwl/empty", {}) == {}
    api._put("/admin/realms/cwl/users/u1", {"enabled": False})
    api._delete("/admin/realms/cwl/users/u1", body={"reason": "test"})
    api.close()

    assert {request.method for request in calls} >= {
        "GET",
        "POST",
        "PUT",
        "DELETE",
    }


def test_parse_user_handles_empty_external_identifier_list() -> None:
    """An empty Keycloak external-ID list becomes no domain external ID."""
    user = _parse_user(
        {
            "id": "u1",
            "enabled": False,
            "attributes": {"scim_external_id": []},
        }
    )

    assert user.state == "disabled"
    assert user.external_id is None


def test_product_constructor_rejects_unsafe_token_realm() -> None:
    """A dedicated token realm remains one safe opaque path segment."""
    with pytest.raises(InvalidIdentifierError):
        ProductHttpAdminApi(
            "https://keycloak.example",
            "cwl",
            "service-client",
            "secret",
            token_realm="../master",
        )


@pytest.mark.parametrize(
    "path",
    [
        "admin/realms/cwl/users",
        "/admin/realms/cwl/users%2Fu1",
        "/admin/realms/cwl//users",
        "/admin/realms/cwl/users/line\nbreak",
        "/admin/realms/other/users",
        "/admin/realms/cwl/server-info",
    ],
)
def test_product_guard_rejects_every_unsafe_path_class(path: str) -> None:
    """The product transport accepts only reviewed Admin REST route shapes."""
    api = ProductHttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(500, request=request)
        ),
    )

    with pytest.raises(InvalidIdentifierError):
        api._guard_path(path)

    api.close()


def test_product_create_user_fallback_returns_found_and_missing_ids() -> None:
    """The hardened create fallback validates found IDs and permits no result."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Create without a Location header and return no transport lookup data."""
        token = _token_response(request)
        if token is not None:
            return token
        if request.method == "POST":
            return httpx.Response(201)
        return httpx.Response(200, json=[])

    api = ProductHttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )
    found = UserAccount(user_id="found-id", user_name="new-user")

    api.find_user_by_username = MethodType(
        lambda self, username: found,
        api,
    )
    assert api.create_user(
        UserAccount(user_id="", user_name="new-user")
    ) == "found-id"

    api.find_user_by_username = MethodType(
        lambda self, username: None,
        api,
    )
    assert api.create_user(
        UserAccount(user_id="", user_name="missing-user")
    ) == ""
    api.close()


def test_product_identity_provider_handles_dict_non_dict_and_non_404() -> None:
    """Identity-provider reads preserve dicts, ignore other JSON, and rethrow errors."""
    responses = iter(
        [
            httpx.Response(200, json={"alias": "provider"}),
            httpx.Response(200, json=[{"alias": "provider"}]),
            httpx.Response(503),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        """Authenticate once and then return the configured sequence."""
        token = _token_response(request)
        if token is not None:
            return token
        response = next(responses)
        response.request = request
        return response

    api = ProductHttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    assert api.get_identity_provider("provider") == {"alias": "provider"}
    assert api.get_identity_provider("provider") is None
    with pytest.raises(httpx.HTTPStatusError) as error:
        api.get_identity_provider("provider")
    assert error.value.response.status_code == 503
    api.close()
