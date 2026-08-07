"""Keycloak Admin REST transport tests for relying-party clients."""
from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from app.identifiers import InvalidIdentifierError
from app.relying_party_admin import RelyingPartyHttpAdminApi


def _api(
    handler: Callable[[httpx.Request], httpx.Response],
) -> RelyingPartyHttpAdminApi:
    """Return a product client backed by one deterministic mock transport."""
    api = RelyingPartyHttpAdminApi(
        server_url="https://keycloak.internal",
        realm="cwl",
        client_id="account-unification-svc",
        client_secret="private-client-value",
        timeout_seconds=5.0,
        transport=httpx.MockTransport(handler),
    )
    api._token = "cached-token"
    return api


def _client_payload() -> dict:
    """Return one closed Keycloak relying-party representation."""
    return {
        "clientId": "naruon-web",
        "name": "naruon-web",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": ["https://naruon.example/auth/callback"],
        "webOrigins": ["https://naruon.example"],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "https://naruon.example/auth/logout",
            "access.token.lifespan": "300",
            "backchannel.logout.session.required": "true",
            "require.pushed.authorization.requests": "false",
        },
        "fullScopeAllowed": False,
        "defaultClientScopes": ["basic", "profile", "email"],
    }


def test_client_list_uses_exact_query_and_authenticated_guarded_path() -> None:
    """Client discovery sends only one documented exact-ID collection query."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Record the request and return one matching client."""
        requests.append(request)
        return httpx.Response(
            200,
            json=[{"id": "client-uuid", **_client_payload()}],
            request=request,
        )

    api = _api(handler)

    clients = api.list_relying_party_clients("naruon-web")

    assert clients[0]["id"] == "client-uuid"
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "GET"
    assert request.url.path == "/admin/realms/cwl/clients"
    assert dict(request.url.params) == {
        "clientId": "naruon-web",
        "search": "false",
    }
    assert request.headers["Authorization"] == "Bearer cached-token"


def test_client_list_rejects_malformed_response_shape() -> None:
    """A non-array or non-object client response fails closed."""
    responses = iter(({"id": "not-a-list"}, ["not-an-object"]))

    def handler(request: httpx.Request) -> httpx.Response:
        """Return consecutive malformed payloads."""
        return httpx.Response(200, json=next(responses), request=request)

    api = _api(handler)
    with pytest.raises(RuntimeError):
        api.list_relying_party_clients("naruon-web")
    with pytest.raises(RuntimeError):
        api.list_relying_party_clients("naruon-web")


def test_client_create_parses_safe_location_and_tolerates_missing_location() -> None:
    """Create returns a safe UUID when present and never fabricates one."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return Location only for the first create."""
        requests.append(request)
        headers = (
            {
                "Location": (
                    "https://keycloak.internal/admin/realms/cwl/clients/"
                    "client-uuid-1"
                )
            }
            if len(requests) == 1
            else {}
        )
        return httpx.Response(201, headers=headers, request=request)

    api = _api(handler)

    first = api.create_relying_party_client(_client_payload())
    second = api.create_relying_party_client(_client_payload())

    assert first == "client-uuid-1"
    assert second is None
    assert requests[0].url.path == "/admin/realms/cwl/clients"
    assert json.loads(requests[0].content) == _client_payload()


@pytest.mark.parametrize(
    "unsafe_location",
    [
        "https://keycloak.internal/admin/realms/cwl/clients/../escape",
        "https://keycloak.internal/admin/realms/cwl/clients/client-uuid?query=1",
        "https://keycloak.internal/admin/realms/cwl/clients",
    ],
)
def test_client_create_rejects_unsafe_body_id_and_location(
    unsafe_location: str,
) -> None:
    """Unsafe public or generated identifiers never enter later transport."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return one malicious Location identifier."""
        requests.append(request)
        return httpx.Response(
            201,
            headers={"Location": unsafe_location},
            request=request,
        )

    api = _api(handler)
    unsafe_payload = _client_payload()
    unsafe_payload["clientId"] = "../escape"
    with pytest.raises(InvalidIdentifierError):
        api.create_relying_party_client(unsafe_payload)
    assert requests == []

    with pytest.raises(InvalidIdentifierError):
        api.create_relying_party_client(_client_payload())
    assert len(requests) == 1


def test_client_update_pins_id_and_delete_targets_exact_resource() -> None:
    """PUT and DELETE use one validated UUID and never trust a payload ID."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Record successful client mutations."""
        requests.append(request)
        return httpx.Response(204, request=request)

    api = _api(handler)
    payload = _client_payload()
    payload["id"] = "attacker-selected-id"

    api.update_relying_party_client("client-uuid-1", payload)
    api.delete_relying_party_client("client-uuid-1")

    assert [request.method for request in requests] == ["PUT", "DELETE"]
    assert all(
        request.url.path == "/admin/realms/cwl/clients/client-uuid-1"
        for request in requests
    )
    assert json.loads(requests[0].content)["id"] == "client-uuid-1"


@pytest.mark.parametrize(
    "client_uuid",
    ["", ".", "..", "../escape", "encoded%2fid", "query?id", "control\x00id"],
)
def test_client_update_and_delete_reject_unsafe_uuid(client_uuid: str) -> None:
    """Unsafe generated identifiers are rejected before any HTTP request."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Fail the test if transport is reached."""
        requests.append(request)
        return httpx.Response(500, request=request)

    api = _api(handler)
    with pytest.raises(InvalidIdentifierError):
        api.update_relying_party_client(client_uuid, _client_payload())
    with pytest.raises(InvalidIdentifierError):
        api.delete_relying_party_client(client_uuid)
    assert requests == []


def test_client_list_reauthenticates_exactly_once_after_401() -> None:
    """Expired bearer state is cleared and one retry uses the fresh token."""
    requests: list[httpx.Request] = []
    client_attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        """Return one client 401, one token, then one successful retry."""
        nonlocal client_attempts
        requests.append(request)
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(
                200,
                json={"access_token": "fresh-token"},
                request=request,
            )
        client_attempts += 1
        if client_attempts == 1:
            return httpx.Response(401, request=request)
        return httpx.Response(200, json=[], request=request)

    api = _api(handler)

    assert api.list_relying_party_clients("naruon-web") == []

    client_requests = [
        request for request in requests if request.url.path.endswith("/clients")
    ]
    token_requests = [
        request
        for request in requests
        if request.url.path.endswith("/protocol/openid-connect/token")
    ]
    assert len(client_requests) == 2
    assert len(token_requests) == 1
    assert client_requests[1].headers["Authorization"] == "Bearer fresh-token"


def test_adapter_preserves_inherited_routes_and_rejects_unknown_admin_paths() -> None:
    """Subclass route expansion does not weaken the parent allowlist."""
    api = _api(
        lambda request: httpx.Response(200, json={}, request=request)
    )

    assert api._guard_path("/admin/realms/cwl/users") == (
        "/admin/realms/cwl/users"
    )
    assert api._guard_path("/admin/realms/cwl/clients/client-uuid") == (
        "/admin/realms/cwl/clients/client-uuid"
    )
    with pytest.raises(InvalidIdentifierError):
        api._guard_path("/admin/realms/cwl/client-policies")
