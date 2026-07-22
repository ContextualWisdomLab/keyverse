"""HTTP Keycloak Admin API adapter mapping tests."""
from __future__ import annotations

import httpx

from app.keycloak_client import AdminApi, HttpAdminApi
from app.models import FederatedIdentity, GroupMembership, RoleMapping, UserAccount

from .mock_keycloak import MockKeycloakAdminApi


def test_admin_api_protocol_methods_have_concrete_implementations():
    protocol_methods = {
        name
        for name, member in AdminApi.__dict__.items()
        if callable(member) and not name.startswith("_")
    }
    assert protocol_methods
    for implementation in (HttpAdminApi, MockKeycloakAdminApi):
        missing = [
            name
            for name in sorted(protocol_methods)
            if not callable(getattr(implementation, name, None))
        ]
        assert missing == []


def test_http_admin_api_maps_keycloak_rest_calls():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "token-1"})
        if request.method == "GET" and path.endswith("/users/u1"):
            return httpx.Response(
                200,
                json={
                    "id": "u1",
                    "username": "jane",
                    "email": "jane@corp.test",
                    "emailVerified": True,
                    "enabled": True,
                    "firstName": "Jane",
                    "lastName": "Doe",
                    "attributes": {"scim_external_id": ["hr-1"]},
                },
            )
        if request.method == "GET" and path.endswith("/users"):
            return httpx.Response(
                200,
                json=[{"id": "u1", "username": "jane", "email": "jane@corp.test"}],
            )
        if request.method == "POST" and path.endswith("/users"):
            return httpx.Response(201, headers={"Location": "http://kc/admin/realms/cwl/users/u2"})
        if request.method == "GET" and path.endswith("/federated-identity"):
            return httpx.Response(
                200,
                json=[
                    {
                        "identityProvider": "adfs",
                        "userId": "jane@corp",
                        "userName": "Jane Doe",
                    }
                ],
            )
        if request.method == "GET" and path.endswith("/role-mappings"):
            return httpx.Response(
                200,
                json={
                    "realmMappings": [{"id": "realm-r", "name": "admin"}],
                    "clientMappings": {
                        "client-uuid": {
                            "id": "client-uuid",
                            "mappings": [{"id": "client-r", "name": "editor"}],
                        }
                    },
                },
            )
        if request.method == "GET" and path.endswith("/groups"):
            return httpx.Response(200, json=[{"id": "g1", "name": "Ops", "path": "/Ops"}])
        return httpx.Response(204)

    api = HttpAdminApi(
        "http://keycloak.test",
        "cwl",
        "account-unification-svc",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    user = api.get_user("u1")
    assert user.external_id == "hr-1"
    assert [u.user_id for u in api.find_users_by_email("jane@corp.test")] == ["u1"]
    assert api.find_user_by_username("Jane").user_id == "u1"
    assert api.create_user(UserAccount(user_id="", user_name="new", email="new@corp.test")) == "u2"
    api.replace_user("u1", user)

    assert api.list_federated_identities("u1") == [
        FederatedIdentity(identity_provider="adfs", external_user_id="jane@corp", external_user_name="Jane Doe")
    ]
    assert {role.role_name for role in api.list_role_mappings("u1")} == {"admin", "editor"}
    assert api.list_group_memberships("u1") == [
        GroupMembership(group_id="g1", group_name="Ops", group_path="/Ops")
    ]

    api.add_federated_identity(
        "u1", FederatedIdentity(identity_provider="github", external_user_id="jane")
    )
    api.remove_federated_identity("u1", "github")
    api.add_role_mapping("u1", RoleMapping(role_id="realm-r", role_name="admin"))
    api.add_role_mapping("u1", RoleMapping(role_id="client-r", role_name="editor", client_id="client-uuid"))
    api.remove_role_mapping("u1", RoleMapping(role_id="realm-r", role_name="admin"))
    api.remove_role_mapping("u1", RoleMapping(role_id="client-r", role_name="editor", client_id="client-uuid"))
    api.add_group_membership("u1", GroupMembership(group_id="g1", group_path="/Ops"))
    api.remove_group_membership("u1", GroupMembership(group_id="g1", group_path="/Ops"))
    api.deactivate_user("u1")
    api.set_user_attribute("u1", "duplicate_of", "survivor")
    api.close()

    assert any(call.headers.get("authorization") == "Bearer token-1" for call in calls)
    assert any(call.method == "DELETE" and call.content for call in calls)


def test_http_admin_api_reauthenticates_once_on_expired_token():
    token_requests = 0
    user_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests, user_requests
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            token_requests += 1
            return httpx.Response(200, json={"access_token": f"token-{token_requests}"})
        user_requests += 1
        # The first data call sees an expired-token 401; the retry must carry
        # a freshly fetched token and succeed.
        if request.headers.get("Authorization") == "Bearer token-0":
            return httpx.Response(401, json={"error": "invalid_token"})
        return httpx.Response(
            200,
            json={
                "id": "u1",
                "username": "jane",
                "email": "jane@corp.test",
                "emailVerified": True,
                "enabled": True,
            },
        )

    api = HttpAdminApi(
        server_url="http://keycloak.test",
        realm="cwl",
        client_id="svc",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    )
    api._token = "token-0"  # simulate a token cached before it expired

    user = api.get_user("u1")

    assert user.user_id == "u1"
    assert token_requests == 1
    assert user_requests == 2
