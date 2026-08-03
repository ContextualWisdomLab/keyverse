"""Core and product Keycloak Admin REST API adapter tests."""
from __future__ import annotations

import httpx
import pytest

from app.identifiers import InvalidIdentifierError
from app.keycloak_client import AdminApi, HttpAdminApi
from app.models import (
    FederatedIdentity,
    GroupMembership,
    RoleMapping,
    UserAccount,
)
from app.product_keycloak_client import (
    ProductAdminApi,
    ProductHttpAdminApi,
)

from .mock_keycloak import MockKeycloakAdminApi
from .mock_product_keycloak import MockProductKeycloakAdminApi


def _protocol_methods(*protocols: type) -> set[str]:
    """Return all public callable methods declared by protocols."""
    return {
        name
        for protocol in protocols
        for name, member in protocol.__dict__.items()
        if callable(member) and not name.startswith("_")
    }


def test_protocol_methods_have_concrete_implementations():
    """Every declared contract method exists on both live and test adapters."""
    core_methods = _protocol_methods(AdminApi)
    product_methods = _protocol_methods(
        AdminApi, ProductAdminApi
    )
    assert core_methods
    assert product_methods
    for implementation in (
        HttpAdminApi,
        MockKeycloakAdminApi,
    ):
        assert [
            name
            for name in sorted(core_methods)
            if not callable(getattr(implementation, name, None))
        ] == []
    for implementation in (
        ProductHttpAdminApi,
        MockProductKeycloakAdminApi,
    ):
        assert [
            name
            for name in sorted(product_methods)
            if not callable(getattr(implementation, name, None))
        ] == []


def test_product_http_admin_api_maps_keycloak_calls():
    """The product adapter maps core and extended methods correctly."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        if path.endswith(
            "/protocol/openid-connect/token"
        ):
            return httpx.Response(
                200, json={"access_token": "token-1"}
            )
        if (
            request.method == "GET"
            and path.endswith("/users/u1")
        ):
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
                    "attributes": {
                        "scim_external_id": ["hr-1"],
                        "merged_into_user_id": ["survivor"],
                    },
                },
            )
        if (
            request.method == "GET"
            and path.endswith("/users")
        ):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "u1",
                        "username": "jane",
                        "email": "jane@corp.test",
                    }
                ],
            )
        if (
            request.method == "POST"
            and path.endswith("/users")
        ):
            return httpx.Response(
                201,
                headers={
                    "Location":
                        "http://kc/admin/realms/cwl/users/u2"
                },
            )
        if path.endswith("/federated-identity"):
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
        if path.endswith("/role-mappings"):
            return httpx.Response(
                200,
                json={
                    "realmMappings": [
                        {"id": "realm-r", "name": "admin"}
                    ],
                    "clientMappings": {
                        "client-uuid": {
                            "id": "client-uuid",
                            "mappings": [
                                {
                                    "id": "client-r",
                                    "name": "editor",
                                }
                            ],
                        }
                    },
                },
            )
        if path.endswith("/groups"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "g1",
                        "name": "Ops",
                        "path": "/Ops",
                    }
                ],
            )
        if path.endswith("/credentials"):
            return httpx.Response(
                200,
                json=[
                    {"id": "cred-1", "type": "password"}
                ],
            )
        if (
            request.method == "GET"
            and "/identity-provider/instances/" in path
        ):
            return httpx.Response(404)
        return httpx.Response(204)

    api = ProductHttpAdminApi(
        "http://keycloak.test",
        "cwl",
        "account-unification-svc",
        "secret",
        transport=httpx.MockTransport(handler),
    )

    user = api.get_user("u1")
    assert user.external_id == "hr-1"
    assert api.get_user_attribute(
        "u1", "merged_into_user_id"
    ) == "survivor"
    assert [
        item.user_id
        for item in api.find_users_by_email(
            "jane@corp.test"
        )
    ] == ["u1"]
    found = api.find_user_by_username("Jane")
    assert found is not None
    assert found.user_id == "u1"
    assert api.create_user(
        UserAccount(
            user_id="",
            user_name="new",
            email="new@corp.test",
        )
    ) == "u2"
    assert [
        item.user_id
        for item in api.list_users(0, 100)
    ] == ["u1"]

    assert api.list_federated_identities("u1") == [
        FederatedIdentity(
            identity_provider="adfs",
            external_user_id="jane@corp",
            external_user_name="Jane Doe",
        )
    ]
    assert {
        role.role_name
        for role in api.list_role_mappings("u1")
    } == {"admin", "editor"}
    assert api.list_group_memberships("u1") == [
        GroupMembership(
            group_id="g1",
            group_name="Ops",
            group_path="/Ops",
        )
    ]
    assert api.list_user_credentials("u1") == [
        {"id": "cred-1", "type": "password"}
    ]
    assert api.get_identity_provider(
        "missing-provider"
    ) is None

    api.replace_user("u1", user)
    api.add_federated_identity(
        "u1",
        FederatedIdentity(
            identity_provider="github",
            external_user_id="jane",
        ),
    )
    api.remove_federated_identity("u1", "github")
    api.add_role_mapping(
        "u1",
        RoleMapping(
            role_id="realm-r", role_name="admin"
        ),
    )
    api.add_role_mapping(
        "u1",
        RoleMapping(
            role_id="client-r",
            role_name="editor",
            client_id="client-uuid",
        ),
    )
    api.remove_role_mapping(
        "u1",
        RoleMapping(
            role_id="realm-r", role_name="admin"
        ),
    )
    api.remove_role_mapping(
        "u1",
        RoleMapping(
            role_id="client-r",
            role_name="editor",
            client_id="client-uuid",
        ),
    )
    api.add_group_membership(
        "u1",
        GroupMembership(
            group_id="g1", group_path="/Ops"
        ),
    )
    api.remove_group_membership(
        "u1",
        GroupMembership(
            group_id="g1", group_path="/Ops"
        ),
    )
    api.deactivate_user("u1")
    api.set_user_attribute(
        "u1", "duplicate_of", "survivor"
    )
    api.reset_user_password(
        "u1", "bootstrap-password"
    )
    api.set_user_required_actions(
        "u1", ["webauthn-register-passwordless"]
    )
    api.delete_user_credential("u1", "cred-1")
    api.create_identity_provider(
        {"alias": "employer-adfs"}
    )
    api.update_identity_provider(
        "employer-adfs",
        {"alias": "employer-adfs", "enabled": False},
    )
    api.delete_identity_provider("employer-adfs")
    api.delete_user("u1")
    api.close()

    assert any(
        call.headers.get("authorization")
        == "Bearer token-1"
        for call in calls
    )
    assert any(
        call.method == "DELETE" and call.content
        for call in calls
    )


def test_product_adapter_reauthenticates_get_once():
    """An expired token is refreshed once before a GET succeeds."""
    token_requests = 0
    user_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests, user_requests
        if request.url.path.endswith(
            "/protocol/openid-connect/token"
        ):
            token_requests += 1
            return httpx.Response(
                200,
                json={
                    "access_token":
                        f"token-{token_requests}"
                },
            )
        user_requests += 1
        if (
            request.headers.get("Authorization")
            == "Bearer token-0"
        ):
            return httpx.Response(401)
        return httpx.Response(
            200,
            json={
                "id": "u1",
                "username": "jane",
                "enabled": True,
            },
        )

    api = ProductHttpAdminApi(
        "http://keycloak.test",
        "cwl",
        "svc",
        "secret",
        transport=httpx.MockTransport(handler),
    )
    api._token = "token-0"

    assert api.get_user("u1").user_id == "u1"
    assert token_requests == 1
    assert user_requests == 2


def test_product_adapter_reauthenticates_create_once():
    """User creation also retries exactly once after an expired token."""
    token_requests = 0
    create_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests, create_requests
        if request.url.path.endswith(
            "/protocol/openid-connect/token"
        ):
            token_requests += 1
            return httpx.Response(
                200,
                json={"access_token": "token-1"},
            )
        create_requests += 1
        if (
            request.headers.get("Authorization")
            == "Bearer token-0"
        ):
            return httpx.Response(401)
        return httpx.Response(
            201,
            headers={
                "Location":
                    "http://kc/admin/realms/cwl/users/u2"
            },
        )

    api = ProductHttpAdminApi(
        "http://keycloak.test",
        "cwl",
        "svc",
        "secret",
        transport=httpx.MockTransport(handler),
    )
    api._token = "token-0"

    account_id = api.create_user(
        UserAccount(
            user_id="",
            user_name="new",
            email="new@example.com",
        )
    )

    assert account_id == "u2"
    assert token_requests == 1
    assert create_requests == 2


@pytest.mark.parametrize(
    "unsafe_user_id",
    [
        "../victim",
        "victim%2Fother",
        "victim\\other",
        "victim\x00other",
    ],
)
def test_product_adapter_rejects_unsafe_paths(
    unsafe_user_id
):
    """Unsafe identifiers fail before any HTTP request is emitted."""
    def fail_handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(
            "unsafe path must not reach the transport"
        )

    api = ProductHttpAdminApi(
        "http://keycloak.test",
        "cwl",
        "svc",
        "secret",
        transport=httpx.MockTransport(fail_handler),
    )
    api._token = "token"

    with pytest.raises(InvalidIdentifierError):
        api.get_user(unsafe_user_id)
