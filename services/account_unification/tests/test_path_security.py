"""Router-level path-parameter security tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app

OPERATOR_TOKEN = "test-operator-token"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def _client() -> TestClient:
    """Return an app client with only operator authentication wired."""
    app = create_app(wire=False)
    app.state.operator_api_token = OPERATOR_TOKEN
    return TestClient(
        app,
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
    )


def test_admin_router_rejects_encoded_identifier() -> None:
    """Encoded path material is rejected before endpoint dependencies."""
    with _client() as client:
        response = client.get("/users/bad%252fidentifier/identities")
    assert response.status_code == 400
    assert "encoding" in response.json()["detail"]


def test_federation_router_rejects_traversal_alias() -> None:
    """Federation aliases cannot carry encoded navigation segments."""
    with _client() as client:
        response = client.get(
            "/federation/identity-providers/%252e%252e"
        )
    assert response.status_code == 400


def test_scim_router_returns_protocol_native_error_for_unsafe_id() -> None:
    """SCIM path validation returns an RFC 7644 body and media type."""
    with _client() as client:
        response = client.get("/scim/v2/Users/bad%252fidentifier")

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/scim+json")
    body = response.json()
    assert body["schemas"] == [SCIM_ERROR_SCHEMA]
    assert body["status"] == "400"
    assert "detail" in body
    assert "detail" not in body.get("detail", {})
