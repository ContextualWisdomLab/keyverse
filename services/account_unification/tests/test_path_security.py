"""Router-level path-parameter security tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app

OPERATOR_TOKEN = "test-operator-token"


def _client() -> TestClient:
    """Return an app client with only operator authentication wired."""
    app = create_app(wire=False)
    app.state.operator_api_token = OPERATOR_TOKEN
    return TestClient(
        app,
        headers={
            "Authorization": f"Bearer {OPERATOR_TOKEN}"
        },
    )


def test_admin_router_rejects_encoded_identifier():
    """Encoded path material is rejected before endpoint dependencies."""
    with _client() as client:
        response = client.get(
            "/users/bad%252fidentifier/identities"
        )
    assert response.status_code == 400
    assert "encoding" in response.json()["detail"]


def test_federation_router_rejects_traversal_alias():
    """Federation aliases cannot carry encoded navigation segments."""
    with _client() as client:
        response = client.get(
            "/federation/identity-providers/%252e%252e"
        )
    assert response.status_code == 400


def test_scim_router_returns_scim_error_for_unsafe_id():
    """SCIM path validation preserves the RFC 7644 error envelope."""
    with _client() as client:
        response = client.get(
            "/scim/v2/Users/bad%252fidentifier"
        )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["schemas"] == [
        "urn:ietf:params:scim:api:messages:2.0:Error"
    ]
    assert detail["status"] == "400"
