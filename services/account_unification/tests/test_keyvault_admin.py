"""Authenticated HTTP surface for the Keyvault namespaced secrets store."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.keyvault import (
    InMemoryKeyvaultAuditSink,
    InMemoryKeyvaultStore,
    KeyvaultService,
    derive_fernet_key,
)
from app.main import create_app


@pytest.fixture
def client(auth_header):
    """Return an authenticated app with a real (in-memory) Keyvault wired."""
    app = create_app(wire=False)
    app.state.keyvault_service = KeyvaultService(
        InMemoryKeyvaultStore(),
        InMemoryKeyvaultAuditSink(),
        derive_fernet_key("test-passphrase"),
    )
    app.state.operator_api_token = auth_header["Authorization"].removeprefix("Bearer ")
    with TestClient(app, headers=auth_header) as test_client:
        yield test_client


@pytest.fixture
def unconfigured_client(auth_header):
    """Return an app whose Keyvault feature was never configured (opt-in)."""
    app = create_app(wire=False)
    app.state.operator_api_token = auth_header["Authorization"].removeprefix("Bearer ")
    with TestClient(app, headers=auth_header) as test_client:
        yield test_client


def test_put_then_get_secret_roundtrips(client):
    put_response = client.put(
        "/keyvault/contextual-orchestrator/OPENAI_API_KEY", json={"value": "sk-live-123"}
    )
    assert put_response.status_code == 200
    body = put_response.json()
    assert body["namespace"] == "contextual-orchestrator"
    assert body["secret_key"] == "OPENAI_API_KEY"
    assert "value" not in body

    get_response = client.get("/keyvault/contextual-orchestrator/OPENAI_API_KEY")
    assert get_response.status_code == 200
    assert get_response.json() == {
        "namespace": "contextual-orchestrator",
        "secret_key": "OPENAI_API_KEY",
        "value": "sk-live-123",
    }


def test_get_missing_secret_returns_404(client):
    response = client.get("/keyvault/ns/absent-key")
    assert response.status_code == 404


def test_delete_secret_then_get_returns_404(client):
    client.put("/keyvault/ns/key1", json={"value": "v1"})
    delete_response = client.delete("/keyvault/ns/key1")
    assert delete_response.status_code == 204
    assert client.get("/keyvault/ns/key1").status_code == 404


def test_delete_missing_secret_returns_404(client):
    assert client.delete("/keyvault/ns/absent").status_code == 404


def test_list_secrets_returns_metadata_never_the_value(client):
    client.put("/keyvault/ns/key1", json={"value": "super-secret-value"})
    client.put("/keyvault/ns/key2", json={"value": "another-secret-value"})
    response = client.get("/keyvault/ns")
    assert response.status_code == 200
    body = response.json()
    assert {item["secret_key"] for item in body} == {"key1", "key2"}
    assert "super-secret-value" not in response.text
    assert "another-secret-value" not in response.text


def test_secret_audit_trail_records_set_read_and_delete(client):
    client.put("/keyvault/ns/key1", json={"value": "v1"})
    client.get("/keyvault/ns/key1")
    client.delete("/keyvault/ns/key1")
    response = client.get("/keyvault/ns/key1/audit")
    assert response.status_code == 200
    actions = [event["action"] for event in response.json()]
    assert actions == ["secret_set", "secret_read", "secret_deleted"]


def test_empty_value_is_rejected_by_request_validation(client):
    response = client.put("/keyvault/ns/key1", json={"value": ""})
    assert response.status_code == 422


def test_path_traversal_namespace_is_rejected(client):
    response = client.get("/keyvault/..%2F..%2Fetc/key1")
    assert response.status_code in (400, 404)
    # A traversal attempt must never reach the store as a normal lookup.
    assert client.get("/keyvault/ns").json() == []


def test_unauthenticated_request_is_rejected(client):
    unauth = TestClient(client.app)
    response = unauth.get("/keyvault/ns/key1")
    assert response.status_code == 401


def test_keyvault_unconfigured_returns_503_not_404(unconfigured_client):
    """No passphrase configured => the feature is unavailable, not 'empty'."""
    response = unconfigured_client.get("/keyvault/ns/key1")
    assert response.status_code == 503
    put_response = unconfigured_client.put("/keyvault/ns/key1", json={"value": "v1"})
    assert put_response.status_code == 503
