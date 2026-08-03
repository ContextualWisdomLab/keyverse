"""HTTP surface: /healthz, identity listing, merge, and audit retrieval."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import FederatedIdentity, RoleMapping


@pytest.fixture
def client(api, audit, config, user_operation_locks):
    from app.service import UnificationService

    app = create_app(wire=False)
    app.state.unification_service = UnificationService(
        api,
        audit,
        config,
        user_operation_locks,
    )
    app.state.audit_logger = audit
    app.state.keycloak_api = api
    with TestClient(app) as test_client:
        yield test_client


def test_healthz_ok(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_list_identities_endpoint(client, api):
    api.create_test_user(
        "u1",
        federated_identities=[
            FederatedIdentity(identity_provider="employer-adfs", external_user_id="jane@corp")
        ],
    )
    response = client.get("/users/u1/identities")
    assert response.status_code == 200
    assert response.json()[0]["identity_provider"] == "employer-adfs"


def test_merge_endpoint_and_audit(client, api):
    api.create_test_user(
        "survivor", email="j@x.com", is_email_verified=True,
        role_mappings=[RoleMapping(role_id="r-s", role_name="admin", client_id="naruon")],
    )
    api.create_test_user(
        "dup", email="j@x.com", is_email_verified=True,
        federated_identities=[
            FederatedIdentity(identity_provider="google", external_user_id="j@gmail")
        ],
    )
    response = client.post(
        "/merges",
        json={"survivor_user_id": "survivor", "duplicate_user_id": "dup", "actor": "admin"},
    )
    assert response.status_code == 200
    audit_id = response.json()["audit_id"]

    audit_response = client.get(f"/merges/{audit_id}/audit")
    assert audit_response.status_code == 200
    assert any(e["event_type"] == "merge_completed" for e in audit_response.json())


def test_merge_endpoint_refuses_unverified_email(client, api):
    api.create_test_user("survivor", email="j@x.com", is_email_verified=True)
    api.create_test_user("dup", email="j@x.com", is_email_verified=False)
    response = client.post(
        "/merges",
        json={"survivor_user_id": "survivor", "duplicate_user_id": "dup", "actor": "admin"},
    )
    assert response.status_code == 422


def test_merge_endpoint_missing_user_404(client, api):
    api.create_test_user("survivor", email="j@x.com", is_email_verified=True)
    response = client.post(
        "/merges",
        json={"survivor_user_id": "survivor", "duplicate_user_id": "ghost", "actor": "admin"},
    )
    assert response.status_code == 404
