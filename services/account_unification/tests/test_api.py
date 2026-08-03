"""Authenticated HTTP surface for identity inspection, merge, and audit."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import FederatedIdentity, RoleMapping
from app.service import UnificationService


@pytest.fixture
def client(
    api,
    audit,
    config,
    auth_header,
    user_operation_locks,
):
    """Return an authenticated app with all merge dependencies wired."""
    app = create_app(wire=False)
    app.state.unification_service = UnificationService(
        api,
        audit,
        config,
        user_operation_locks,
    )
    app.state.audit_logger = audit
    app.state.keycloak_api = api
    app.state.user_operation_locks = user_operation_locks
    app.state.operator_api_token = config.operator_api_token
    with TestClient(app, headers=auth_header) as test_client:
        yield test_client


def test_healthz_ok(client):
    """Health probes remain open and report readiness."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_list_identities_endpoint(client, api):
    """The authenticated identity endpoint returns external links."""
    api.create_test_user(
        "u1",
        federated_identities=[
            FederatedIdentity(
                identity_provider="employer-adfs",
                external_user_id="jane@corp",
            )
        ],
    )
    response = client.get("/users/u1/identities")
    assert response.status_code == 200
    assert (
        response.json()[0]["identity_provider"]
        == "employer-adfs"
    )


def test_merge_endpoint_and_audit(client, api):
    """A valid merge produces a retrievable append-only audit trail."""
    api.create_test_user(
        "survivor",
        email="j@x.com",
        is_email_verified=True,
        role_mappings=[
            RoleMapping(
                role_id="r-s",
                role_name="admin",
                client_id="naruon",
            )
        ],
    )
    api.create_test_user(
        "dup",
        email="j@x.com",
        is_email_verified=True,
        federated_identities=[
            FederatedIdentity(
                identity_provider="google",
                external_user_id="j@gmail",
            )
        ],
    )
    response = client.post(
        "/merges",
        json={
            "survivor_user_id": "survivor",
            "duplicate_user_id": "dup",
            "actor": "admin",
        },
    )
    assert response.status_code == 200
    audit_id = response.json()["audit_id"]

    audit_response = client.get(f"/merges/{audit_id}/audit")
    assert audit_response.status_code == 200
    assert any(
        event["event_type"] == "merge_completed"
        for event in audit_response.json()
    )


def test_merge_endpoint_refuses_unverified_email(client, api):
    """Unverified-email coincidence never authorizes a merge."""
    api.create_test_user(
        "survivor",
        email="j@x.com",
        is_email_verified=True,
    )
    api.create_test_user(
        "dup",
        email="j@x.com",
        is_email_verified=False,
    )
    response = client.post(
        "/merges",
        json={
            "survivor_user_id": "survivor",
            "duplicate_user_id": "dup",
            "actor": "admin",
        },
    )
    assert response.status_code == 422


def test_merge_endpoint_missing_user_404(client, api):
    """Unknown accounts produce an HTTP 404 without partial writes."""
    api.create_test_user(
        "survivor",
        email="j@x.com",
        is_email_verified=True,
    )
    response = client.post(
        "/merges",
        json={
            "survivor_user_id": "survivor",
            "duplicate_user_id": "ghost",
            "actor": "admin",
        },
    )
    assert response.status_code == 404
