"""Operator bearer authentication gates every privileged API surface."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.federation import FederationService
from app.kv_store import InMemoryKvStore
from app.main import create_app
from app.service import UnificationService


def _wired_app(
    api,
    audit,
    config,
    user_operation_locks,
):
    """Return an app with privileged service dependencies wired."""
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
    app.state.federation_service = FederationService(
        InMemoryKvStore(), api
    )
    app.state.operator_api_token = config.operator_api_token
    return app


def test_healthz_is_open_without_a_token(
    api, audit, config, user_operation_locks
):
    """Health probes remain available without operator credentials."""
    client = TestClient(
        _wired_app(
            api,
            audit,
            config,
            user_operation_locks,
        )
    )
    response = client.get("/healthz")
    assert response.status_code == 200


def test_privileged_routes_reject_missing_token(
    api, audit, config, user_operation_locks
):
    """Every privileged router rejects an absent bearer token."""
    client = TestClient(
        _wired_app(
            api,
            audit,
            config,
            user_operation_locks,
        )
    )
    assert client.get("/users/u1").status_code == 401
    assert client.post(
        "/merges", json={}
    ).status_code == 401
    assert client.get(
        "/federation/identity-providers"
    ).status_code == 401
    assert client.post(
        "/scim/v2/Users",
        json={"userName": "x"},
    ).status_code == 401


def test_privileged_routes_reject_wrong_token(
    api, audit, config, user_operation_locks
):
    """A mismatched bearer token produces HTTP 403."""
    client = TestClient(
        _wired_app(
            api,
            audit,
            config,
            user_operation_locks,
        ),
        headers={
            "Authorization": "Bearer not-the-token"
        },
    )
    assert client.get(
        "/federation/identity-providers"
    ).status_code == 403


def test_privileged_routes_accept_valid_token(
    api,
    audit,
    config,
    auth_header,
    user_operation_locks,
):
    """A valid operator token opens the privileged router."""
    client = TestClient(
        _wired_app(
            api,
            audit,
            config,
            user_operation_locks,
        ),
        headers=auth_header,
    )
    assert client.get(
        "/federation/identity-providers"
    ).status_code == 200


def test_service_without_configured_token_fails_closed(
    api, audit, config, user_operation_locks
):
    """Missing token configuration makes the surface unavailable."""
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
    client = TestClient(
        app,
        headers={
            "Authorization": "Bearer anything"
        },
    )
    assert client.get("/users/u1").status_code == 503
