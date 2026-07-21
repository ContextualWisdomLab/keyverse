"""Operator bearer auth gates the privileged admin surface; /healthz is open."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.federation import FederationService  # noqa: E402
from app.kv_store import InMemoryKvStore  # noqa: E402
from app.main import create_app  # noqa: E402
from app.service import UnificationService  # noqa: E402

from .mock_keycloak import MockKeycloakAdminApi  # noqa: E402


def _wired_app(api: MockKeycloakAdminApi, audit, config):
    app = create_app(wire=False)
    app.state.unification_service = UnificationService(api, audit, config)
    app.state.audit_logger = audit
    app.state.keycloak_api = api
    app.state.federation_service = FederationService(InMemoryKvStore(), api)
    app.state.operator_api_token = config.operator_api_token
    return app


def test_healthz_is_open_without_a_token(api, audit, config):
    client = TestClient(_wired_app(api, audit, config))
    response = client.get("/healthz")
    assert response.status_code == 200


def test_privileged_routes_reject_missing_token(api, audit, config):
    client = TestClient(_wired_app(api, audit, config))

    assert client.get("/users/u1").status_code == 401
    assert client.post("/merges", json={}).status_code == 401
    assert client.get("/federation/identity-providers").status_code == 401
    assert client.post("/scim/v2/Users", json={"userName": "x"}).status_code == 401


def test_privileged_routes_reject_wrong_token(api, audit, config):
    client = TestClient(
        _wired_app(api, audit, config),
        headers={"Authorization": "Bearer not-the-token"},
    )
    assert client.get("/federation/identity-providers").status_code == 403


def test_privileged_routes_accept_valid_token(api, audit, config, auth_header):
    client = TestClient(_wired_app(api, audit, config), headers=auth_header)
    # 200 with the correct token (empty registry list), not 401/403.
    assert client.get("/federation/identity-providers").status_code == 200


def test_service_without_configured_token_fails_closed(api, audit, config):
    app = create_app(wire=False)
    app.state.unification_service = UnificationService(api, audit, config)
    app.state.audit_logger = audit
    app.state.keycloak_api = api
    # No operator_api_token wired: privileged surface is unavailable, never open.
    client = TestClient(app, headers={"Authorization": "Bearer anything"})
    assert client.get("/users/u1").status_code == 503
