"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.audit import AuditLogger, InMemoryAuditSink  # noqa: E402
from app.config import ServiceConfig  # noqa: E402
from app.service import UnificationService  # noqa: E402

from .mock_keycloak import MockKeycloakAdminApi  # noqa: E402


@pytest.fixture
def api() -> MockKeycloakAdminApi:
    return MockKeycloakAdminApi()


@pytest.fixture
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def audit(audit_sink: InMemoryAuditSink) -> AuditLogger:
    return AuditLogger(audit_sink)


OPERATOR_TOKEN = "test-operator-token"


@pytest.fixture
def operator_token() -> str:
    return OPERATOR_TOKEN


@pytest.fixture
def auth_header(operator_token: str) -> dict[str, str]:
    """Default operator bearer header for authenticated admin requests."""
    return {"Authorization": f"Bearer {operator_token}"}


@pytest.fixture
def config() -> ServiceConfig:
    return ServiceConfig(
        keycloak_server_url="http://keycloak.test",
        keycloak_realm="cwl",
        keycloak_client_id="account-unification-svc",
        keycloak_client_secret="test-secret",
        operator_api_token=OPERATOR_TOKEN,
        merge_conflict_policy="survivor_wins",
        allow_unverified_email_link=False,
    )


@pytest.fixture
def service(
    api: MockKeycloakAdminApi, audit: AuditLogger, config: ServiceConfig
) -> UnificationService:
    return UnificationService(api, audit, config)
