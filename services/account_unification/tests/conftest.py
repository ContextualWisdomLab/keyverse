"""Shared pytest fixtures for authenticated, serialized service tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.audit import AuditLogger, InMemoryAuditSink  # noqa: E402
from app.config import ServiceConfig  # noqa: E402
from app.service import UnificationService  # noqa: E402
from app.user_locks import InMemoryUserOperationLocks  # noqa: E402

from .mock_product_keycloak import (  # noqa: E402
    MockProductKeycloakAdminApi,
)

OPERATOR_TOKEN = "test-operator-token"


@pytest.fixture
def api() -> MockProductKeycloakAdminApi:
    """Return a fresh product-capable Keycloak test double."""
    return MockProductKeycloakAdminApi()


@pytest.fixture
def audit_sink() -> InMemoryAuditSink:
    """Return a fresh in-memory audit sink."""
    return InMemoryAuditSink()


@pytest.fixture
def audit(audit_sink: InMemoryAuditSink) -> AuditLogger:
    """Return an audit logger around the in-memory sink."""
    return AuditLogger(audit_sink)


@pytest.fixture
def operator_token() -> str:
    """Return the shared operator token used by HTTP tests."""
    return OPERATOR_TOKEN


@pytest.fixture
def auth_header(operator_token: str) -> dict[str, str]:
    """Return an authenticated operator bearer header."""
    return {"Authorization": f"Bearer {operator_token}"}


@pytest.fixture
def config() -> ServiceConfig:
    """Return deterministic account-unification service configuration."""
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
def user_operation_locks() -> InMemoryUserOperationLocks:
    """Return a process-local keyed lock manager."""
    return InMemoryUserOperationLocks()


@pytest.fixture
def service(
    api: MockProductKeycloakAdminApi,
    audit: AuditLogger,
    config: ServiceConfig,
    user_operation_locks: InMemoryUserOperationLocks,
) -> UnificationService:
    """Return a fully wired unification service."""
    return UnificationService(
        api,
        audit,
        config,
        user_operation_locks,
    )
