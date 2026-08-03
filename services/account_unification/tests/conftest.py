"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.audit import AuditLogger, InMemoryAuditSink  # noqa: E402
from app.config import ServiceConfig  # noqa: E402
from app.service import UnificationService  # noqa: E402
from app.user_locks import InMemoryUserOperationLocks  # noqa: E402

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


@pytest.fixture
def config() -> ServiceConfig:
    return ServiceConfig(
        keycloak_server_url="http://keycloak.test",
        keycloak_realm="cwl",
        keycloak_client_id="account-unification-svc",
        keycloak_client_secret="test-secret",
        merge_conflict_policy="survivor_wins",
        allow_unverified_email_link=False,
    )


@pytest.fixture
def user_operation_locks() -> InMemoryUserOperationLocks:
    return InMemoryUserOperationLocks()


@pytest.fixture
def service(
    api: MockKeycloakAdminApi,
    audit: AuditLogger,
    config: ServiceConfig,
    user_operation_locks: InMemoryUserOperationLocks,
) -> UnificationService:
    return UnificationService(api, audit, config, user_operation_locks)
