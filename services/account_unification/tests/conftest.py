"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.audit import AuditLogger, InMemoryAuditSink  # noqa: E402
from app.config import ServiceConfig  # noqa: E402
from app.service import UnificationService  # noqa: E402

from .mock_zitadel import MockManagementApi  # noqa: E402


@pytest.fixture
def api() -> MockManagementApi:
    return MockManagementApi()


@pytest.fixture
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def audit(audit_sink: InMemoryAuditSink) -> AuditLogger:
    return AuditLogger(audit_sink)


@pytest.fixture
def config() -> ServiceConfig:
    return ServiceConfig(
        zitadel_api_base="http://zitadel.test",
        zitadel_mgmt_token="test-token",
        zitadel_org_id="org-1",
        merge_conflict_policy="survivor_wins",
        allow_unverified_email_link=False,
    )


@pytest.fixture
def service(
    api: MockManagementApi, audit: AuditLogger, config: ServiceConfig
) -> UnificationService:
    return UnificationService(api, audit, config)
