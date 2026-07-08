"""Merge operations are fully audit-logged (in-memory and SQLite sinks)."""
from __future__ import annotations

from app.audit import AuditLogger, SqliteAuditSink
from app.config import ServiceConfig
from app.models import IdentityLink, MergeRequest, UserGrant
from app.service import UnificationService

from .mock_zitadel import MockManagementApi


def _seed_mergeable(api):
    api.create_user(
        "survivor", email="j@x.com", is_email_verified=True,
        grants=[UserGrant(grant_id="g-s", project_id="naruon", role_keys=["admin"])],
    )
    api.create_user(
        "dup", email="j@x.com", is_email_verified=True,
        idp_links=[IdentityLink(idp_id="google", external_user_id="j@gmail")],
        grants=[UserGrant(grant_id="g-d", project_id="clearfolio", role_keys=["editor"])],
    )


def test_audit_trail_records_full_merge(service, api, audit_sink):
    _seed_mergeable(api)
    result = service.merge_accounts(
        MergeRequest(survivor_user_id="survivor", duplicate_user_id="dup", actor="admin@cwl")
    )
    events = audit_sink.events_for(result.audit_id)
    event_types = [e.event_type for e in events]
    assert event_types[0] == "merge_started"
    assert event_types[-1] == "merge_completed"
    assert "idp_link_moved" in event_types
    assert "grant_moved" in event_types
    assert "duplicate_tombstoned" in event_types
    # every event carries the same actor + correlation id.
    assert {e.actor for e in events} == {"admin@cwl"}
    assert {e.audit_id for e in events} == {result.audit_id}


def test_sqlite_audit_sink_persists(tmp_path):
    api = MockManagementApi()
    _seed_mergeable(api)
    db = tmp_path / "audit.db"
    audit = AuditLogger(SqliteAuditSink(str(db)))
    config = ServiceConfig(
        zitadel_api_base="http://z", zitadel_mgmt_token="t", zitadel_org_id="o"
    )
    service = UnificationService(api, audit, config)
    result = service.merge_accounts(
        MergeRequest(survivor_user_id="survivor", duplicate_user_id="dup", actor="admin@cwl")
    )
    # re-open a fresh sink over the same DB file: events are durable.
    reopened = SqliteAuditSink(str(db))
    events = reopened.events_for(result.audit_id)
    assert any(e.event_type == "merge_completed" for e in events)
