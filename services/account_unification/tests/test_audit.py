"""Merge operations are fully audit-logged (in-memory and SQLite sinks)."""
from __future__ import annotations

from contextlib import closing

from app.audit import AuditLogger, AuditSink, InMemoryAuditSink, SqliteAuditSink
from app.config import ServiceConfig
from app.models import FederatedIdentity, MergeRequest, RoleMapping
from app.service import UnificationService

from .mock_keycloak import MockKeycloakAdminApi


def test_audit_sink_protocol_methods_have_concrete_implementations():
    protocol_methods = {
        name
        for name, member in AuditSink.__dict__.items()
        if callable(member) and not name.startswith("_")
    }
    assert protocol_methods
    for implementation in (InMemoryAuditSink, SqliteAuditSink):
        missing = [
            name
            for name in sorted(protocol_methods)
            if not callable(getattr(implementation, name, None))
        ]
        assert missing == []


def _seed_mergeable(api):
    api.create_test_user(
        "survivor", email="j@x.com", is_email_verified=True,
        role_mappings=[RoleMapping(role_id="r-s", role_name="admin", client_id="naruon")],
    )
    api.create_test_user(
        "dup", email="j@x.com", is_email_verified=True,
        federated_identities=[
            FederatedIdentity(identity_provider="google", external_user_id="j@gmail")
        ],
        role_mappings=[RoleMapping(role_id="r-d", role_name="editor", client_id="clearfolio")],
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
    assert "federated_identity_moved" in event_types
    assert "role_mapping_moved" in event_types
    assert "duplicate_tombstoned" in event_types
    # every event carries the same actor + correlation id.
    assert {e.actor for e in events} == {"admin@cwl"}
    assert {e.audit_id for e in events} == {result.audit_id}


def test_sqlite_audit_sink_persists(tmp_path):
    api = MockKeycloakAdminApi()
    _seed_mergeable(api)
    db = tmp_path / "audit.db"
    with closing(SqliteAuditSink(str(db))) as sink:
        audit = AuditLogger(sink)
        config = ServiceConfig(
            keycloak_server_url="http://kc",
            keycloak_realm="cwl",
            keycloak_client_id="svc",
            keycloak_client_secret="secret",
            operator_api_token="op-token",
        )
        service = UnificationService(api, audit, config)
        result = service.merge_accounts(
            MergeRequest(
                survivor_user_id="survivor",
                duplicate_user_id="dup",
                actor="admin@cwl",
            )
        )
        # re-open a fresh sink over the same DB file: events are durable.
        with closing(SqliteAuditSink(str(db))) as reopened:
            events = reopened.events_for(result.audit_id)
            assert any(e.event_type == "merge_completed" for e in events)
