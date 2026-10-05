"""One-event PAT rotation metadata on real durable and in-memory storage."""
from __future__ import annotations

import json
from contextlib import ExitStack, closing

import pytest

from app.application_tokens import (
    APPLICATION_TOKEN_NAMESPACE,
    ApplicationTokenIssueRequest,
    ApplicationTokenService,
    ApplicationTokenVerifyRequest,
)
from app.audit import AuditLogger, InMemoryAuditSink, SqliteAuditSink
from app.kv_store import InMemoryKvStore, SqliteKvStore
from tests.test_application_tokens import ISSUE_BODY


@pytest.fixture(params=["memory", "sqlite"])
def persistence(request, tmp_path):
    """Own actual KV and audit resources; reopen SQLite after the cutover."""
    with ExitStack() as stack:
        def open_pair():
            """Create resources for this backend and register their closure."""
            if request.param == "sqlite":
                store = SqliteKvStore(str(tmp_path / "token_state.sqlite3"))
                sink = SqliteAuditSink(str(tmp_path / "token_audit.sqlite3"))
            else:
                store, sink = InMemoryKvStore(), InMemoryAuditSink()
            stack.enter_context(closing(store))
            audit = stack.enter_context(closing(AuditLogger(sink)))
            return store, audit

        store, audit = open_pair()

        def reopen():
            """Close and reopen durable resources; memory keeps its existing state."""
            if request.param == "sqlite":
                store.close()
                audit.close()
                return open_pair()
            return store, audit

        yield store, audit, reopen


def service_for(store, audit):
    """Use a fixed clock, with lifecycle validation still enabled."""
    return ApplicationTokenService(store, audit, clock=lambda: 1_700_000_000.0)


def verify(service, issued):
    """Verify a minted credential without exposing it in assertion diagnostics."""
    return service.verify(ApplicationTokenVerifyRequest(
        presented_token=issued.plaintext_token,
        tenant_deployment_id=ISSUE_BODY["tenant_deployment_id"],
        software_unit_id=ISSUE_BODY["software_unit_id"],
        requested_capability_codes=["api.invoices.read"],
    ))


def assert_secret_free(events, store):
    """Assert only a boolean, never print plaintext or persisted token hashes."""
    serialized = json.dumps([event.payload_json for event in events])
    secret_present = any(marker in serialized for marker in ("kvt_", "token_hash", "plaintext_token"))
    secret_present |= any(
        json.loads(raw)["token_hash"] in serialized
        for raw in store.get_all(APPLICATION_TOKEN_NAMESPACE).values()
    )
    assert secret_present is False


def test_rotation_event_has_both_ids_and_persisted_retired_state(persistence):
    """Persist one successor event, with predecessor metadata but no query expansion."""
    store, audit, reopen = persistence
    service = service_for(store, audit)
    request = ApplicationTokenIssueRequest.model_validate(ISSUE_BODY)
    predecessor = service.issue(request)
    assert verify(service, predecessor).active is True
    successor = service.rotate(predecessor.application_token_id, request)
    assert verify(service, predecessor).denial_code == "revoked_token"
    assert verify(service, successor).active is True
    old_id, new_id = predecessor.application_token_id, successor.application_token_id
    del predecessor, successor

    store, audit = reopen()
    service = service_for(store, audit)
    old_view, new_view = service.get_token(old_id), service.get_token(new_id)
    assert old_view.lifecycle_status_code == "rotated"
    assert old_view.revoked_at is not None
    assert new_view.lifecycle_status_code == "active"
    assert new_view.replaced_token_id == old_id
    old_events, new_events = audit.events_for(old_id), audit.events_for(new_id)
    assert [event.event_type for event in old_events] == ["application_token_issued"]
    assert [event.event_type for event in new_events] == ["application_token_rotated"]
    assert len(old_events + new_events) == 2
    event = new_events[0]
    assert event.audit_id == new_id
    assert event.actor == request.actor_identity_id
    assert event.survivor_user_id is None and event.duplicate_user_id is None
    assert_secret_free(old_events + new_events, store)
    base_payload = {
        "application_token_id": new_id,
        "tenant_deployment_id": request.tenant_deployment_id,
        "software_unit_id": request.software_unit_id,
        "token_prefix": new_view.token_prefix,
        "purpose_code": request.purpose_code,
        "lifecycle_status_code": "active",
    }
    assert json.loads(event.payload_json) == {
        **base_payload,
        "replaced_token_id": old_id,
        "replaced_token_lifecycle_status_code": old_view.lifecycle_status_code,
    }
    assert json.loads(old_events[0].payload_json) == {
        **base_payload, "application_token_id": old_id, "token_prefix": old_view.token_prefix,
    }

    service.revoke(new_id, actor_identity_id="operator-revoke-fixture")
    events = audit.events_for(new_id)
    assert [event.event_type for event in events] == [
        "application_token_rotated", "application_token_revoked",
    ]
    assert json.loads(events[1].payload_json) == {**base_payload, "lifecycle_status_code": "revoked"}
    assert json.loads(events[0].payload_json)["lifecycle_status_code"] == "active"
    assert_secret_free(events, store)


def test_rotation_metadata_uses_captured_row_not_later_retirement(persistence, tmp_path, monkeypatch):
    """A committed recovery after cutover cannot rewrite historical audit metadata."""
    store, audit, _ = persistence
    service = service_for(store, audit)
    request = ApplicationTokenIssueRequest.model_validate(ISSUE_BODY)
    predecessor = service.issue(request)
    old_id = predecessor.application_token_id
    with closing(SqliteKvStore(str(tmp_path / "token_state.sqlite3"))
                 if isinstance(store, SqliteKvStore) else InMemoryKvStore()) as other:
        independent = other if isinstance(store, SqliteKvStore) else store
        original = store.compare_and_replace
        retired = []

        def after_commit(namespace, expected, entries, delete_keys=()):
            """Perform the real cutover, then independently retire the predecessor."""
            result = original(namespace, expected, entries, delete_keys)
            if result and old_id in entries and len(entries) == 2:
                captured = json.loads(entries[old_id])
                assert captured["lifecycle_status_code"] == "rotated"
                changed = {**captured, "lifecycle_status_code": "revoked",
                           "lifecycle_generation_id": "independent-recovery"}
                assert independent.compare_and_replace(
                    namespace, {old_id: entries[old_id]}, {old_id: json.dumps(changed)},
                )
                retired.append(changed["lifecycle_status_code"])
            return result

        monkeypatch.setattr(store, "compare_and_replace", after_commit)
        successor = service.rotate(old_id, request)
        assert retired == ["revoked"]
        assert service.get_token(old_id).lifecycle_status_code == "revoked"
        events = audit.events_for(successor.application_token_id)
        assert len(events) == 1
        payload = json.loads(events[0].payload_json)
        assert payload["replaced_token_id"] == old_id
        assert payload["replaced_token_lifecycle_status_code"] == "rotated"
        assert payload["lifecycle_status_code"] == "active"
        assert verify(service, successor).active is True
        assert_secret_free(events, store)


@pytest.mark.parametrize("independent_retirement", [False, True])
def test_real_rotation_emit_failure_preserves_error_and_conditional_compensation(
    persistence, tmp_path, monkeypatch, independent_retirement,
):
    """The real metadata helper reaches one failed append without reviving newer state."""
    store, audit, _ = persistence
    service = service_for(store, audit)
    request = ApplicationTokenIssueRequest.model_validate(ISSUE_BODY)
    predecessor = service.issue(request)
    old_id = predecessor.application_token_id
    failure = RuntimeError("fixture audit append unavailable")
    attempted = []
    with closing(SqliteKvStore(str(tmp_path / "token_state.sqlite3"))
                 if isinstance(store, SqliteKvStore) else InMemoryKvStore()) as other:
        independent = other if isinstance(store, SqliteKvStore) else store
        persisted_retirement = []

        def fail_append(event):
            """Reject one actual event after an optional independent recovery commit."""
            attempted.append(event)
            assert json.loads(event.payload_json)["replaced_token_lifecycle_status_code"] == "rotated"
            if independent_retirement:
                raw = independent.get(APPLICATION_TOKEN_NAMESPACE, old_id)
                changed = {**json.loads(raw), "lifecycle_status_code": "revoked",
                           "lifecycle_generation_id": "independent-recovery"}
                updated = json.dumps(changed)
                assert independent.compare_and_replace(
                    APPLICATION_TOKEN_NAMESPACE, {old_id: raw}, {old_id: updated},
                )
                persisted_retirement.append(updated)
            raise failure

        monkeypatch.setattr(audit._sink, "record", fail_append)
        with pytest.raises(RuntimeError) as error:
            service.rotate(old_id, request)
        assert error.value is failure
        assert len(attempted) == 1
        new_id = attempted[0].audit_id
        assert json.loads(attempted[0].payload_json)["replaced_token_id"] == old_id
        assert store.get(APPLICATION_TOKEN_NAMESPACE, new_id) is None
        assert len(service.list_tokens()) == 1
        assert [event.event_type for event in audit.events_for(old_id)] == ["application_token_issued"]
        assert audit.events_for(new_id) == []
        if independent_retirement:
            preserved = store.get(APPLICATION_TOKEN_NAMESPACE, old_id) == persisted_retirement[0]
            assert preserved is True
            assert service.get_token(old_id).lifecycle_status_code == "revoked"
            assert verify(service, predecessor).active is False
        else:
            assert service.get_token(old_id).lifecycle_status_code == "active"
            assert verify(service, predecessor).active is True
        assert_secret_free(attempted, store)
