"""Independent exact-state storage contracts for PAT lifecycle operations."""
import sqlite3

import pytest

from app.kv_store import InMemoryKvStore, SqliteKvStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    """Exercise both canonical backends, closing the owned connection."""
    value = (InMemoryKvStore() if request.param == "memory"
             else SqliteKvStore(str(tmp_path / "conditional.sqlite3")))
    yield value
    value.close()


def test_conditional_batch_requires_exact_state_and_absent_successor(store):
    """A stale predecessor or occupied successor rejects the entire pair."""
    store.put_many("application_access_tokens", {"old_token": "active", "new_token": "occupied"})
    baseline = store.get_all("application_access_tokens")
    assert not store.compare_and_replace(
        "application_access_tokens", {"old_token": "active", "new_token": None},
        {"old_token": "rotated", "new_token": "active"},
    )
    assert store.get_all("application_access_tokens") == baseline
    assert not store.compare_and_replace(
        "application_access_tokens", {"old_token": "stale", "new_token": "occupied"},
        {"old_token": "rotated"}, ["new_token"],
    )
    assert store.get_all("application_access_tokens") == baseline
    assert store.compare_and_replace(
        "application_access_tokens", baseline, {"old_token": "retired"}, ["new_token"],
    )
    assert store.get_all("application_access_tokens") == {"old_token": "retired"}
    assert store.compare_and_replace("absent_namespace", {}, {})
    assert store.get_all("absent_namespace") == {}


def test_conditional_batch_rejects_unexpected_changes(store):
    """Every changed or removed key requires an expectation."""
    with pytest.raises(ValueError, match="expected"):
        store.compare_and_replace("application_access_tokens", {}, {"new_token": "active"})
    with pytest.raises(ValueError, match="expected"):
        store.compare_and_replace("application_access_tokens", {}, {}, ["old_token"])
    assert store.get_all("application_access_tokens") == {}


def test_memory_conditional_write_exception_rolls_back_partial_override(monkeypatch):
    """A failing existing write adapter cannot leak a partial conditional batch."""
    store = InMemoryKvStore({"application_access_tokens": {"old_token": "active"}})
    failure = RuntimeError("fixture partial storage failure")

    def fail(namespace, entries):
        store.put(namespace, "old_token", "rotated")
        raise failure

    monkeypatch.setattr(store, "put_many", fail)
    with pytest.raises(RuntimeError) as error:
        store.compare_and_replace(
            "application_access_tokens", {"old_token": "active", "new_token": None},
            {"old_token": "rotated", "new_token": "active"},
        )
    assert error.value is failure
    assert store.get_all("application_access_tokens") == {"old_token": "active"}


@pytest.mark.parametrize("phase", ["insert", "delete"])
def test_sqlite_actual_statement_failure_rolls_back_entire_batch(tmp_path, phase):
    """SQLite trigger failure rolls back already executed writes and releases locks."""
    path = str(tmp_path / "failure.sqlite3")
    stores = [SqliteKvStore(path), SqliteKvStore(path)]
    try:
        stores[0].put_many("application_access_tokens", {"old_token": "active", "delete_token": "revoked"})
        if phase == "insert":
            trigger = "BEFORE INSERT ON idp_config_entries WHEN NEW.entry_key = 'new_token'"
        else:
            trigger = "BEFORE DELETE ON idp_config_entries WHEN OLD.entry_key = 'delete_token'"
        stores[0]._connection.execute(
            f"CREATE TRIGGER fixture_failure {trigger} BEGIN SELECT RAISE(ABORT, 'fixture failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="fixture failure"):
            stores[0].compare_and_replace(
                "application_access_tokens",
                {"old_token": "active", "new_token": None, "delete_token": "revoked"},
                {"old_token": "rotated", "new_token": "active"}, ["delete_token"],
            )
        assert not stores[0]._connection.in_transaction
        assert stores[1].get_all("application_access_tokens") == {"old_token": "active", "delete_token": "revoked"}
        stores[1].put("application_access_tokens", "independent_token", "revoked")
    finally:
        for store in stores:
            store.close()


def test_sqlite_busy_begin_has_no_partial_write_and_can_recover(tmp_path):
    """Actual independent writer contention exits without changing expected state."""
    path = str(tmp_path / "busy.sqlite3")
    stores = [SqliteKvStore(path), SqliteKvStore(path)]
    try:
        stores[0].put("application_access_tokens", "old_token", "active")
        stores[0]._connection.execute("PRAGMA busy_timeout = 25")
        stores[1]._connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            stores[0].compare_and_replace(
                "application_access_tokens", {"old_token": "active", "new_token": None},
                {"old_token": "rotated", "new_token": "active"},
            )
        assert not stores[0]._connection.in_transaction
        stores[1]._connection.rollback()
        assert stores[0].get_all("application_access_tokens") == {"old_token": "active"}
        assert stores[0].compare_and_replace(
            "application_access_tokens", {"old_token": "active", "new_token": None},
            {"old_token": "rotated", "new_token": "active"},
        )
    finally:
        stores[1]._connection.rollback()
        for store in stores:
            store.close()


def test_sqlite_failed_lifecycle_write_does_not_audit_or_compensate(tmp_path, monkeypatch):
    """Actual mid-pair SQL failure preserves active predecessor with zero audit."""
    from app.application_tokens import (
        APPLICATION_TOKEN_NAMESPACE, ApplicationTokenIssueRequest,
        ApplicationTokenService, ApplicationTokenVerifyRequest,
    )
    from app.audit import AuditLogger, InMemoryAuditSink

    store = SqliteKvStore(str(tmp_path / "service-failure.sqlite3"))
    service = ApplicationTokenService(store, AuditLogger(InMemoryAuditSink()))
    request = ApplicationTokenIssueRequest(
        tenant_deployment_id="fixture-deployment", software_unit_id="fixture-rp",
        purpose_code="machine_api", capability_codes=["api.read"],
        lifetime_seconds=3600, actor_identity_id="fixture-operator",
    )
    try:
        issued = service.issue(request)
        baseline = store.get_all(APPLICATION_TOKEN_NAMESPACE)
        audit_calls = []
        monkeypatch.setattr(service, "_audit_event", lambda *args: audit_calls.append(args[0]))
        store._connection.execute(
            "CREATE TRIGGER fixture_failure BEFORE INSERT ON idp_config_entries "
            "WHEN NEW.entry_value LIKE '%rotated%' "
            "BEGIN SELECT RAISE(ABORT, 'fixture lifecycle failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="fixture lifecycle failure"):
            service.rotate(issued.application_token_id, request)
        assert audit_calls == []
        assert store.get_all(APPLICATION_TOKEN_NAMESPACE) == baseline
        assert service.verify(ApplicationTokenVerifyRequest(
            presented_token=issued.plaintext_token,
            tenant_deployment_id="fixture-deployment", software_unit_id="fixture-rp",
        )).active
    finally:
        store.close()
