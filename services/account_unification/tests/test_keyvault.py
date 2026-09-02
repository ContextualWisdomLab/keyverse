"""Keyvault: encrypted-at-rest namespaced secret storage, in-memory and SQLite."""
from __future__ import annotations

import sqlite3

import pytest

from app.keyvault import (
    InMemoryKeyvaultAuditSink,
    InMemoryKeyvaultStore,
    KeyvaultAuditSink,
    KeyvaultService,
    KeyvaultStore,
    SecretNotFoundError,
    SqliteKeyvaultAuditSink,
    SqliteKeyvaultStore,
    derive_fernet_key,
)


def test_store_protocol_methods_have_concrete_implementations():
    """Every backend implements the complete persistence protocol."""
    protocol_methods = {
        name
        for name, member in KeyvaultStore.__dict__.items()
        if callable(member) and not name.startswith("_")
    }
    assert protocol_methods
    for implementation in (InMemoryKeyvaultStore, SqliteKeyvaultStore):
        missing = [
            name
            for name in sorted(protocol_methods)
            if not callable(getattr(implementation, name, None))
        ]
        assert missing == []


def test_audit_sink_protocol_methods_have_concrete_implementations():
    """Every audit sink implements the complete event-logging protocol."""
    protocol_methods = {
        name
        for name, member in KeyvaultAuditSink.__dict__.items()
        if callable(member) and not name.startswith("_")
    }
    assert protocol_methods
    for implementation in (InMemoryKeyvaultAuditSink, SqliteKeyvaultAuditSink):
        missing = [
            name
            for name in sorted(protocol_methods)
            if not callable(getattr(implementation, name, None))
        ]
        assert missing == []


@pytest.fixture(params=["memory", "sqlite"])
def keyvault_service(request, tmp_path) -> KeyvaultService:
    """Return a KeyvaultService over each supported backend pair."""
    if request.param == "memory":
        store = InMemoryKeyvaultStore()
        audit = InMemoryKeyvaultAuditSink()
    else:
        store = SqliteKeyvaultStore(str(tmp_path / "keyvault.db"))
        audit = SqliteKeyvaultAuditSink(str(tmp_path / "keyvault-audit.db"))
    service = KeyvaultService(store, audit, derive_fernet_key("test-passphrase"))
    yield service
    service.close()


def test_put_then_get_roundtrips_the_plaintext_value(keyvault_service):
    """A secret written through the service reads back byte-identical."""
    keyvault_service.put_secret(
        "contextual-orchestrator", "OPENAI_API_KEY", "sk-live-123", actor="operator1"
    )
    assert (
        keyvault_service.get_secret(
            "contextual-orchestrator", "OPENAI_API_KEY", actor="operator1"
        )
        == "sk-live-123"
    )


def test_get_missing_secret_raises_not_found(keyvault_service):
    with pytest.raises(SecretNotFoundError):
        keyvault_service.get_secret("ns", "absent", actor="operator1")


def test_delete_missing_secret_raises_not_found(keyvault_service):
    with pytest.raises(SecretNotFoundError):
        keyvault_service.delete_secret("ns", "absent", actor="operator1")


def test_delete_then_get_raises_not_found(keyvault_service):
    keyvault_service.put_secret("ns", "key1", "value1", actor="operator1")
    keyvault_service.delete_secret("ns", "key1", actor="operator1")
    with pytest.raises(SecretNotFoundError):
        keyvault_service.get_secret("ns", "key1", actor="operator1")


def test_list_secrets_returns_metadata_only_never_the_value(keyvault_service):
    keyvault_service.put_secret("ns", "key1", "super-secret-value", actor="operator1")
    keyvault_service.put_secret("ns", "key2", "another-secret", actor="operator1")
    listing = keyvault_service.list_secrets("ns")
    assert {item.secret_key for item in listing} == {"key1", "key2"}
    assert not any("super-secret-value" in repr(item) for item in listing)
    assert not any("another-secret" in repr(item) for item in listing)


def test_list_secrets_is_namespace_scoped(keyvault_service):
    keyvault_service.put_secret("tenant-a", "shared-key", "a-value", actor="operator1")
    keyvault_service.put_secret("tenant-b", "shared-key", "b-value", actor="operator1")
    assert [item.secret_key for item in keyvault_service.list_secrets("tenant-a")] == ["shared-key"]
    assert keyvault_service.get_secret("tenant-a", "shared-key", actor="op") == "a-value"
    assert keyvault_service.get_secret("tenant-b", "shared-key", actor="op") == "b-value"


def test_audit_history_records_set_read_and_delete_in_order(keyvault_service):
    keyvault_service.put_secret("ns", "key1", "value1", actor="alice")
    keyvault_service.get_secret("ns", "key1", actor="bob")
    keyvault_service.delete_secret("ns", "key1", actor="alice")
    history = keyvault_service.audit_history("ns", "key1")
    assert [event["action"] for event in history] == [
        "secret_set",
        "secret_read",
        "secret_deleted",
    ]
    assert [event["actor"] for event in history] == ["alice", "bob", "alice"]
    # No event ever carries the plaintext or ciphertext value.
    assert all("value1" not in str(event.values()) for event in history)


def test_overwriting_a_secret_replaces_the_value_and_keeps_one_metadata_row(keyvault_service):
    keyvault_service.put_secret("ns", "key1", "first", actor="operator1")
    keyvault_service.put_secret("ns", "key1", "second", actor="operator1")
    assert keyvault_service.get_secret("ns", "key1", actor="operator1") == "second"
    assert len(keyvault_service.list_secrets("ns")) == 1


def test_wrong_passphrase_cannot_decrypt_another_services_secrets(tmp_path):
    """Encryption is real: a different Fernet key cannot read the ciphertext."""
    shared_store = SqliteKeyvaultStore(str(tmp_path / "shared.db"))
    writer = KeyvaultService(
        shared_store, InMemoryKeyvaultAuditSink(), derive_fernet_key("correct-horse")
    )
    writer.put_secret("ns", "key1", "top-secret", actor="operator1")

    reader = KeyvaultService(
        shared_store, InMemoryKeyvaultAuditSink(), derive_fernet_key("wrong-passphrase")
    )
    with pytest.raises(Exception):
        reader.get_secret("ns", "key1", actor="operator1")
    writer.close()


def test_sqlite_store_persists_across_reopen(tmp_path):
    database_path = str(tmp_path / "keyvault.db")
    first = SqliteKeyvaultStore(database_path)
    first.put("ns", "key1", b"ciphertext-bytes")
    first.close()

    second = SqliteKeyvaultStore(database_path)
    assert second.get("ns", "key1") == b"ciphertext-bytes"
    second.close()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM keyvault_secrets"
        ).fetchone() == (1,)


def test_sqlite_audit_sink_persists_across_reopen(tmp_path):
    database_path = str(tmp_path / "keyvault-audit.db")
    first = SqliteKeyvaultAuditSink(database_path)
    first.record(namespace="ns", secret_key="key1", action="secret_set", actor="operator1")
    first.close()

    second = SqliteKeyvaultAuditSink(database_path)
    events = second.events_for("ns", "key1")
    assert len(events) == 1 and events[0]["action"] == "secret_set"
    second.close()


def test_derive_fernet_key_is_deterministic_for_the_same_passphrase():
    assert derive_fernet_key("same-passphrase") == derive_fernet_key("same-passphrase")
    assert derive_fernet_key("passphrase-a") != derive_fernet_key("passphrase-b")
