"""Coverage for durable Keyvault metadata and failed startup cleanup."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app import main
from app.keyvault import SqliteKeyvaultStore


def test_sqlite_namespace_inventory_uses_durable_rows(tmp_path):
    """The SQLite backend lists distinct namespaces in deterministic order."""
    store = SqliteKeyvaultStore(str(tmp_path / "keyvault.db"))
    store.put("z_service", "second_key", b"ciphertext", actor="fixture")
    store.put("a_service", "first_key", b"ciphertext", actor="fixture")
    store.put("z_service", "third_key", b"ciphertext", actor="fixture")

    assert store.list_namespaces() == ["a_service", "z_service"]
    store.close()


def test_keyvault_startup_closes_store_when_kdf_recovery_fails(monkeypatch, tmp_path):
    """A KDF metadata failure does not leak the just-opened SQLite resource."""
    class FailingStore:
        """Record closure after a deterministic KDF recovery failure."""

        closed = False

        def __init__(self, database_path: str) -> None:
            """Accept the production constructor contract."""
            self.database_path = database_path

        def load_or_create_kdf_parameters(self):
            """Represent corrupt or unsupported durable KDF metadata."""
            raise RuntimeError("fixture KDF recovery failure")

        def close(self) -> None:
            """Record cleanup of the failed startup resource."""
            self.closed = True

    store_holder = {}

    def build_store(database_path: str):
        """Expose the fake instance for post-failure cleanup assertion."""
        store = FailingStore(database_path)
        store_holder["store"] = store
        return store

    monkeypatch.setattr(main, "SqliteKeyvaultStore", build_store)
    config = SimpleNamespace(
        keyvault_passphrase="protected-root",
        keyvault_database_path=str(tmp_path / "nested" / "keyvault.db"),
    )

    with pytest.raises(RuntimeError, match="fixture KDF recovery failure"):
        main._build_keyvault_service(config)

    assert store_holder["store"].closed is True
