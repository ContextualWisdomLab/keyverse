"""Per-vault KDF parameters are durable and legacy migration is explicit."""
from __future__ import annotations

import sqlite3

import pytest
from cryptography.fernet import Fernet

from app.keyvault import (
    LegacyKeyvaultMigrationRequiredError,
    SqliteKeyvaultStore,
    derive_fernet_key,
    legacy_fernet_key_for_migration,
)


def test_fresh_vaults_get_different_kdf_salts_for_same_passphrase(tmp_path):
    """A passphrase does not produce one organization-wide encryption key."""
    first_store = SqliteKeyvaultStore(str(tmp_path / "first.db"))
    second_store = SqliteKeyvaultStore(str(tmp_path / "second.db"))

    first_parameters = first_store.load_or_create_kdf_parameters()
    second_parameters = second_store.load_or_create_kdf_parameters()

    assert first_parameters.salt != second_parameters.salt
    assert derive_fernet_key("shared-passphrase", first_parameters) != derive_fernet_key(
        "shared-passphrase", second_parameters
    )
    first_store.close()
    second_store.close()


def test_kdf_parameters_survive_reopen_and_recover_ciphertext(tmp_path):
    """Restart loads the exact parameters used to encrypt existing values."""
    database_path = str(tmp_path / "keyvault.db")
    first_store = SqliteKeyvaultStore(database_path)
    first_parameters = first_store.load_or_create_kdf_parameters()
    first_key = derive_fernet_key("passphrase", first_parameters)
    ciphertext = Fernet(first_key).encrypt(b"fixture-secret")
    first_store.put("service", "credential", ciphertext, actor="fixture")
    first_store.close()

    second_store = SqliteKeyvaultStore(database_path)
    second_parameters = second_store.load_or_create_kdf_parameters()
    second_key = derive_fernet_key("passphrase", second_parameters)

    assert second_parameters == first_parameters
    assert Fernet(second_key).decrypt(second_store.get("service", "credential")) == b"fixture-secret"
    second_store.close()


def test_kdf_metadata_is_versioned_and_persisted_in_vault_database(tmp_path):
    """Recovery does not depend on a process-local random salt."""
    database_path = str(tmp_path / "keyvault.db")
    store = SqliteKeyvaultStore(database_path)
    parameters = store.load_or_create_kdf_parameters()
    store.close()

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT kdf_version, iteration_count, salt FROM keyvault_kdf_config WHERE config_slot = 1"
        ).fetchone()

    assert row == (parameters.version, parameters.iterations, parameters.salt)
    assert parameters.version == 1
    assert parameters.iterations >= 600_000
    assert len(parameters.salt) == 32


def test_nonempty_legacy_vault_fails_closed_without_explicit_migration(tmp_path):
    """Startup must not invent a fresh salt for ciphertext made by the old feature branch."""
    database_path = str(tmp_path / "legacy.db")
    store = SqliteKeyvaultStore(database_path)
    legacy_key = legacy_fernet_key_for_migration("legacy-passphrase")
    store.put(
        "service",
        "credential",
        Fernet(legacy_key).encrypt(b"legacy-secret"),
        actor="legacy-fixture",
    )

    with pytest.raises(LegacyKeyvaultMigrationRequiredError):
        store.load_or_create_kdf_parameters()
    store.close()


def test_explicit_legacy_rewrap_preserves_plaintext_and_records_event(tmp_path):
    """One reviewed migration rewrites legacy ciphertext before KDF metadata becomes authoritative."""
    database_path = str(tmp_path / "legacy.db")
    store = SqliteKeyvaultStore(database_path)
    legacy_key = legacy_fernet_key_for_migration("legacy-passphrase")
    old_ciphertext = Fernet(legacy_key).encrypt(b"legacy-secret")
    store.put("service", "credential", old_ciphertext, actor="legacy-fixture")

    parameters = store.migrate_legacy_kdf("legacy-passphrase", actor="migration-operator")
    new_ciphertext = store.get("service", "credential")
    assert new_ciphertext is not None
    assert new_ciphertext != old_ciphertext
    assert Fernet(derive_fernet_key("legacy-passphrase", parameters)).decrypt(
        new_ciphertext
    ) == b"legacy-secret"
    assert [event["action"] for event in store.events_for("service", "credential")] == [
        "secret_set",
        "secret_rewrapped",
    ]
    store.close()


def test_wrong_passphrase_cannot_partially_migrate_legacy_vault(tmp_path):
    """All legacy ciphertext is authenticated before any durable rewrap begins."""
    database_path = str(tmp_path / "legacy.db")
    store = SqliteKeyvaultStore(database_path)
    legacy_key = legacy_fernet_key_for_migration("correct-passphrase")
    old_ciphertext = Fernet(legacy_key).encrypt(b"legacy-secret")
    store.put("service", "credential", old_ciphertext, actor="legacy-fixture")

    with pytest.raises(Exception):
        store.migrate_legacy_kdf("wrong-passphrase", actor="migration-operator")

    assert store.get("service", "credential") == old_ciphertext
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM keyvault_kdf_config").fetchone() == (0,)
    store.close()
