"""Durable namespace inventory follows actual encrypted-secret lifecycle."""
from contextlib import closing

from cryptography.fernet import Fernet

from app.keyvault import KeyvaultService, SqliteKeyvaultStore


def test_empty_sqlite_namespace_inventory(tmp_path):
    """An initialized database reports no namespaces until a secret exists."""
    database_path = str(tmp_path / "namespace_inventory.db")
    with closing(SqliteKeyvaultStore(database_path)) as secret_store:
        assert secret_store.list_namespaces() == []


def test_sqlite_namespace_inventory_is_unique_sorted_and_value_free(tmp_path):
    """Multiple keys and a replacement value cannot duplicate a namespace."""
    database_path = str(tmp_path / "namespace_inventory.db")
    with closing(SqliteKeyvaultStore(database_path)) as secret_store:
        secret_service = KeyvaultService(secret_store, Fernet.generate_key())
        secret_service.put_secret("zeta_service", "first_key", "fixture-first-value", actor="test_operator")
        secret_service.put_secret("alpha_service", "first_key", "fixture-second-value", actor="test_operator")
        secret_service.put_secret("zeta_service", "second_key", "fixture-third-value", actor="test_operator")
        secret_service.put_secret("zeta_service", "first_key", "fixture-replacement-value", actor="test_operator")
        assert secret_service.list_namespaces() == ["alpha_service", "zeta_service"]
        assert b"fixture-replacement-value" not in secret_store.get("zeta_service", "first_key")
        assert secret_service.get_secret("zeta_service", "first_key", actor="test_reader") == "fixture-replacement-value"


def test_sqlite_namespace_inventory_survives_restart_and_last_key_deletion(tmp_path):
    """Retired namespaces disappear while deletion audit remains durable."""
    database_path = str(tmp_path / "namespace_inventory.db")
    encryption_key = Fernet.generate_key()
    with closing(SqliteKeyvaultStore(database_path)) as secret_store:
        secret_service = KeyvaultService(secret_store, encryption_key)
        secret_service.put_secret("consumer_service", "first_key", "fixture-first-value", actor="test_operator")
        secret_service.put_secret("consumer_service", "second_key", "fixture-second-value", actor="test_operator")
        assert secret_service.list_namespaces() == ["consumer_service"]

    with closing(SqliteKeyvaultStore(database_path)) as secret_store:
        secret_service = KeyvaultService(secret_store, encryption_key)
        assert secret_service.list_namespaces() == ["consumer_service"]
        assert secret_service.get_secret("consumer_service", "first_key", actor="test_reader") == "fixture-first-value"
        secret_service.delete_secret("consumer_service", "first_key", actor="test_operator")
        assert secret_service.list_namespaces() == ["consumer_service"]
        secret_service.delete_secret("consumer_service", "second_key", actor="test_operator")
        assert secret_service.list_namespaces() == []

    with closing(SqliteKeyvaultStore(database_path)) as secret_store:
        assert secret_store.list_namespaces() == []
        assert [event["action"] for event in secret_store.events_for("consumer_service", "second_key")] == ["secret_set", "secret_deleted"]
