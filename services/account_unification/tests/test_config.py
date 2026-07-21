"""Config comes only from the KV store; bootstrap points at it."""
from __future__ import annotations

from contextlib import closing

import pytest

from app.bootstrap import (
    BootstrapDescriptor,
    UnsupportedConfigBackendError,
    load_bootstrap_descriptor,
    open_config_store,
)
from app.config import load_service_config
from app.kv_store import InMemoryKvStore, KvStore, SqliteKvStore


def test_kv_store_protocol_methods_have_concrete_implementations():
    protocol_methods = {
        name
        for name, member in KvStore.__dict__.items()
        if callable(member) and not name.startswith("_")
    }
    assert protocol_methods
    for implementation in (InMemoryKvStore, SqliteKvStore):
        missing = [
            name
            for name in sorted(protocol_methods)
            if not callable(getattr(implementation, name, None))
        ]
        assert missing == []


def test_config_loads_from_kv():
    store = InMemoryKvStore(
        {
            "account_unification": {
                "keycloak_server_url": "http://kc",
                "keycloak_realm": "cwl",
                "keycloak_client_id": "svc",
                "keycloak_client_secret": "secret",
                "operator_api_token": "op-token",
            }
        }
    )
    config = load_service_config(store, "account_unification")
    assert config.keycloak_server_url == "http://kc"
    assert config.keycloak_realm == "cwl"
    # policy default: unverified linking OFF.
    assert config.allow_unverified_email_link is False
    assert config.merge_conflict_policy == "survivor_wins"


def test_missing_required_config_fails_loudly():
    store = InMemoryKvStore({"account_unification": {}})
    with pytest.raises(RuntimeError):
        load_service_config(store, "account_unification")


def test_bootstrap_points_at_sqlite_store(tmp_path):
    db = tmp_path / "store.db"
    with closing(SqliteKvStore(str(db))) as seed:
        seed.put("account_unification", "keycloak_server_url", "http://kc")
        seed.put("account_unification", "keycloak_realm", "cwl")
        seed.put("account_unification", "keycloak_client_id", "svc")
        seed.put("account_unification", "keycloak_client_secret", "secret")
        seed.put("account_unification", "operator_api_token", "op-token")

    bootstrap = tmp_path / "bootstrap.yaml"
    bootstrap.write_text(
        "config_store:\n"
        "  backend: sqlite\n"
        f"  sqlite:\n    path: {db}\n"
        "  namespace: account_unification\n",
        encoding="utf-8",
    )
    descriptor = load_bootstrap_descriptor(str(bootstrap))
    assert descriptor.backend == "sqlite"
    with closing(open_config_store(descriptor)) as store:
        config = load_service_config(store, descriptor.namespace)
        assert config.keycloak_realm == "cwl"


def test_unsupported_standalone_backend_fails_loudly():
    descriptor = BootstrapDescriptor(
        backend="postgres",
        namespace="account_unification",
        postgres_dsn_secret_ref="secret://idp/postgres",
    )
    with pytest.raises(
        UnsupportedConfigBackendError, match="unavailable in the standalone image"
    ):
        open_config_store(descriptor)
