"""Config comes only from the KV store; bootstrap points at it."""
from __future__ import annotations

import pytest

from app.bootstrap import load_bootstrap_descriptor, open_config_store
from app.config import load_service_config
from app.kv_store import InMemoryKvStore, SqliteKvStore


def test_config_loads_from_kv():
    store = InMemoryKvStore(
        {
            "account_unification": {
                "keycloak_server_url": "http://kc",
                "keycloak_realm": "cwl",
                "keycloak_client_id": "svc",
                "keycloak_client_secret": "secret",
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
    seed = SqliteKvStore(str(db))
    seed.put("account_unification", "keycloak_server_url", "http://kc")
    seed.put("account_unification", "keycloak_realm", "cwl")
    seed.put("account_unification", "keycloak_client_id", "svc")
    seed.put("account_unification", "keycloak_client_secret", "secret")

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
    store = open_config_store(descriptor)
    config = load_service_config(store, descriptor.namespace)
    assert config.keycloak_realm == "cwl"
