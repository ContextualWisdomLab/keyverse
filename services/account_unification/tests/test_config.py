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
                "zitadel_api_base": "http://z",
                "zitadel_mgmt_token": "tok",
                "zitadel_org_id": "org",
            }
        }
    )
    config = load_service_config(store, "account_unification")
    assert config.zitadel_api_base == "http://z"
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
    seed.put("account_unification", "zitadel_api_base", "http://z")
    seed.put("account_unification", "zitadel_mgmt_token", "tok")
    seed.put("account_unification", "zitadel_org_id", "org")

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
    assert config.zitadel_org_id == "org"
