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


def _config_store(**overrides: str) -> InMemoryKvStore:
    """Build one complete config namespace with selected overrides."""
    entries = {
        "keycloak_server_url": "http://kc",
        "keycloak_realm": "cwl",
        "keycloak_client_id": "svc",
        "keycloak_client_secret": "secret",
        "operator_api_token": "operator-token",
    }
    entries.update(overrides)
    return InMemoryKvStore({"account_unification": entries})


def test_config_loads_from_kv():
    config = load_service_config(_config_store(), "account_unification")
    assert config.keycloak_server_url == "http://kc"
    assert config.keycloak_realm == "cwl"
    # policy default: unverified linking OFF.
    assert config.allow_unverified_email_link is False
    assert config.merge_conflict_policy == "survivor_wins"


def test_missing_required_config_fails_loudly():
    store = InMemoryKvStore({"account_unification": {}})
    with pytest.raises(RuntimeError):
        load_service_config(store, "account_unification")


@pytest.mark.parametrize(
    "raw_value",
    ["0", "-1", "nan", "inf", "-inf", "not-a-number"],
)
def test_request_timeout_must_be_positive_and_finite(raw_value):
    store = _config_store(request_timeout_seconds=raw_value)
    with pytest.raises(RuntimeError, match="request_timeout_seconds"):
        load_service_config(store, "account_unification")


@pytest.mark.parametrize(
    "raw_value",
    ["-1", "nan", "inf", "-inf", "not-a-number"],
)
def test_janitor_interval_must_be_non_negative_and_finite(raw_value):
    store = _config_store(password_janitor_interval_seconds=raw_value)
    with pytest.raises(RuntimeError, match="password_janitor_interval_seconds"):
        load_service_config(store, "account_unification")


def test_zero_janitor_interval_disables_periodic_task_cleanly():
    store = _config_store(password_janitor_interval_seconds="0")
    config = load_service_config(store, "account_unification")
    assert config.password_janitor_interval_seconds == 0.0


def test_registration_token_must_not_equal_operator_token():
    store = _config_store(registration_api_token="operator-token")
    with pytest.raises(RuntimeError, match="registration_api_token"):
        load_service_config(store, "account_unification")


@pytest.mark.parametrize("raw_value", ["true", "1", "yes", "on"])
def test_unverified_email_link_policy_cannot_be_enabled(raw_value):
    store = _config_store(allow_unverified_email_link=raw_value)
    with pytest.raises(RuntimeError, match="allow_unverified_email_link"):
        load_service_config(store, "account_unification")


def test_invalid_boolean_text_fails_loudly():
    store = _config_store(allow_unverified_email_link="definitely")
    with pytest.raises(RuntimeError, match="allow_unverified_email_link"):
        load_service_config(store, "account_unification")


def test_only_implemented_merge_conflict_policy_is_accepted():
    store = _config_store(merge_conflict_policy="duplicate_wins")
    with pytest.raises(RuntimeError, match="merge_conflict_policy"):
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
