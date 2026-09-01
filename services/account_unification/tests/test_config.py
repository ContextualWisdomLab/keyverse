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


def test_kv_store_protocol_methods_have_concrete_implementations() -> None:
    """Every config-store adapter implements the complete public protocol."""
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


def test_config_loads_from_kv() -> None:
    """Required values load and security invariants retain safe defaults."""
    config = load_service_config(_config_store(), "account_unification")
    assert config.keycloak_server_url == "http://kc"
    assert config.keycloak_realm == "cwl"
    assert config.allow_unverified_email_link is False
    assert config.merge_conflict_policy == "survivor_wins"
    assert config.registration_api_token is None
    assert config.runtime_api_token is None


def test_runtime_and_public_issuer_settings_are_loaded_and_separated() -> None:
    """Runtime callers use a distinct token and an explicit HTTPS issuer."""
    config = load_service_config(
        _config_store(
            runtime_api_token="runtime-token",
            public_issuer_url="https://login.example/realms/cwl",
        ),
        "account_unification",
    )
    assert config.runtime_api_token == "runtime-token"
    assert config.public_issuer_url == "https://login.example/realms/cwl"


def test_runtime_token_must_not_equal_operator_token() -> None:
    """Runtime service credentials cannot silently gain operator authority."""
    with pytest.raises(RuntimeError, match="runtime_api_token"):
        load_service_config(
            _config_store(runtime_api_token="operator-token"),
            "account_unification",
        )


def test_runtime_token_must_not_equal_registration_token() -> None:
    """Runtime and registration credentials remain separate trust domains."""
    with pytest.raises(RuntimeError, match="runtime_api_token"):
        load_service_config(
            _config_store(
                runtime_api_token="shared-token",
                registration_api_token="shared-token",
            ),
            "account_unification",
        )


@pytest.mark.parametrize(
    "public_issuer_url",
    [
        "https://login.example/realms/cwl?tenant=other",
        "https://login.example/realms/cwl#fragment",
    ],
)
def test_public_issuer_rejects_query_and_fragment(public_issuer_url: str) -> None:
    """A configured issuer is one canonical HTTPS origin/path, not a URI template."""
    with pytest.raises(RuntimeError, match="public_issuer_url"):
        load_service_config(
            _config_store(public_issuer_url=public_issuer_url),
            "account_unification",
        )


def test_missing_required_config_fails_loudly() -> None:
    """Startup fails when any foundational Keycloak setting is absent."""
    store = InMemoryKvStore({"account_unification": {}})
    with pytest.raises(RuntimeError):
        load_service_config(store, "account_unification")


@pytest.mark.parametrize(
    "raw_value",
    ["0", "-1", "nan", "inf", "-inf", "not-a-number"],
)
def test_request_timeout_must_be_positive_and_finite(raw_value: str) -> None:
    """Nonpositive or nonfinite request timeouts fail startup."""
    store = _config_store(request_timeout_seconds=raw_value)
    with pytest.raises(RuntimeError, match="request_timeout_seconds"):
        load_service_config(store, "account_unification")


def test_registration_token_must_not_equal_operator_token() -> None:
    """Product signup credentials cannot acquire operator authority."""
    store = _config_store(registration_api_token="operator-token")
    with pytest.raises(RuntimeError, match="registration_api_token"):
        load_service_config(store, "account_unification")


def test_registration_requires_complete_action_email_config() -> None:
    """Enabling signup requires an RP, redirect URI, and action-link lifespan."""
    store = _config_store(registration_api_token="registration-token")
    with pytest.raises(RuntimeError, match="registration_client_id"):
        load_service_config(store, "account_unification")


def test_registration_action_email_config_loads() -> None:
    """A complete passwordless enrollment configuration loads atomically."""
    store = _config_store(
        registration_api_token="registration-token",
        registration_client_id="naruon-web",
        registration_redirect_uri="https://naruon.example/auth/passkey-complete",
        registration_action_lifespan_seconds="900",
    )

    config = load_service_config(store, "account_unification")

    assert config.registration_client_id == "naruon-web"
    assert config.registration_redirect_uri == (
        "https://naruon.example/auth/passkey-complete"
    )
    assert config.registration_action_lifespan_seconds == 900


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://naruon.example/callback",
        "javascript:alert(1)",
        "//naruon.example/callback",
        "https:///missing-host",
    ],
)
def test_registration_redirect_uri_requires_absolute_https(
    redirect_uri: str,
) -> None:
    """Action emails cannot redirect to non-HTTPS or hostless locations."""
    store = _config_store(
        registration_api_token="registration-token",
        registration_client_id="naruon-web",
        registration_redirect_uri=redirect_uri,
        registration_action_lifespan_seconds="900",
    )
    with pytest.raises(RuntimeError, match="registration_redirect_uri"):
        load_service_config(store, "account_unification")


@pytest.mark.parametrize(
    "raw_value",
    ["0", "-1", "1.5", "nan", "inf", "not-a-number"],
)
def test_registration_action_lifespan_must_be_positive_integer(
    raw_value: str,
) -> None:
    """Keycloak action-email lifespan must be a bounded integer duration."""
    store = _config_store(
        registration_api_token="registration-token",
        registration_client_id="naruon-web",
        registration_redirect_uri="https://naruon.example/auth/passkey-complete",
        registration_action_lifespan_seconds=raw_value,
    )
    with pytest.raises(RuntimeError, match="registration_action_lifespan_seconds"):
        load_service_config(store, "account_unification")


@pytest.mark.parametrize("raw_value", ["true", "1", "yes", "on"])
def test_unverified_email_link_policy_cannot_be_enabled(raw_value: str) -> None:
    """An unverified-email link policy is rejected even when explicitly set."""
    store = _config_store(allow_unverified_email_link=raw_value)
    with pytest.raises(RuntimeError, match="allow_unverified_email_link"):
        load_service_config(store, "account_unification")


def test_invalid_boolean_text_fails_loudly() -> None:
    """Ambiguous boolean configuration cannot silently become false."""
    store = _config_store(allow_unverified_email_link="definitely")
    with pytest.raises(RuntimeError, match="allow_unverified_email_link"):
        load_service_config(store, "account_unification")


def test_only_implemented_merge_conflict_policy_is_accepted() -> None:
    """Unknown conflict policies cannot claim behavior the service lacks."""
    store = _config_store(merge_conflict_policy="duplicate_wins")
    with pytest.raises(RuntimeError, match="merge_conflict_policy"):
        load_service_config(store, "account_unification")


def test_bootstrap_points_at_sqlite_store(tmp_path) -> None:
    """The bootstrap descriptor opens the configured SQLite namespace."""
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


def test_unsupported_standalone_backend_fails_loudly() -> None:
    """A deployment cannot select an adapter absent from its image."""
    descriptor = BootstrapDescriptor(
        backend="postgres",
        namespace="account_unification",
        postgres_dsn_secret_ref="secret://idp/postgres",
    )
    with pytest.raises(
        UnsupportedConfigBackendError, match="unavailable in the standalone image"
    ):
        open_config_store(descriptor)
