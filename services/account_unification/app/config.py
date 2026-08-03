"""Typed service configuration, loaded entirely from the KV/DB store.

Nothing here reads process environment. :func:`load_service_config` takes an
opened :class:`~app.kv_store.KvStore` (from :mod:`app.bootstrap`) and returns a
frozen config object. Missing or unsafe values fail loudly at startup.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .kv_store import KvStore

# Keys expected in the KV namespace. Two-word snake_case where they map to
# stored/DB objects.
KEY_KEYCLOAK_SERVER_URL = "keycloak_server_url"
KEY_KEYCLOAK_REALM = "keycloak_realm"
KEY_KEYCLOAK_CLIENT_ID = "keycloak_client_id"
KEY_KEYCLOAK_CLIENT_SECRET = "keycloak_client_secret"
KEY_MERGE_CONFLICT_POLICY = "merge_conflict_policy"
KEY_ALLOW_UNVERIFIED_LINK = "allow_unverified_email_link"
KEY_REQUEST_TIMEOUT_SECONDS = "request_timeout_seconds"
KEY_OPERATOR_API_TOKEN = "operator_api_token"
KEY_REGISTRATION_API_TOKEN = "registration_api_token"
KEY_AUDIT_DATABASE_PATH = "audit_database_path"
KEY_PASSWORD_JANITOR_INTERVAL_SECONDS = "password_janitor_interval_seconds"


@dataclass(frozen=True)
class ServiceConfig:
    """Validated runtime settings loaded from the config store."""

    # Keycloak Admin REST API wiring. The service authenticates to the realm
    # token endpoint with a confidential service-account client.
    keycloak_server_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: str
    # Privileged and product registration surfaces deliberately use different
    # bearer credentials so relying products never acquire operator authority.
    operator_api_token: str
    registration_api_token: str | None = None
    # Zero disables the periodic task; a manual janitor endpoint remains.
    password_janitor_interval_seconds: float = 300.0
    audit_database_path: str = "/var/lib/account-unification/audit.db"
    merge_conflict_policy: str = "survivor_wins"
    # This is an invariant, not a deployer-selectable feature. The field remains
    # so audit/config evidence can prove it was explicitly disabled.
    allow_unverified_email_link: bool = False
    request_timeout_seconds: float = 10.0


def _require(store: KvStore, namespace: str, entry_key: str) -> str:
    """Read a required config value or fail startup with context."""
    value = store.get(namespace, entry_key)
    if value is None or value == "":
        raise RuntimeError(
            f"required config '{entry_key}' missing in KV namespace '{namespace}'"
        )
    return value


def _as_bool(
    raw: str | None,
    default: bool,
    *,
    entry_key: str,
) -> bool:
    """Parse one explicit boolean or fail startup on ambiguous text."""
    if raw is None or raw == "":
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"config '{entry_key}' must be a boolean")


def _as_finite_float(
    raw: str | None,
    default: float,
    *,
    entry_key: str,
    allow_zero: bool,
) -> float:
    """Parse a runtime duration and reject negative, NaN, or infinite values."""
    candidate = str(default) if raw is None or raw == "" else raw
    try:
        value = float(candidate)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"config '{entry_key}' must be a finite number"
        ) from exc
    if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise RuntimeError(
            f"config '{entry_key}' must be a finite {qualifier} number"
        )
    return value


def load_service_config(store: KvStore, namespace: str) -> ServiceConfig:
    """Build and validate the :class:`ServiceConfig` from the KV store."""
    operator_api_token = _require(store, namespace, KEY_OPERATOR_API_TOKEN)
    registration_api_token = (
        store.get(namespace, KEY_REGISTRATION_API_TOKEN) or None
    )
    if registration_api_token == operator_api_token:
        raise RuntimeError(
            "config 'registration_api_token' must differ from "
            "'operator_api_token'"
        )

    allow_unverified_email_link = _as_bool(
        store.get(namespace, KEY_ALLOW_UNVERIFIED_LINK),
        default=False,
        entry_key=KEY_ALLOW_UNVERIFIED_LINK,
    )
    if allow_unverified_email_link:
        raise RuntimeError(
            "config 'allow_unverified_email_link' must remain false"
        )

    merge_conflict_policy = (
        store.get(namespace, KEY_MERGE_CONFLICT_POLICY) or "survivor_wins"
    )
    if merge_conflict_policy != "survivor_wins":
        raise RuntimeError(
            "config 'merge_conflict_policy' must be 'survivor_wins'"
        )

    return ServiceConfig(
        keycloak_server_url=_require(store, namespace, KEY_KEYCLOAK_SERVER_URL),
        keycloak_realm=_require(store, namespace, KEY_KEYCLOAK_REALM),
        keycloak_client_id=_require(store, namespace, KEY_KEYCLOAK_CLIENT_ID),
        keycloak_client_secret=_require(
            store, namespace, KEY_KEYCLOAK_CLIENT_SECRET
        ),
        operator_api_token=operator_api_token,
        registration_api_token=registration_api_token,
        password_janitor_interval_seconds=_as_finite_float(
            store.get(namespace, KEY_PASSWORD_JANITOR_INTERVAL_SECONDS),
            300.0,
            entry_key=KEY_PASSWORD_JANITOR_INTERVAL_SECONDS,
            allow_zero=True,
        ),
        audit_database_path=(
            store.get(namespace, KEY_AUDIT_DATABASE_PATH)
            or "/var/lib/account-unification/audit.db"
        ),
        merge_conflict_policy=merge_conflict_policy,
        allow_unverified_email_link=allow_unverified_email_link,
        request_timeout_seconds=_as_finite_float(
            store.get(namespace, KEY_REQUEST_TIMEOUT_SECONDS),
            10.0,
            entry_key=KEY_REQUEST_TIMEOUT_SECONDS,
            allow_zero=False,
        ),
    )
