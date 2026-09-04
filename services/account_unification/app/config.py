"""Typed service configuration, loaded entirely from the KV/DB store.

Nothing here reads process environment. :func:`load_service_config` takes an
opened :class:`~app.kv_store.KvStore` (from :mod:`app.bootstrap`) and returns a
frozen config object. Missing or unsafe values fail loudly at startup.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from urllib.parse import urlsplit

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
KEY_REGISTRATION_CLIENT_ID = "registration_client_id"
KEY_REGISTRATION_REDIRECT_URI = "registration_redirect_uri"
KEY_REGISTRATION_ACTION_LIFESPAN_SECONDS = (
    "registration_action_lifespan_seconds"
)
KEY_AUDIT_DATABASE_PATH = "audit_database_path"
KEY_KEYVAULT_DATABASE_PATH = "keyvault_database_path"
KEY_KEYVAULT_PASSPHRASE = "keyvault_passphrase"

MAX_REGISTRATION_ACTION_LIFESPAN_SECONDS = 3600


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
    registration_client_id: str | None = None
    registration_redirect_uri: str | None = None
    registration_action_lifespan_seconds: int = 900
    audit_database_path: str = "/var/lib/account-unification/audit.db"
    # Keyvault stays opt-in: a deployment with no passphrase configured gets
    # keyvault_service=None (503 "not configured"), never a silently-open
    # secret store. See app/keyvault.py and app/keyvault_admin.py.
    keyvault_database_path: str = "/var/lib/account-unification/keyvault.db"
    keyvault_passphrase: str | None = None
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


def _as_positive_int(
    raw: str | None,
    default: int,
    *,
    entry_key: str,
    maximum: int,
) -> int:
    """Parse a positive bounded integer configuration value."""
    candidate = str(default) if raw is None or raw == "" else raw.strip()
    try:
        value = int(candidate)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"config '{entry_key}' must be a positive integer"
        ) from exc
    if str(value) != candidate or value <= 0 or value > maximum:
        raise RuntimeError(
            f"config '{entry_key}' must be a positive integer at or below "
            f"{maximum}"
        )
    return value


def _validated_https_uri(raw_uri: str, *, entry_key: str) -> str:
    """Return an absolute HTTPS URI or fail startup."""
    candidate = raw_uri.strip()
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RuntimeError(
            f"config '{entry_key}' must be an absolute HTTPS URI without "
            "credentials or fragments"
        )
    return candidate


def _registration_settings(
    store: KvStore,
    namespace: str,
    registration_api_token: str | None,
) -> tuple[str | None, str | None, int]:
    """Load all-or-nothing action-email registration settings."""
    if registration_api_token is None:
        return None, None, 900
    client_id = _require(store, namespace, KEY_REGISTRATION_CLIENT_ID)
    if len(client_id) > 255 or any(
        character.isspace() or ord(character) < 0x20
        for character in client_id
    ):
        raise RuntimeError(
            f"config '{KEY_REGISTRATION_CLIENT_ID}' must be one bounded client ID"
        )
    redirect_uri = _validated_https_uri(
        _require(store, namespace, KEY_REGISTRATION_REDIRECT_URI),
        entry_key=KEY_REGISTRATION_REDIRECT_URI,
    )
    lifespan_seconds = _as_positive_int(
        store.get(namespace, KEY_REGISTRATION_ACTION_LIFESPAN_SECONDS),
        900,
        entry_key=KEY_REGISTRATION_ACTION_LIFESPAN_SECONDS,
        maximum=MAX_REGISTRATION_ACTION_LIFESPAN_SECONDS,
    )
    return client_id, redirect_uri, lifespan_seconds


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
    (
        registration_client_id,
        registration_redirect_uri,
        registration_action_lifespan_seconds,
    ) = _registration_settings(
        store,
        namespace,
        registration_api_token,
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
        registration_client_id=registration_client_id,
        registration_redirect_uri=registration_redirect_uri,
        registration_action_lifespan_seconds=(
            registration_action_lifespan_seconds
        ),
        audit_database_path=(
            store.get(namespace, KEY_AUDIT_DATABASE_PATH)
            or "/var/lib/account-unification/audit.db"
        ),
        keyvault_database_path=(
            store.get(namespace, KEY_KEYVAULT_DATABASE_PATH)
            or "/var/lib/account-unification/keyvault.db"
        ),
        keyvault_passphrase=store.get(namespace, KEY_KEYVAULT_PASSPHRASE) or None,
        merge_conflict_policy=merge_conflict_policy,
        allow_unverified_email_link=allow_unverified_email_link,
        request_timeout_seconds=_as_finite_float(
            store.get(namespace, KEY_REQUEST_TIMEOUT_SECONDS),
            10.0,
            entry_key=KEY_REQUEST_TIMEOUT_SECONDS,
            allow_zero=False,
        ),
    )
