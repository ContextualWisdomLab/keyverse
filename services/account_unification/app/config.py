"""Typed service configuration, loaded entirely from the KV/DB store.

Nothing here reads process environment. :func:`load_service_config` takes an
opened :class:`~app.kv_store.KvStore` (from :mod:`app.bootstrap`) and returns a
frozen config object. Missing required keys fail loudly at startup.
"""
from __future__ import annotations

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
    """Runtime settings loaded from the config store."""

    # Keycloak Admin REST API wiring. The service authenticates to the realm
    # token endpoint with a confidential service-account client (client
    # credentials) that holds realm-management view-users/manage-users roles.
    keycloak_server_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: str
    # Shared operator bearer token gating the privileged admin API surface
    # (merge, SCIM, federation, identity reads). Required: the service must not
    # start with an open privileged surface.
    operator_api_token: str
    # Bearer token for the headless self-registration surface, held by product
    # frontend backends (e.g. Naruon). Optional: deployments without
    # self-signup leave it unset and the surface answers 503, never open.
    registration_api_token: str | None = None
    # Seconds between bootstrap-password janitor passes; 0 disables the
    # periodic task (the operator endpoint still runs passes on demand).
    password_janitor_interval_seconds: float = 300.0
    # Audit sink location. Must NOT live inside the read-only /bootstrap
    # mount: the config store and the audit trail have different write needs.
    audit_database_path: str = "/var/lib/account-unification/audit.db"
    merge_conflict_policy: str = "survivor_wins"
    # Hard default False: the ecosystem policy forbids linking/merging on an
    # unverified email. Present as config only so audits can prove it is off.
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


def _as_bool(raw: str | None, default: bool) -> bool:
    """Parse a store value as a permissive boolean."""
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_service_config(store: KvStore, namespace: str) -> ServiceConfig:
    """Build the :class:`ServiceConfig` from the KV store."""
    return ServiceConfig(
        keycloak_server_url=_require(store, namespace, KEY_KEYCLOAK_SERVER_URL),
        keycloak_realm=_require(store, namespace, KEY_KEYCLOAK_REALM),
        keycloak_client_id=_require(store, namespace, KEY_KEYCLOAK_CLIENT_ID),
        keycloak_client_secret=_require(store, namespace, KEY_KEYCLOAK_CLIENT_SECRET),
        operator_api_token=_require(store, namespace, KEY_OPERATOR_API_TOKEN),
        registration_api_token=store.get(namespace, KEY_REGISTRATION_API_TOKEN) or None,
        password_janitor_interval_seconds=float(
            store.get(namespace, KEY_PASSWORD_JANITOR_INTERVAL_SECONDS) or "300"
        ),
        audit_database_path=store.get(namespace, KEY_AUDIT_DATABASE_PATH)
        or "/var/lib/account-unification/audit.db",
        merge_conflict_policy=store.get(namespace, KEY_MERGE_CONFLICT_POLICY)
        or "survivor_wins",
        allow_unverified_email_link=_as_bool(
            store.get(namespace, KEY_ALLOW_UNVERIFIED_LINK), default=False
        ),
        request_timeout_seconds=float(
            store.get(namespace, KEY_REQUEST_TIMEOUT_SECONDS) or "10.0"
        ),
    )
