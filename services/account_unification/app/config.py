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
KEY_ZITADEL_API_BASE = "zitadel_api_base"
KEY_ZITADEL_MGMT_TOKEN = "zitadel_mgmt_token"
KEY_ZITADEL_ORG_ID = "zitadel_org_id"
KEY_MERGE_CONFLICT_POLICY = "merge_conflict_policy"
KEY_ALLOW_UNVERIFIED_LINK = "allow_unverified_email_link"
KEY_REQUEST_TIMEOUT_SECONDS = "request_timeout_seconds"


@dataclass(frozen=True)
class ServiceConfig:
    zitadel_api_base: str
    zitadel_mgmt_token: str
    zitadel_org_id: str
    merge_conflict_policy: str = "survivor_wins"
    # Hard default False: the ecosystem policy forbids linking/merging on an
    # unverified email. Present as config only so audits can prove it is off.
    allow_unverified_email_link: bool = False
    request_timeout_seconds: float = 10.0


def _require(store: KvStore, namespace: str, entry_key: str) -> str:
    value = store.get(namespace, entry_key)
    if value is None or value == "":
        raise RuntimeError(
            f"required config '{entry_key}' missing in KV namespace '{namespace}'"
        )
    return value


def _as_bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_service_config(store: KvStore, namespace: str) -> ServiceConfig:
    """Build the :class:`ServiceConfig` from the KV store."""
    return ServiceConfig(
        zitadel_api_base=_require(store, namespace, KEY_ZITADEL_API_BASE),
        zitadel_mgmt_token=_require(store, namespace, KEY_ZITADEL_MGMT_TOKEN),
        zitadel_org_id=_require(store, namespace, KEY_ZITADEL_ORG_ID),
        merge_conflict_policy=store.get(namespace, KEY_MERGE_CONFLICT_POLICY)
        or "survivor_wins",
        allow_unverified_email_link=_as_bool(
            store.get(namespace, KEY_ALLOW_UNVERIFIED_LINK), default=False
        ),
        request_timeout_seconds=float(
            store.get(namespace, KEY_REQUEST_TIMEOUT_SECONDS) or "10.0"
        ),
    )
