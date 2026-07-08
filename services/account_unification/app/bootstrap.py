"""Bootstrap: the single, clearly-marked place an environment variable is read.

``CWL_IDP_BOOTSTRAP`` is *bootstrap transport only* — it names a small YAML file
whose sole job is to point at the real config/secret store (KV or DB). Once the
store is opened, all application config and secrets come from
:mod:`app.kv_store`. No other module reads process environment for config.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .kv_store import KvStore, SqliteKvStore

BOOTSTRAP_ENV_VAR = "CWL_IDP_BOOTSTRAP"


@dataclass(frozen=True)
class BootstrapDescriptor:
    """Where the config store lives and under which namespace to read it."""

    backend: str
    namespace: str
    sqlite_path: str | None = None
    postgres_dsn_secret_ref: str | None = None


def load_bootstrap_descriptor(bootstrap_path: str | None = None) -> BootstrapDescriptor:
    """Read the bootstrap YAML named by ``CWL_IDP_BOOTSTRAP`` (or an override)."""
    resolved = bootstrap_path or os.environ.get(BOOTSTRAP_ENV_VAR)
    if not resolved:
        raise RuntimeError(
            f"{BOOTSTRAP_ENV_VAR} is not set; it must point at the bootstrap "
            "YAML that locates the config store."
        )
    document = yaml.safe_load(Path(resolved).read_text(encoding="utf-8")) or {}
    store = document.get("config_store", {})
    backend = store.get("backend", "sqlite")
    namespace = store.get("namespace", "account_unification")
    sqlite_path = (store.get("sqlite") or {}).get("path")
    postgres_dsn_secret_ref = (store.get("postgres") or {}).get("dsn_secret_ref")
    return BootstrapDescriptor(
        backend=backend,
        namespace=namespace,
        sqlite_path=sqlite_path,
        postgres_dsn_secret_ref=postgres_dsn_secret_ref,
    )


def open_config_store(descriptor: BootstrapDescriptor) -> KvStore:
    """Open the KV/DB config store described by ``descriptor``."""
    if descriptor.backend == "sqlite":
        if not descriptor.sqlite_path:
            raise RuntimeError("sqlite backend requires config_store.sqlite.path")
        return SqliteKvStore(descriptor.sqlite_path)
    # The postgres backend is wired the same way (a PgKvStore reading
    # idp_config_entries); its DSN is fetched from the platform secret manager
    # via descriptor.postgres_dsn_secret_ref. Kept out of the standalone image
    # to avoid a hard psycopg dependency for local runs.
    raise NotImplementedError(
        f"config store backend '{descriptor.backend}' is not built into the "
        "standalone image; use the sqlite backend or provide a PgKvStore."
    )
