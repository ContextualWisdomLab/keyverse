"""FastAPI application factory, dependency wiring, and resource lifecycle.

Startup reads one bootstrap pointer, opens the KV/DB configuration store, builds
the Keycloak-backed services, and starts the bounded credential janitor. The
privileged routers are authenticated and path-validated; ``/healthz`` remains
open for orchestrator probes.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI

from . import __version__
from .api import router
from .audit import AuditLogger, SqliteAuditSink
from .auth import operator_auth_dependency
from .bootstrap import load_bootstrap_descriptor, open_config_store
from .config import load_service_config
from .federation import FederationService, federation_router
from .path_security import (
    admin_path_security_dependency,
    scim_path_security_dependency,
)
from .product_keycloak_client import ProductHttpAdminApi
from .registration import (
    registration_auth_dependency,
    registration_router,
    revoke_bootstrap_passwords,
)
from .scim import scim_router
from .service import UnificationService
from .user_locks import SqliteUserOperationLocks

logger = logging.getLogger(__name__)


def _ensure_parent_directory(database_path: str) -> None:
    """Create a filesystem parent for a persistent SQLite database path."""
    if database_path == ":memory:":
        return
    Path(database_path).expanduser().resolve().parent.mkdir(
        parents=True, exist_ok=True
    )


def build_service(app: FastAPI) -> None:
    """Wire all live service dependencies from the bootstrap configuration."""
    descriptor = load_bootstrap_descriptor()
    store = open_config_store(descriptor)
    config = load_service_config(store, descriptor.namespace)
    _ensure_parent_directory(config.audit_database_path)

    api = ProductHttpAdminApi(
        server_url=config.keycloak_server_url,
        realm=config.keycloak_realm,
        client_id=config.keycloak_client_id,
        client_secret=config.keycloak_client_secret,
        timeout_seconds=config.request_timeout_seconds,
    )
    audit = AuditLogger(SqliteAuditSink(config.audit_database_path))
    user_operation_locks = SqliteUserOperationLocks(
        f"{config.audit_database_path}.user-operation-locks.sqlite3"
    )

    app.state.config_store = store
    app.state.unification_service = UnificationService(
        api,
        audit,
        config,
        user_operation_locks,
    )
    app.state.audit_logger = audit
    app.state.keycloak_api = api
    app.state.user_operation_locks = user_operation_locks
    app.state.federation_service = FederationService(store, api)
    app.state.operator_api_token = config.operator_api_token
    app.state.registration_api_token = config.registration_api_token
    app.state.password_janitor_interval_seconds = (
        config.password_janitor_interval_seconds
    )
    app.state.ready = True


async def _credential_janitor_loop(
    app: FastAPI, interval_seconds: float
) -> None:
    """Periodically remove bootstrap credentials from passkey accounts."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            result = await asyncio.to_thread(
                revoke_bootstrap_passwords, app.state.keycloak_api
            )
            if result.removed_bootstrap_credentials:
                # Log only an aggregate count. No credential material, user ID,
                # email address, or other account-linked value enters the log.
                logger.info(
                    "credential janitor removed %d bootstrap credential(s)",
                    result.removed_bootstrap_credentials,
                )
        except Exception:
            logger.exception("credential janitor pass failed; will retry")


def _close_resource(resource) -> None:
    """Close one optional resource that exposes a callable ``close`` method."""
    close = getattr(resource, "close", None)
    if callable(close):
        close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build live dependencies and release them on application shutdown."""
    app.state.ready = False
    build_service(app)
    janitor_interval = getattr(
        app.state, "password_janitor_interval_seconds", 0.0
    )
    janitor_task = (
        asyncio.create_task(
            _credential_janitor_loop(app, janitor_interval),
            name="credential-janitor",
        )
        if janitor_interval > 0
        else None
    )
    try:
        yield
    finally:
        app.state.ready = False
        if janitor_task is not None:
            janitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await janitor_task
        _close_resource(getattr(app.state, "keycloak_api", None))
        _close_resource(getattr(app.state, "audit_logger", None))
        _close_resource(getattr(app.state, "config_store", None))


def create_app(*, wire: bool = True) -> FastAPI:
    """Create the FastAPI app; ``wire=False`` skips startup wiring for tests."""
    app = FastAPI(
        title="cwl-idp account-unification",
        version=__version__,
        lifespan=lifespan if wire else None,
    )
    if not wire:
        app.state.ready = True

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict:
        """Return readiness status for container and orchestration probes."""
        return {
            "status": (
                "ok" if getattr(app.state, "ready", False) else "starting"
            ),
            "service": "account-unification",
            "version": __version__,
        }

    app.include_router(
        router,
        dependencies=[
            operator_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(
        scim_router,
        dependencies=[
            operator_auth_dependency,
            scim_path_security_dependency,
        ],
    )
    app.include_router(
        federation_router,
        dependencies=[
            operator_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(
        registration_router,
        dependencies=[registration_auth_dependency],
    )
    return app


app = create_app()
