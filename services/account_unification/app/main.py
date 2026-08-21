"""FastAPI application factory, dependency wiring, and resource lifecycle.

Startup reads one bootstrap pointer, opens the KV/DB configuration store, and
builds the Keycloak-backed services. Privileged routers are authenticated and
path-validated; ``/healthz`` remains open for orchestrator probes.
"""
from __future__ import annotations

import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from . import __version__
from .api import router
from .application_tokens import (
    ApplicationTokenService,
    application_token_router,
    application_token_runtime_router,
)
from .audit import AuditLogger, SqliteAuditSink
from .auth import operator_auth_dependency, runtime_auth_dependency
from .authorization_plane import AuthorizationPlaneService, authorization_router
from .bootstrap import load_bootstrap_descriptor, open_config_store
from .config import load_service_config
from .directory_federation import directory_federation_router
from .federation import FederationService, federation_router
from .path_security import (
    ScimPathValidationError,
    admin_path_security_dependency,
    scim_path_security_dependency,
    scim_path_validation_exception_handler,
)
from .registration import registration_auth_dependency, registration_router
from .relying_party import relying_party_router
from .relying_party_admin import RelyingPartyHttpAdminApi
from .relying_party_state import RelyingPartyService, relying_party_state_router
from .scim import scim_router
from .service import UnificationService
from .start_login import StartLoginService, start_login_router
from .user_locks import SqliteUserOperationLocks

# Preserve the established wiring seam used by lifecycle tests and embedders
# while constructing the expanded relying-party-capable implementation.
ProductHttpAdminApi = RelyingPartyHttpAdminApi


def _ensure_parent_directory(database_path: str) -> None:
    """Create a filesystem parent for a persistent SQLite database path."""
    if database_path == ":memory:":
        return
    Path(database_path).expanduser().resolve().parent.mkdir(
        parents=True, exist_ok=True
    )


def _user_operation_lock_path(audit_database_path: str) -> tuple[str, bool]:
    """Return a durable sidecar path or one secure temporary test path."""
    if audit_database_path != ":memory:":
        return f"{audit_database_path}.user-operation-locks.sqlite3", False
    descriptor, temporary_path = tempfile.mkstemp(
        prefix="keyverse-user-operation-locks-",
        suffix=".sqlite3",
    )
    os.close(descriptor)
    return temporary_path, True


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
    lock_database_path, temporary_lock_database = _user_operation_lock_path(
        config.audit_database_path
    )
    user_operation_locks = SqliteUserOperationLocks(lock_database_path)

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
    app.state.user_operation_lock_database_path = lock_database_path
    app.state.temporary_user_operation_lock_database = temporary_lock_database
    app.state.federation_service = FederationService(store, api)
    app.state.relying_party_service = RelyingPartyService(store, api)
    app.state.authorization_service = AuthorizationPlaneService(store)
    app.state.start_login_service = StartLoginService(store, config)
    app.state.application_token_service = ApplicationTokenService(store, audit)
    app.state.operator_api_token = config.operator_api_token
    app.state.runtime_api_token = getattr(config, "runtime_api_token", None)
    app.state.registration_api_token = config.registration_api_token
    app.state.registration_client_id = config.registration_client_id
    app.state.registration_redirect_uri = config.registration_redirect_uri
    app.state.registration_action_lifespan_seconds = (
        config.registration_action_lifespan_seconds
    )
    app.state.ready = True


def _close_resource(resource) -> None:
    """Close one optional resource that exposes a callable ``close`` method."""
    close = getattr(resource, "close", None)
    if callable(close):
        close()


def _remove_temporary_lock_database(app: FastAPI) -> None:
    """Remove the secure sidecar used only with an in-memory audit database."""
    if not getattr(app.state, "temporary_user_operation_lock_database", False):
        return
    lock_database_path = getattr(
        app.state,
        "user_operation_lock_database_path",
        None,
    )
    if lock_database_path:
        Path(lock_database_path).unlink(missing_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build live dependencies and release them on application shutdown."""
    app.state.ready = False
    build_service(app)
    try:
        yield
    finally:
        app.state.ready = False
        _close_resource(getattr(app.state, "keycloak_api", None))
        _close_resource(getattr(app.state, "audit_logger", None))
        _close_resource(getattr(app.state, "config_store", None))
        _remove_temporary_lock_database(app)


def create_app(*, wire: bool = True) -> FastAPI:
    """Create the FastAPI app; ``wire=False`` skips startup wiring for tests."""
    app = FastAPI(
        title="cwl-idp account-unification",
        version=__version__,
        lifespan=lifespan if wire else None,
    )
    app.add_exception_handler(
        ScimPathValidationError,
        scim_path_validation_exception_handler,
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
        directory_federation_router,
        dependencies=[
            operator_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(
        relying_party_router,
        dependencies=[
            operator_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(
        relying_party_state_router,
        dependencies=[
            operator_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(
        authorization_router,
    )
    app.include_router(
        start_login_router,
        dependencies=[
            runtime_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(
        application_token_router,
        dependencies=[
            operator_auth_dependency,
            admin_path_security_dependency,
        ],
    )
    app.include_router(application_token_runtime_router)
    app.include_router(
        registration_router,
        dependencies=[registration_auth_dependency],
    )
    return app


app = create_app()
