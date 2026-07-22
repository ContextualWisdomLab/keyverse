"""FastAPI application factory and lifespan wiring.

On startup the app reads the single bootstrap pointer, opens the KV/DB config
store, loads config + secrets from it (no scattered os.getenv), and builds the
live Keycloak-backed :class:`UnificationService`. A ``/healthz`` endpoint reports
readiness for the compose/k8s probe (and additionally probes Keycloak + DB when
wired against a live instance).
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__
from .api import router
from .audit import AuditLogger, SqliteAuditSink
from .auth import operator_auth_dependency
from .bootstrap import load_bootstrap_descriptor, open_config_store
from .config import load_service_config
from .federation import FederationService, federation_router
from .keycloak_client import HttpAdminApi
from .registration import (
    registration_auth_dependency,
    registration_router,
    revoke_bootstrap_passwords,
)
from .scim import scim_router
from .service import UnificationService

logger = logging.getLogger(__name__)


def build_service(app: FastAPI) -> None:
    """Wire the service from the bootstrap pointer + KV store."""
    descriptor = load_bootstrap_descriptor()
    store = open_config_store(descriptor)
    config = load_service_config(store, descriptor.namespace)

    api = HttpAdminApi(
        server_url=config.keycloak_server_url,
        realm=config.keycloak_realm,
        client_id=config.keycloak_client_id,
        client_secret=config.keycloak_client_secret,
        timeout_seconds=config.request_timeout_seconds,
    )
    # The audit sink is a separate writable database: the config store may be
    # (and in compose IS) a read-only mount, so co-locating the audit trail
    # there makes the service unable to start.
    audit = AuditLogger(SqliteAuditSink(config.audit_database_path))

    app.state.unification_service = UnificationService(api, audit, config)
    app.state.audit_logger = audit
    app.state.keycloak_api = api
    # External IdPs (employer ADFS etc.) are runtime data in the KV/DB store,
    # never realm code; this service converges Keycloak from that store.
    app.state.federation_service = FederationService(store, api)
    # Gate the privileged admin surface on the operator bearer token.
    app.state.operator_api_token = config.operator_api_token
    # Separate, narrower token for the headless self-registration surface.
    app.state.registration_api_token = config.registration_api_token
    app.state.password_janitor_interval_seconds = (
        config.password_janitor_interval_seconds
    )
    app.state.ready = True


async def _password_janitor_loop(app: FastAPI, interval_seconds: float) -> None:
    """Periodically revoke bootstrap passwords from passkey-holding accounts."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            result = await asyncio.to_thread(
                revoke_bootstrap_passwords, app.state.keycloak_api
            )
            if result.revoked_passwords:
                logger.info(
                    "password janitor revoked %d bootstrap password(s)",
                    result.revoked_passwords,
                )
        except Exception:
            logger.exception("password janitor pass failed; will retry")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the live service before accepting traffic."""
    app.state.ready = False
    build_service(app)
    janitor_interval = getattr(app.state, "password_janitor_interval_seconds", 0.0)
    janitor_task = (
        asyncio.create_task(_password_janitor_loop(app, janitor_interval))
        if janitor_interval > 0
        else None
    )
    try:
        yield
    finally:
        if janitor_task is not None:
            janitor_task.cancel()


def create_app(*, wire: bool = True) -> FastAPI:
    """Create the FastAPI app. ``wire=False`` skips startup wiring (tests)."""
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
            "status": "ok" if getattr(app.state, "ready", False) else "starting",
            "service": "account-unification",
            "version": __version__,
        }

    # Every privileged router requires the operator bearer token; /healthz is
    # registered directly on the app above and stays open for probes.
    app.include_router(router, dependencies=[operator_auth_dependency])
    app.include_router(scim_router, dependencies=[operator_auth_dependency])
    app.include_router(federation_router, dependencies=[operator_auth_dependency])
    # Self-registration carries its own narrower bearer token so product
    # backends never hold the operator (merge/SCIM/federation) credential.
    app.include_router(
        registration_router, dependencies=[registration_auth_dependency]
    )
    return app


app = create_app()
