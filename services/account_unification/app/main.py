"""FastAPI application factory and lifespan wiring.

On startup the app reads the single bootstrap pointer, opens the KV/DB config
store, loads config + secrets from it (no scattered os.getenv), and builds the
live ZITADEL-backed :class:`UnificationService`. A ``/healthz`` endpoint reports
readiness for the compose/k8s probe.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__
from .api import router
from .audit import AuditLogger, SqliteAuditSink
from .bootstrap import load_bootstrap_descriptor, open_config_store
from .config import load_service_config
from .service import UnificationService
from .zitadel_client import HttpManagementApi


def build_service(app: FastAPI) -> None:
    """Wire the service from the bootstrap pointer + KV store."""
    descriptor = load_bootstrap_descriptor()
    store = open_config_store(descriptor)
    config = load_service_config(store, descriptor.namespace)

    api = HttpManagementApi(
        api_base=config.zitadel_api_base,
        mgmt_token=config.zitadel_mgmt_token,
        org_id=config.zitadel_org_id,
        timeout_seconds=config.request_timeout_seconds,
    )
    # Audit sink co-located with the config store for standalone; prod swaps in
    # a Postgres-backed sink writing account_merge_audit.
    audit_path = (descriptor.sqlite_path or "account_unification.db")
    audit = AuditLogger(SqliteAuditSink(audit_path))

    app.state.unification_service = UnificationService(api, audit, config)
    app.state.audit_logger = audit
    app.state.ready = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.ready = False
    build_service(app)
    yield


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
        return {"status": "ok" if getattr(app.state, "ready", False) else "starting",
                "service": "account-unification", "version": __version__}

    app.include_router(router)
    return app


app = create_app()
