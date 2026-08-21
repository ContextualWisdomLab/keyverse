"""Operator bearer-token authentication for the admin API surface.

The account-unification service exposes privileged operations — account
merge, SCIM provisioning/deactivation, and the federation registry — that must
never be reachable unauthenticated. Every mutating and identity-reading route
requires an operator bearer token; ``/healthz`` stays open for probes.

The token is a shared operator secret loaded from the KV/DB config store
(``operator_api_token``), compared in constant time. This is deliberately a
coarse operator gate: the service already runs behind the ecosystem network
boundary and holds realm-management privileges, so the token gates *access to
the service*, and finer per-action authorization remains Keycloak's job.
"""
from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, Request


def _configured_operator_token(request: Request) -> str | None:
    """Return the operator token wired into application state, if any."""
    return getattr(request.app.state, "operator_api_token", None)


def require_operator_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    """Authenticate an operator bearer token; raise 401/403 otherwise.

    Fails closed: a service started without a configured operator token rejects
    every authenticated request rather than allowing open access.
    """
    expected = _configured_operator_token(request)
    if not expected:
        # No token configured => the privileged surface is unavailable, never
        # implicitly open.
        raise HTTPException(status_code=503, detail="operator authentication unavailable")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="operator bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[len("Bearer ") :].strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=403, detail="invalid operator token")


operator_auth_dependency = Depends(require_operator_token)


def require_runtime_token(
    request: Request,
    runtime_token: str | None = Header(
        default=None,
        alias="X-Keyverse-Runtime-Token",
    ),
) -> None:
    """Authenticate the least-privilege runtime service token."""
    expected = getattr(request.app.state, "runtime_api_token", None)
    if not expected:
        raise HTTPException(status_code=503, detail="runtime authentication unavailable")
    if not runtime_token:
        raise HTTPException(
            status_code=401,
            detail="runtime service token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(runtime_token, expected):
        raise HTTPException(status_code=403, detail="invalid runtime service token")


runtime_auth_dependency = Depends(require_runtime_token)
