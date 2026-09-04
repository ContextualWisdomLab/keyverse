"""FastAPI routes for the Keyvault namespaced secrets store.

Write/delete/list, each behind the same operator bearer token and
opaque-path-segment validation already required for every other privileged
router (see ``main.py``'s ``include_router`` wiring). No administrator route
returns plaintext. A future service-to-service read API must first bind a
verified workload identity to one namespace and one explicit read scope.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .keyvault import KeyvaultService, SecretNotFoundError

router = APIRouter(prefix="/keyvault", tags=["keyvault"])


class SecretWrite(BaseModel):
    """Request body for creating or replacing one secret."""

    value: str = Field(min_length=1, max_length=65536)


class SecretMetadataOut(BaseModel):
    """One secret's non-secret listing information."""

    namespace: str
    secret_key: str
    updated_at: float


def get_keyvault(request: Request) -> KeyvaultService:
    """Return the request-scoped Keyvault service.

    503 (not 404) when unconfigured: an operator who has not set a Keyvault
    passphrase gets "feature unavailable," never a misleading "no such
    secret" that would suggest the feature exists but is merely empty.
    """
    service = getattr(request.app.state, "keyvault_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="keyvault not configured")
    return service


def _actor(request: Request) -> str:
    """Return an opaque actor label for the audit trail.

    The operator token is a single shared secret (see ``auth.py``), so there
    is no per-operator identity to attribute writes to yet; recording the
    caller's address keeps the audit trail non-empty and honest about what
    is actually known, rather than fabricating an operator name.
    """
    client = request.client
    return client.host if client else "unknown"


@router.get("", response_model=list[str])
def list_namespaces(
    keyvault: KeyvaultService = Depends(get_keyvault),
) -> list[str]:
    """List non-empty consumer namespaces without exposing secret material."""
    return keyvault.list_namespaces()


@router.put("/{namespace}/{secret_key}", response_model=SecretMetadataOut)
def put_secret(
    namespace: str,
    secret_key: str,
    body: SecretWrite,
    request: Request,
    keyvault: KeyvaultService = Depends(get_keyvault),
) -> SecretMetadataOut:
    """Create or replace one secret; always audited, never partially applied."""
    metadata = keyvault.put_secret(namespace, secret_key, body.value, actor=_actor(request))
    return SecretMetadataOut(
        namespace=metadata.namespace,
        secret_key=metadata.secret_key,
        updated_at=metadata.updated_at,
    )


@router.get("/{namespace}", response_model=list[SecretMetadataOut])
def list_secrets(
    namespace: str, keyvault: KeyvaultService = Depends(get_keyvault)
) -> list[SecretMetadataOut]:
    """List one namespace's secrets as metadata only -- values are never listed."""
    return [
        SecretMetadataOut(
            namespace=metadata.namespace,
            secret_key=metadata.secret_key,
            updated_at=metadata.updated_at,
        )
        for metadata in keyvault.list_secrets(namespace)
    ]


@router.delete("/{namespace}/{secret_key}", status_code=204)
def delete_secret(
    namespace: str,
    secret_key: str,
    request: Request,
    keyvault: KeyvaultService = Depends(get_keyvault),
) -> None:
    """Delete one secret; 404 when it was already absent."""
    try:
        keyvault.delete_secret(namespace, secret_key, actor=_actor(request))
    except SecretNotFoundError as exc:
        raise HTTPException(status_code=404, detail="secret not found") from exc


@router.get("/{namespace}/{secret_key}/audit")
def get_secret_audit(
    namespace: str, secret_key: str, keyvault: KeyvaultService = Depends(get_keyvault)
) -> list[dict]:
    """Return the ordered set/read/delete audit trail for one secret."""
    return keyvault.audit_history(namespace, secret_key)
