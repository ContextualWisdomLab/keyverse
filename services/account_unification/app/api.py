"""FastAPI routes for the account-unification admin service."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from .audit import AuditLogger
from .identifiers import InvalidIdentifierError, validate_path_segment
from .errors import (
    InactiveAccountError,
    NoMatchError,
    SameUserError,
    UnverifiedEmailMergeError,
    UserNotFoundError,
)
from .models import FederatedIdentity, MergeRequest, MergeResult, UserAccount
from .service import UnificationService

router = APIRouter()


def get_service(request: Request) -> UnificationService:
    """Return the request-scoped unification service."""
    service = getattr(request.app.state, "unification_service", None)
    if service is None:  # pragma: no cover - only when misconfigured
        raise HTTPException(status_code=503, detail="service not initialised")
    return service


def get_audit(request: Request) -> AuditLogger:
    """Return the request-scoped audit logger."""
    audit = getattr(request.app.state, "audit_logger", None)
    if audit is None:  # pragma: no cover
        raise HTTPException(status_code=503, detail="audit not initialised")
    return audit


def _safe_identifier(value: str, field_name: str) -> str:
    """Validate a path-segment identifier at the API boundary (400 on failure)."""
    try:
        return validate_path_segment(value, field_name=field_name)
    except InvalidIdentifierError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/users/{user_id}", response_model=UserAccount, tags=["identities"])
def get_user(user_id: str, service: UnificationService = Depends(get_service)) -> UserAccount:
    """Return one account and its merge-relevant identity state."""
    user_id = _safe_identifier(user_id, "user_id")
    try:
        return service.get_account(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/users/{user_id}/identities",
    response_model=list[FederatedIdentity],
    tags=["identities"],
)
def list_identities(
    user_id: str, service: UnificationService = Depends(get_service)
) -> list[FederatedIdentity]:
    """List one user's external identities (federated identities)."""
    user_id = _safe_identifier(user_id, "user_id")
    try:
        return service.list_identities(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/merges", response_model=MergeResult, tags=["merge"])
def merge_accounts(
    body: MergeRequest, service: UnificationService = Depends(get_service)
) -> MergeResult:
    """Merge ``duplicate`` into ``survivor`` (survivor-wins, fully audited)."""
    try:
        return service.merge_accounts(body)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SameUserError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UnverifiedEmailMergeError as exc:
        # 422: request understood but refused by policy (unverified email).
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except NoMatchError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except InactiveAccountError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/merges/{audit_id}/audit", tags=["merge"])
def get_merge_audit(audit_id: str, audit: AuditLogger = Depends(get_audit)) -> list[dict]:
    """Return the ordered audit trail for a merge correlation id."""
    events = audit.events_for(audit_id)
    if not events:
        raise HTTPException(status_code=404, detail="no audit events for id")
    return [
        {
            "audit_id": event.audit_id,
            "event_type": event.event_type,
            "actor": event.actor,
            "survivor_user_id": event.survivor_user_id,
            "duplicate_user_id": event.duplicate_user_id,
            "payload_json": event.payload_json,
            "created_at": event.created_at,
        }
        for event in events
    ]
