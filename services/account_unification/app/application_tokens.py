"""Programmable application tokens scoped to one software unit and API.

Tokens are hashed at rest, purpose-bound, rotatable, and auditable. They are
never a password or WebAuthn substitute and never inherit down the org tree.
The plaintext secret is returned only at issue time.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .audit import AuditLogger
from .auth import operator_auth_dependency, runtime_auth_dependency
from .errors import AuthorizationPolicyError
from .kv_store import KvStore
from .org_authorization import validate_capability_codes, validate_slug
from .path_security import admin_path_security_dependency

APPLICATION_TOKEN_NAMESPACE = "application_access_tokens"
TOKEN_SCHEME = "kvt"
CLOSED_PURPOSE_CODES: frozenset[str] = frozenset(
    {"machine_api", "integration_sync", "operator_export"}
)
FORBIDDEN_PURPOSE_CODES: frozenset[str] = frozenset(
    {"password", "webauthn", "browser_login", "login", "authenticator"}
)
ACTIVE_LIFECYCLE = "active"
REVOKED_LIFECYCLE = "revoked"
ROTATED_LIFECYCLE = "rotated"
MIN_LIFETIME_SECONDS = 60
MAX_LIFETIME_SECONDS = 90 * 24 * 60 * 60

application_token_router = APIRouter(
    prefix="/application-tokens",
    tags=["application-tokens"],
    dependencies=[operator_auth_dependency, admin_path_security_dependency],
)
application_token_runtime_router = APIRouter(
    prefix="/application-tokens",
    tags=["application-tokens"],
    dependencies=[runtime_auth_dependency],
)
_MANAGEMENT_DEPENDENCIES = [operator_auth_dependency, admin_path_security_dependency]


class ApplicationTokenIssueRequest(BaseModel):
    """Mint one software-unit-scoped programmable application token."""

    model_config = ConfigDict(extra="forbid")

    software_unit_id: str
    purpose_code: str
    capability_codes: list[str]
    lifetime_seconds: int = Field(default=3600, ge=1)
    actor_identity_id: str = Field(min_length=1, max_length=128)
    tenant_deployment_id: str


class ApplicationTokenRecord(BaseModel):
    """Durable hashed token record. The plaintext secret is never stored."""

    model_config = ConfigDict(extra="forbid")

    application_token_id: str
    tenant_deployment_id: str
    software_unit_id: str
    token_prefix: str
    token_hash: str
    purpose_code: str
    capability_codes: list[str]
    lifecycle_status_code: str
    expires_at: float
    created_at: float
    revoked_at: float | None = None
    actor_identity_id: str
    replaced_token_id: str | None = None


class ApplicationTokenIssueResponse(BaseModel):
    """One-time issue envelope containing the plaintext token."""

    model_config = ConfigDict(extra="forbid")

    application_token_id: str
    tenant_deployment_id: str
    software_unit_id: str
    token_prefix: str
    purpose_code: str
    capability_codes: list[str]
    expires_at: str
    plaintext_token: str
    token_substitute_for_password: bool = False
    inherits_org_grants: bool = False
    application_next_action: str = (
        "Store the plaintext token in the relying application's secret "
        "manager, then discard the response. Present the token only to "
        "POST /application-tokens:verify."
    )


class ApplicationTokenView(BaseModel):
    """Operator view of a token with secret material omitted."""

    model_config = ConfigDict(extra="forbid")

    application_token_id: str
    tenant_deployment_id: str
    software_unit_id: str
    token_prefix: str
    purpose_code: str
    capability_codes: list[str]
    lifecycle_status_code: str
    expires_at: str
    created_at: str
    revoked_at: str | None = None
    actor_identity_id: str
    replaced_token_id: str | None = None
    token_substitute_for_password: bool = False
    inherits_org_grants: bool = False


class ApplicationTokenVerifyRequest(BaseModel):
    """Ask whether a presented token is active for a software unit and APIs."""

    model_config = ConfigDict(extra="forbid")

    presented_token: str = Field(min_length=8, max_length=256)
    tenant_deployment_id: str
    software_unit_id: str
    requested_capability_codes: list[str] = Field(default_factory=list)


class ApplicationTokenVerifyResponse(BaseModel):
    """Secret-free verification result for one programmable token."""

    model_config = ConfigDict(extra="forbid")

    active: bool
    effect: str
    denial_code: str | None = None
    application_token_id: str | None = None
    tenant_deployment_id: str | None = None
    software_unit_id: str | None = None
    capability_codes: list[str] = Field(default_factory=list)
    purpose_code: str | None = None
    token_substitute_for_password: bool = False
    inherits_org_grants: bool = False


class ApplicationTokenService:
    """Issue, verify, revoke, and rotate hashed programmable application tokens."""

    def __init__(
        self,
        store: KvStore,
        audit: AuditLogger,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Create one service around KV storage, audit, and an optional clock."""
        self._store = store
        self._audit = audit
        self._clock = clock or time.time
        self._state_lock = threading.RLock()

    def issue(
        self, request: ApplicationTokenIssueRequest
    ) -> ApplicationTokenIssueResponse:
        """Mint one token, persist only the hash, and audit the issue."""
        record, plaintext = self._mint(request, replaced_token_id=None)
        with self._state_lock:
            self._write_record(record)
            try:
                self._audit_event(
                    "application_token_issued",
                    request.actor_identity_id,
                    record,
                )
            except Exception:
                self._delete_record(record)
                raise
        return self._issue_response(record, plaintext)

    def list_tokens(self) -> list[ApplicationTokenView]:
        """Return secret-free views of every stored token."""
        return [
            self._view(record)
            for record in sorted(self._records(), key=lambda item: item.application_token_id)
        ]

    def get_token(self, application_token_id: str) -> ApplicationTokenView:
        """Return one secret-free token view."""
        return self._view(self._require_record(application_token_id))

    def revoke(
        self,
        application_token_id: str,
        *,
        actor_identity_id: str,
        lifecycle_status_code: str = REVOKED_LIFECYCLE,
    ) -> ApplicationTokenView:
        """Revoke one token. Hashes remain stored for audit, never returned."""
        _validate_token_id(application_token_id)
        with self._state_lock:
            record = self._require_record(application_token_id)
            if record.lifecycle_status_code != ACTIVE_LIFECYCLE:
                raise AuthorizationPolicyError(
                    "application token is not active",
                    status_code=409,
                )
            updated = record.model_copy(
                update={
                    "lifecycle_status_code": lifecycle_status_code,
                    "revoked_at": self._clock(),
                }
            )
            self._write_record(updated)
            try:
                self._audit_event(
                    "application_token_revoked",
                    actor_identity_id,
                    updated,
                )
            except Exception:
                self._write_record(record)
                raise
        return self._view(updated)

    def rotate(
        self,
        application_token_id: str,
        request: ApplicationTokenIssueRequest,
    ) -> ApplicationTokenIssueResponse:
        """Revoke one active token and issue a replacement in one actor action."""
        _validate_token_id(application_token_id)
        validate_slug(
            request.tenant_deployment_id,
            field_name="tenant_deployment_id",
        )
        with self._state_lock:
            existing = self._require_record(application_token_id)
            if existing.software_unit_id != request.software_unit_id:
                raise AuthorizationPolicyError(
                    "rotated token must stay bound to the same software unit"
                )
            if existing.tenant_deployment_id != request.tenant_deployment_id:
                raise AuthorizationPolicyError(
                    "rotated token must stay bound to the same tenant"
                )
            if (
                existing.lifecycle_status_code != ACTIVE_LIFECYCLE
                or existing.expires_at <= self._clock()
            ):
                raise AuthorizationPolicyError(
                    "application token is not active",
                    status_code=409,
                )
            updated = existing.model_copy(
                update={
                    "lifecycle_status_code": ROTATED_LIFECYCLE,
                    "revoked_at": self._clock(),
                }
            )
            record, plaintext = self._mint(
                request, replaced_token_id=application_token_id
            )
            try:
                self._write_record(record)
                self._write_record(updated)
                self._audit_event(
                    "application_token_rotated",
                    request.actor_identity_id,
                    record,
                )
            except Exception:
                self._write_record(existing)
                self._delete_record(record)
                raise
        return self._issue_response(record, plaintext)

    def verify(
        self, request: ApplicationTokenVerifyRequest
    ) -> ApplicationTokenVerifyResponse:
        """Verify a presented token without consulting org-tree grants."""
        validate_slug(request.software_unit_id, field_name="software_unit_id")
        validate_slug(
            request.tenant_deployment_id,
            field_name="tenant_deployment_id",
        )
        requested = validate_capability_codes(request.requested_capability_codes)
        parsed = _parse_presented_token(request.presented_token)
        if parsed is None:
            return _inactive("malformed_token")
        token_prefix, _secret = parsed
        presented_hash = _hash_token(request.presented_token)
        now = self._clock()
        with self._state_lock:
            matches = [
                record
                for record in self._records()
                if record.token_prefix == token_prefix
                and _hash_matches(record.token_hash, presented_hash)
            ]
        if not matches:
            return _inactive("unknown_token")
        record = matches[0]
        if record.tenant_deployment_id != request.tenant_deployment_id:
            return _inactive("tenant_mismatch")
        if record.lifecycle_status_code != ACTIVE_LIFECYCLE:
            return _inactive("revoked_token", record)
        if record.expires_at <= now:
            return _inactive("expired_token", record)
        if record.software_unit_id != request.software_unit_id:
            return _inactive("software_unit_mismatch", record)
        if any(code not in record.capability_codes for code in requested):
            return _inactive("capability_denied", record)
        return ApplicationTokenVerifyResponse(
            active=True,
            effect="allow",
            application_token_id=record.application_token_id,
            tenant_deployment_id=record.tenant_deployment_id,
            software_unit_id=record.software_unit_id,
            capability_codes=list(record.capability_codes),
            purpose_code=record.purpose_code,
        )

    def _mint(
        self,
        request: ApplicationTokenIssueRequest,
        *,
        replaced_token_id: str | None,
    ) -> tuple[ApplicationTokenRecord, str]:
        """Create one hashed record and the corresponding plaintext token."""
        software_unit_id = validate_slug(
            request.software_unit_id, field_name="software_unit_id"
        )
        validate_slug(
            request.tenant_deployment_id, field_name="tenant_deployment_id"
        )
        purpose_code = _validate_purpose(request.purpose_code)
        capability_codes = validate_capability_codes(request.capability_codes)
        if not capability_codes:
            raise AuthorizationPolicyError(
                "application tokens require at least one API capability"
            )
        if (
            request.lifetime_seconds < MIN_LIFETIME_SECONDS
            or request.lifetime_seconds > MAX_LIFETIME_SECONDS
        ):
            raise AuthorizationPolicyError(
                "lifetime_seconds must be between 60 seconds and 90 days"
            )
        application_token_id = f"tok-{uuid.uuid4().hex[:16]}"
        token_prefix = secrets.token_hex(6)
        secret_material = secrets.token_urlsafe(32)
        plaintext = f"{TOKEN_SCHEME}_{token_prefix}_{secret_material}"
        now = self._clock()
        record = ApplicationTokenRecord(
            application_token_id=application_token_id,
            tenant_deployment_id=request.tenant_deployment_id,
            software_unit_id=software_unit_id,
            token_prefix=token_prefix,
            token_hash=_hash_token(plaintext),
            purpose_code=purpose_code,
            capability_codes=capability_codes,
            lifecycle_status_code=ACTIVE_LIFECYCLE,
            expires_at=now + request.lifetime_seconds,
            created_at=now,
            actor_identity_id=request.actor_identity_id,
            replaced_token_id=replaced_token_id,
        )
        return record, plaintext

    def _write_record(self, record: ApplicationTokenRecord) -> None:
        """Persist one hashed token record."""
        with self._state_lock:
            self._store.put(
                APPLICATION_TOKEN_NAMESPACE,
                record.application_token_id,
                record.model_dump_json(),
            )

    def _delete_record(self, record: ApplicationTokenRecord) -> None:
        """Compensate one lifecycle write when its audit event fails."""
        with self._state_lock:
            self._store.delete(APPLICATION_TOKEN_NAMESPACE, record.application_token_id)

    def _records(self) -> list[ApplicationTokenRecord]:
        """Load every hashed token record, fail-closed on corruption."""
        with self._state_lock:
            raw_values = list(self._store.get_all(APPLICATION_TOKEN_NAMESPACE).values())
        records: list[ApplicationTokenRecord] = []
        for raw_value in raw_values:
            try:
                records.append(ApplicationTokenRecord.model_validate_json(raw_value))
            except ValidationError as exc:
                raise AuthorizationPolicyError(
                    "application token store is corrupt",
                    status_code=500,
                ) from exc
        return records

    def _require_record(self, application_token_id: str) -> ApplicationTokenRecord:
        """Return one stored record or raise 404."""
        _validate_token_id(application_token_id)
        with self._state_lock:
            raw_value = self._store.get(
                APPLICATION_TOKEN_NAMESPACE, application_token_id
            )
        if raw_value is None:
            raise AuthorizationPolicyError(
                "application token is not registered",
                status_code=404,
            )
        try:
            return ApplicationTokenRecord.model_validate_json(raw_value)
        except ValidationError as exc:
            raise AuthorizationPolicyError(
                "application token store is corrupt",
                status_code=500,
            ) from exc

    def _issue_response(
        self, record: ApplicationTokenRecord, plaintext: str
    ) -> ApplicationTokenIssueResponse:
        """Build the one-time plaintext issue envelope."""
        return ApplicationTokenIssueResponse(
            application_token_id=record.application_token_id,
            tenant_deployment_id=record.tenant_deployment_id,
            software_unit_id=record.software_unit_id,
            token_prefix=record.token_prefix,
            purpose_code=record.purpose_code,
            capability_codes=list(record.capability_codes),
            expires_at=_iso(record.expires_at),
            plaintext_token=plaintext,
        )

    def _view(self, record: ApplicationTokenRecord) -> ApplicationTokenView:
        """Build a secret-free operator view."""
        return ApplicationTokenView(
            application_token_id=record.application_token_id,
            tenant_deployment_id=record.tenant_deployment_id,
            software_unit_id=record.software_unit_id,
            token_prefix=record.token_prefix,
            purpose_code=record.purpose_code,
            capability_codes=list(record.capability_codes),
            lifecycle_status_code=record.lifecycle_status_code,
            expires_at=_iso(record.expires_at),
            created_at=_iso(record.created_at),
            revoked_at=None if record.revoked_at is None else _iso(record.revoked_at),
            actor_identity_id=record.actor_identity_id,
            replaced_token_id=record.replaced_token_id,
        )

    def _audit_event(
        self,
        event_type: str,
        actor_identity_id: str,
        record: ApplicationTokenRecord,
    ) -> None:
        """Record one hashed-token lifecycle event without secret material."""
        self._audit.emit(
            audit_id=record.application_token_id,
            event_type=event_type,
            actor=actor_identity_id,
            payload={
                "application_token_id": record.application_token_id,
                "tenant_deployment_id": record.tenant_deployment_id,
                "software_unit_id": record.software_unit_id,
                "token_prefix": record.token_prefix,
                "purpose_code": record.purpose_code,
                "lifecycle_status_code": record.lifecycle_status_code,
            },
        )


def _validate_purpose(purpose_code: str) -> str:
    """Accept only closed machine-purpose codes."""
    if purpose_code in FORBIDDEN_PURPOSE_CODES:
        raise AuthorizationPolicyError(
            "application tokens cannot substitute for a password or authenticator"
        )
    if purpose_code not in CLOSED_PURPOSE_CODES:
        raise AuthorizationPolicyError("purpose_code is not in the closed set")
    return purpose_code


def _validate_token_id(application_token_id: str) -> str:
    """Validate the tok-<hex> identifier issued by this service."""
    if (
        not application_token_id.startswith("tok-")
        or len(application_token_id) != 20
        or any(
            character not in "0123456789abcdef"
            for character in application_token_id[4:]
        )
    ):
        raise AuthorizationPolicyError("application_token_id is malformed")
    return application_token_id


def _hash_token(plaintext: str) -> str:
    """Return the hex SHA-256 digest of one token."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _hash_matches(stored_hash: str, presented_hash: str) -> bool:
    """Compare token hashes without raising on length mismatch."""
    if len(stored_hash) != len(presented_hash):
        return False
    return hmac.compare_digest(stored_hash, presented_hash)


def _parse_presented_token(presented_token: str) -> tuple[str, str] | None:
    """Split ``kvt_<prefix>_<secret>`` or return None for malformed input."""
    parts = presented_token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_SCHEME or len(parts[1]) != 12:
        return None
    if any(ord(character) < 0x20 for character in presented_token):
        return None
    return parts[1], parts[2]


def _inactive(
    denial_code: str, record: ApplicationTokenRecord | None = None
) -> ApplicationTokenVerifyResponse:
    """Return a secret-free deny without echoing the presented token."""
    return ApplicationTokenVerifyResponse(
        active=False,
        effect="deny",
        denial_code=denial_code,
        application_token_id=None if record is None else record.application_token_id,
        tenant_deployment_id=(
            None if record is None else record.tenant_deployment_id
        ),
        software_unit_id=None if record is None else record.software_unit_id,
        purpose_code=None if record is None else record.purpose_code,
    )


def _iso(timestamp: float) -> str:
    """Format a unix timestamp as UTC ISO-8601."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def get_application_token_service(request: Request) -> ApplicationTokenService:
    """Return the wired token service from application state."""
    service = getattr(request.app.state, "application_token_service", None)
    if service is None:
        raise HTTPException(
            status_code=503, detail="application token service not ready"
        )
    return service


class ApplicationTokenRevokeRequest(BaseModel):
    """Identify the operator revoking one programmable token."""

    model_config = ConfigDict(extra="forbid")

    actor_identity_id: str = Field(min_length=1, max_length=128)


@application_token_router.post(
    "",
    response_model=ApplicationTokenIssueResponse,
    dependencies=_MANAGEMENT_DEPENDENCIES,
)
def issue_application_token(
    body: ApplicationTokenIssueRequest,
    service: ApplicationTokenService = Depends(get_application_token_service),
) -> ApplicationTokenIssueResponse:
    """Issue one hashed-at-rest programmable application token."""
    try:
        return service.issue(body)
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@application_token_router.get(
    "",
    response_model=list[ApplicationTokenView],
    dependencies=_MANAGEMENT_DEPENDENCIES,
)
def list_application_tokens(
    service: ApplicationTokenService = Depends(get_application_token_service),
) -> list[ApplicationTokenView]:
    """List secret-free programmable application tokens."""
    try:
        return service.list_tokens()
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@application_token_router.get(
    "/{application_token_id}",
    response_model=ApplicationTokenView,
    dependencies=_MANAGEMENT_DEPENDENCIES,
)
def get_application_token(
    application_token_id: str,
    service: ApplicationTokenService = Depends(get_application_token_service),
) -> ApplicationTokenView:
    """Return one secret-free programmable application token."""
    try:
        return service.get_token(application_token_id)
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@application_token_router.post(
    "/{application_token_id}:revoke",
    response_model=ApplicationTokenView,
    dependencies=_MANAGEMENT_DEPENDENCIES,
)
def revoke_application_token(
    application_token_id: str,
    body: ApplicationTokenRevokeRequest,
    service: ApplicationTokenService = Depends(get_application_token_service),
) -> ApplicationTokenView:
    """Revoke one programmable application token."""
    try:
        return service.revoke(
            application_token_id, actor_identity_id=body.actor_identity_id
        )
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@application_token_router.post(
    "/{application_token_id}:rotate",
    response_model=ApplicationTokenIssueResponse,
    dependencies=_MANAGEMENT_DEPENDENCIES,
)
def rotate_application_token(
    application_token_id: str,
    body: ApplicationTokenIssueRequest,
    service: ApplicationTokenService = Depends(get_application_token_service),
) -> ApplicationTokenIssueResponse:
    """Rotate one programmable application token."""
    try:
        return service.rotate(application_token_id, body)
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@application_token_runtime_router.post(
    ":verify",
    response_model=ApplicationTokenVerifyResponse,
)
def verify_application_token(
    body: ApplicationTokenVerifyRequest,
    service: ApplicationTokenService = Depends(get_application_token_service),
) -> ApplicationTokenVerifyResponse:
    """Verify one presented programmable application token."""
    try:
        return service.verify(body)
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
