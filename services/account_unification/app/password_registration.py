"""Headless password-credential registration for naruon's own signup form.

naruon renders its own email/password signup form and calls this endpoint
server-side; no Keycloak page is ever shown to the user, matching the same
zero-Keycloak-HTML constraint as its login route
(see docs/adr/0015-naruon-password-credential-issuance.md). Scoped to naruon
only by possession of a dedicated bearer token — distinct from the operator
token and from :mod:`app.registration`'s passwordless-enrollment token, so no
other capability transfers between them.

Unlike ``POST /registration/accounts`` (passwordless, email-verification and
WebAuthn-enrollment link), this creates the account with an immediately
usable, non-temporary password credential — no email round-trip — so a
Direct Access Grants login right after signup succeeds. Email verification,
abuse detection beyond a per-peer rate limit, and CAPTCHA-equivalent
hardening are explicitly deferred; see the ADR's "not yet done" section.
"""
from __future__ import annotations

import threading
import time
import hmac

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .models import UserAccount
from .product_keycloak_client import ProductAdminApi
from .registration import CONTROL_CHARACTER_PATTERN, _validated_email, _validated_name

password_registration_router = APIRouter(prefix="/registration", tags=["registration"])

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

PASSWORD_REGISTRATION_RATE_LIMIT_WINDOW_SECONDS = 300.0
PASSWORD_REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS = 30
_password_registration_attempt_lock = threading.Lock()
_password_registration_attempt_windows: dict[str, tuple[float, int]] = {}


class PasswordRegistrationRequest(BaseModel):
    """One password-credential registration submission from naruon's signup form."""

    model_config = ConfigDict(extra="forbid")

    email_address: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    first_name: str | None = Field(default=None, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)


class PasswordRegistrationResult(BaseModel):
    """Public outcome after a password-credential account is created."""

    account_id: str
    email_address: str


def require_password_registration_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    """Authenticate the dedicated password-registration bearer token."""
    expected = getattr(request.app.state, "password_registration_api_token", None)
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="password registration authentication unavailable",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="password registration bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[len("Bearer ") :].strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=403, detail="invalid password registration token"
        )


password_registration_auth_dependency = Depends(require_password_registration_token)


def get_admin_api(request: Request) -> ProductAdminApi:
    """Return the wired product Keycloak API from application state."""
    api = getattr(request.app.state, "keycloak_api", None)
    if api is None:
        raise HTTPException(status_code=503, detail="keycloak api unavailable")
    return api


def reset_rate_limit_state() -> None:
    """Clear process-local password-registration counters for deterministic tests."""
    with _password_registration_attempt_lock:
        _password_registration_attempt_windows.clear()


def _registration_client_key(request: Request) -> str:
    """Return the direct peer address used for process-local throttling."""
    return request.client.host if request.client is not None else "unknown-client"


def _record_registration_attempt(client_key: str) -> None:
    """Enforce an independent fixed-window registration limit per caller."""
    now = time.monotonic()
    with _password_registration_attempt_lock:
        window_start, attempt_count = _password_registration_attempt_windows.get(
            client_key, (now, 0)
        )
        if now - window_start > PASSWORD_REGISTRATION_RATE_LIMIT_WINDOW_SECONDS:
            window_start, attempt_count = now, 0
        attempt_count += 1
        _password_registration_attempt_windows[client_key] = (
            window_start,
            attempt_count,
        )
        if attempt_count > PASSWORD_REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail="registration temporarily rate limited",
            )


def _validated_password(password: str, email_address: str) -> str:
    """Reject a password that is malformed or trivially guessable.

    Length is already bounded by ``PasswordRegistrationRequest``'s Field
    constraints; Keycloak's realm ``passwordPolicy`` is the second, server-
    side enforcement layer for the same minimum.
    """
    if password.strip() != password or not password:
        raise HTTPException(status_code=422, detail="invalid_password")
    if CONTROL_CHARACTER_PATTERN.search(password):
        raise HTTPException(status_code=422, detail="invalid_password")
    if password.lower() == email_address.lower():
        raise HTTPException(
            status_code=422, detail="password_must_not_match_email"
        )
    return password


def _create_account_with_password(
    api: ProductAdminApi, email_address: str, password: str, request_body: PasswordRegistrationRequest
) -> str:
    """Create the user, then roll it back if the credential cannot be set."""
    try:
        account_id = api.create_user(
            UserAccount(
                user_id="",
                user_name=email_address,
                email=email_address,
                is_email_verified=False,
                state="active",
                first_name=_validated_name(request_body.first_name),
                last_name=_validated_name(request_body.last_name),
            )
        )
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 409:
            raise HTTPException(
                status_code=409, detail="email_already_registered"
            ) from error
        raise
    if not account_id:
        raise HTTPException(status_code=502, detail="account_creation_failed")

    try:
        api.reset_password(account_id, password)
    except Exception as credential_error:
        try:
            api.delete_user(account_id)
        except Exception as rollback_error:
            raise HTTPException(
                status_code=502,
                detail="account_credential_rollback_failed",
            ) from rollback_error
        raise HTTPException(
            status_code=502,
            detail="account_credential_failed",
        ) from credential_error
    return account_id


@password_registration_router.post(
    "/accounts/password",
    response_model=PasswordRegistrationResult,
    status_code=201,
)
def register_account_with_password(
    request_body: PasswordRegistrationRequest,
    request: Request,
    api: ProductAdminApi = Depends(get_admin_api),
) -> PasswordRegistrationResult:
    """Create an account with an immediately usable password credential."""
    _record_registration_attempt(_registration_client_key(request))
    email_address = _validated_email(request_body.email_address)
    password = _validated_password(request_body.password, email_address)
    if api.find_users_by_email(email_address):
        raise HTTPException(status_code=409, detail="email_already_registered")

    account_id = _create_account_with_password(
        api, email_address, password, request_body
    )
    return PasswordRegistrationResult(
        account_id=account_id, email_address=email_address
    )
