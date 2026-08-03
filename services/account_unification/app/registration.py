"""Headless passwordless self-registration through one-time action email.

First-party product backends submit accounts through a dedicated bearer-token
surface. The service creates a password-free account, then asks Keycloak to send
a bounded verification and passkey-enrollment link. A failed email request
rolls the account back so no unusable orphan remains.
"""
from __future__ import annotations

import hmac
import re
import threading
import time

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .models import UserAccount
from .product_keycloak_client import ProductAdminApi

registration_router = APIRouter(prefix="/registration", tags=["registration"])

VERIFY_EMAIL_REQUIRED_ACTION = "VERIFY_EMAIL"
PASSKEY_ENROLL_REQUIRED_ACTION = "webauthn-register-passwordless"

EMAIL_MAX_LENGTH = 254
NAME_MAX_LENGTH = 100
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_LOCAL_ATOM_PUNCTUATION = frozenset("!#$%&'*+-/=?^_`{|}~.")

REGISTRATION_RATE_LIMIT_WINDOW_SECONDS = 300.0
REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS = 30
_registration_attempt_lock = threading.Lock()
_registration_attempt_windows: dict[str, tuple[float, int]] = {}


class RegistrationRequest(BaseModel):
    """One password-free registration submission from a product signup page."""

    model_config = ConfigDict(extra="forbid")

    email_address: str = Field(min_length=3, max_length=EMAIL_MAX_LENGTH)
    first_name: str | None = Field(default=None, max_length=NAME_MAX_LENGTH)
    last_name: str | None = Field(default=None, max_length=NAME_MAX_LENGTH)


class RegistrationResult(BaseModel):
    """Public outcome after a passkey-enrollment email has been accepted."""

    account_id: str
    email_address: str


def require_registration_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    """Authenticate the dedicated registration bearer token."""
    expected = getattr(request.app.state, "registration_api_token", None)
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="registration authentication unavailable",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="registration bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[len("Bearer ") :].strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=403, detail="invalid registration token")


registration_auth_dependency = Depends(require_registration_token)


def get_admin_api(request: Request) -> ProductAdminApi:
    """Return the wired product Keycloak API from application state."""
    api = getattr(request.app.state, "keycloak_api", None)
    if api is None:
        raise HTTPException(status_code=503, detail="keycloak api unavailable")
    return api


def reset_rate_limit_state() -> None:
    """Clear process-local registration counters for deterministic tests."""
    with _registration_attempt_lock:
        _registration_attempt_windows.clear()


def _registration_client_key(request: Request) -> str:
    """Return the direct peer address used for process-local throttling."""
    return request.client.host if request.client is not None else "unknown-client"


def _record_registration_attempt(client_key: str) -> None:
    """Enforce an independent fixed-window registration limit per caller."""
    now = time.monotonic()
    with _registration_attempt_lock:
        window_start, attempt_count = _registration_attempt_windows.get(
            client_key, (now, 0)
        )
        if now - window_start > REGISTRATION_RATE_LIMIT_WINDOW_SECONDS:
            window_start, attempt_count = now, 0
        attempt_count += 1
        _registration_attempt_windows[client_key] = (
            window_start,
            attempt_count,
        )
        if attempt_count > REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail="registration temporarily rate limited",
            )


def _registration_settings(request: Request) -> tuple[str, str, int]:
    """Return complete passwordless enrollment settings or fail closed."""
    client_id = getattr(request.app.state, "registration_client_id", None)
    redirect_uri = getattr(request.app.state, "registration_redirect_uri", None)
    lifespan_seconds = getattr(
        request.app.state,
        "registration_action_lifespan_seconds",
        None,
    )
    if (
        not client_id
        or not redirect_uri
        or not isinstance(lifespan_seconds, int)
        or lifespan_seconds <= 0
    ):
        raise HTTPException(
            status_code=503,
            detail="registration enrollment unavailable",
        )
    return client_id, redirect_uri, lifespan_seconds


def _has_valid_email_shape(email_address: str) -> bool:
    """Return whether an email has bounded, non-ambiguous syntax."""
    if email_address.count("@") != 1 or any(
        character.isspace() for character in email_address
    ):
        return False
    local_part, domain_part = email_address.split("@", 1)
    if (
        not local_part
        or local_part.startswith(".")
        or local_part.endswith(".")
        or ".." in local_part
        or not all(
            character.isalnum() or character in _LOCAL_ATOM_PUNCTUATION
            for character in local_part
        )
    ):
        return False
    if (
        not domain_part
        or "." not in domain_part
        or domain_part.startswith(".")
        or domain_part.endswith(".")
        or ".." in domain_part
    ):
        return False
    labels = domain_part.split(".")
    return all(
        1 <= len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def _validated_email(raw_email: str) -> str:
    """Normalize and shape-check a registration email address."""
    email_address = raw_email.strip().lower()
    if (
        len(email_address) > EMAIL_MAX_LENGTH
        or CONTROL_CHARACTER_PATTERN.search(email_address)
        or not _has_valid_email_shape(email_address)
    ):
        raise HTTPException(status_code=422, detail="invalid_email_address")
    return email_address


def _validated_name(raw_name: str | None) -> str | None:
    """Trim an optional display-name part and reject controls."""
    if raw_name is None:
        return None
    candidate = raw_name.strip()
    if not candidate:
        return None
    if CONTROL_CHARACTER_PATTERN.search(candidate):
        raise HTTPException(status_code=422, detail="invalid_name")
    return candidate


def _initialize_account(
    api: ProductAdminApi,
    account_id: str,
    *,
    client_id: str,
    redirect_uri: str,
    lifespan_seconds: int,
) -> None:
    """Send verification/passkey actions or roll back the new account."""
    try:
        api.send_execute_actions_email(
            account_id,
            [
                VERIFY_EMAIL_REQUIRED_ACTION,
                PASSKEY_ENROLL_REQUIRED_ACTION,
            ],
            client_id=client_id,
            redirect_uri=redirect_uri,
            lifespan_seconds=lifespan_seconds,
        )
    except Exception as initialization_error:
        try:
            api.delete_user(account_id)
        except Exception as rollback_error:
            raise HTTPException(
                status_code=502,
                detail="account_initialization_rollback_failed",
            ) from rollback_error
        raise HTTPException(
            status_code=502,
            detail="account_initialization_failed",
        ) from initialization_error


@registration_router.post(
    "/accounts",
    response_model=RegistrationResult,
    status_code=201,
)
def register_account(
    request_body: RegistrationRequest,
    request: Request,
    api: ProductAdminApi = Depends(get_admin_api),
) -> RegistrationResult:
    """Create a password-free account and send one enrollment email."""
    client_id, redirect_uri, lifespan_seconds = _registration_settings(request)
    _record_registration_attempt(_registration_client_key(request))
    email_address = _validated_email(request_body.email_address)
    if api.find_users_by_email(email_address):
        raise HTTPException(
            status_code=409,
            detail="email_already_registered",
        )

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
                status_code=409,
                detail="email_already_registered",
            ) from error
        raise
    if not account_id:
        raise HTTPException(status_code=502, detail="account_creation_failed")
    _initialize_account(
        api,
        account_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        lifespan_seconds=lifespan_seconds,
    )
    return RegistrationResult(
        account_id=account_id,
        email_address=email_address,
    )
