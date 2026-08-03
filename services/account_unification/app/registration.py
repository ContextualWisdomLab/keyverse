"""Headless self-registration and bootstrap-credential retirement.

First-party product backends submit accounts through a dedicated bearer-token
surface. The account starts with a bounded bootstrap password and a mandatory
passkey enrollment action. A janitor removes the password after passkey
enrollment, leaving the steady state passwordless.
"""
from __future__ import annotations

import hmac
import re
import threading
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .models import UserAccount
from .product_keycloak_client import ProductAdminApi

registration_router = APIRouter(
    prefix="/registration", tags=["registration"]
)

PASSKEY_ENROLL_REQUIRED_ACTION = "webauthn-register-passwordless"
PASSWORD_CREDENTIAL_TYPE = "password"  # noqa: S105 - credential type name
PASSKEY_CREDENTIAL_TYPE = "webauthn-passwordless"  # noqa: S105

EMAIL_MAX_LENGTH = 254
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
NAME_MAX_LENGTH = 100
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_LOCAL_ATOM_PUNCTUATION = frozenset("!#$%&'*+-/=?^_`{|}~.")

REGISTRATION_RATE_LIMIT_WINDOW_SECONDS = 300.0
REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS = 30
_registration_attempt_lock = threading.Lock()
_registration_attempt_window_start = 0.0
_registration_attempt_count = 0

JANITOR_PAGE_SIZE = 100
JANITOR_MAX_PAGES = 50


class RegistrationRequest(BaseModel):
    """One self-registration submission from a product signup page."""

    email_address: str = Field(
        min_length=3, max_length=EMAIL_MAX_LENGTH
    )
    initial_password: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )
    first_name: str | None = Field(
        default=None, max_length=NAME_MAX_LENGTH
    )
    last_name: str | None = Field(
        default=None, max_length=NAME_MAX_LENGTH
    )


class RegistrationResult(BaseModel):
    """Public outcome of a registration without internal details."""

    account_id: str
    email_address: str


class JanitorResult(BaseModel):
    """Outcome of one bounded bootstrap-credential janitor pass."""

    scanned_users: int
    revoked_passwords: int


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
        raise HTTPException(
            status_code=403, detail="invalid registration token"
        )


registration_auth_dependency = Depends(require_registration_token)


def get_admin_api(request: Request) -> ProductAdminApi:
    """Return the wired product Keycloak API from application state."""
    api = getattr(request.app.state, "keycloak_api", None)
    if api is None:
        raise HTTPException(
            status_code=503, detail="keycloak api unavailable"
        )
    return api


def _record_registration_attempt() -> None:
    """Enforce a bounded process-local fixed-window registration limit."""
    global _registration_attempt_window_start, _registration_attempt_count
    now = time.monotonic()
    with _registration_attempt_lock:
        if (
            now - _registration_attempt_window_start
            > REGISTRATION_RATE_LIMIT_WINDOW_SECONDS
        ):
            _registration_attempt_window_start = now
            _registration_attempt_count = 0
        _registration_attempt_count += 1
        if (
            _registration_attempt_count
            > REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS
        ):
            raise HTTPException(
                status_code=429,
                detail="registration temporarily rate limited",
            )


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
            character.isalnum()
            or character in _LOCAL_ATOM_PUNCTUATION
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
        and all(
            character.isalnum() or character == "-"
            for character in label
        )
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
        raise HTTPException(
            status_code=422, detail="invalid_email_address"
        )
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
    initial_password: str,
) -> None:
    """Install the bootstrap credential and passkey enrollment action.

    A partial initialization is rolled back by deleting the newly created
    account, preventing orphaned accounts that cannot complete first login.
    """
    try:
        api.reset_user_password(account_id, initial_password)
        api.set_user_required_actions(
            account_id, [PASSKEY_ENROLL_REQUIRED_ACTION]
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
    api: ProductAdminApi = Depends(get_admin_api),
) -> RegistrationResult:
    """Create and initialize one Keycloak account atomically."""
    _record_registration_attempt()
    email_address = _validated_email(request_body.email_address)
    if CONTROL_CHARACTER_PATTERN.search(
        request_body.initial_password
    ):
        raise HTTPException(
            status_code=422, detail="invalid_password"
        )
    if api.find_users_by_email(email_address):
        raise HTTPException(
            status_code=409, detail="email_already_registered"
        )

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
    if not account_id:
        raise HTTPException(
            status_code=502, detail="account_creation_failed"
        )
    _initialize_account(
        api, account_id, request_body.initial_password
    )
    return RegistrationResult(
        account_id=account_id,
        email_address=email_address,
    )


def revoke_bootstrap_passwords(
    api: ProductAdminApi,
) -> JanitorResult:
    """Delete password credentials from passkey-holding accounts."""
    scanned_users = 0
    revoked_passwords = 0
    for page_index in range(JANITOR_MAX_PAGES):
        users = api.list_users(
            page_index * JANITOR_PAGE_SIZE,
            JANITOR_PAGE_SIZE,
        )
        if not users:
            break
        for user in users:
            scanned_users += 1
            credentials = api.list_user_credentials(user.user_id)
            credential_types = {
                item.get("type") for item in credentials
            }
            if PASSKEY_CREDENTIAL_TYPE not in credential_types:
                continue
            for item in credentials:
                if (
                    item.get("type") == PASSWORD_CREDENTIAL_TYPE
                    and item.get("id")
                ):
                    api.delete_user_credential(
                        user.user_id, item["id"]
                    )
                    revoked_passwords += 1
        if len(users) < JANITOR_PAGE_SIZE:
            break
    return JanitorResult(
        scanned_users=scanned_users,
        revoked_passwords=revoked_passwords,
    )


@registration_router.post(
    "/password-janitor:run",
    response_model=JanitorResult,
)
def run_password_janitor(
    api: ProductAdminApi = Depends(get_admin_api),
) -> JanitorResult:
    """Run one bounded janitor pass on demand."""
    return revoke_bootstrap_passwords(api)
