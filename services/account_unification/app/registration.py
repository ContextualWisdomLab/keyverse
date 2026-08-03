"""Headless self-registration API for first-party product signup pages.

Product frontends (e.g. Naruon) own the signup UX and submit new accounts to
this service, which creates the Keycloak user through the Admin REST API. The
IdP-hosted registration page stays disabled (``registrationAllowed:false``), so
this endpoint is the only account-creation entry point and carries its own
bearer token (``registration_api_token``) — deliberately separate from the
operator token so relying products never hold merge/SCIM/federation privileges.

Bootstrap-credential contract: the account is created with the caller-supplied
initial password and the ``webauthn-register-passwordless`` required action.
The realm browser flow offers the password form only while the account has no
passkey; once the first session enrolls a passkey, the password janitor
(:func:`revoke_bootstrap_passwords`) deletes the password credential so the
steady state stays passwordless. See docs/passwordless-policy.md.
"""
from __future__ import annotations

import hmac
import re
import threading
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .keycloak_client import AdminApi
from .models import UserAccount

registration_router = APIRouter(prefix="/registration", tags=["registration"])

PASSKEY_ENROLL_REQUIRED_ACTION = "webauthn-register-passwordless"
PASSWORD_CREDENTIAL_TYPE = "password"  # noqa: S105 - credential type name, not a secret
PASSKEY_CREDENTIAL_TYPE = "webauthn-passwordless"  # noqa: S105

# Registration input bounds. Email validation intentionally checks deterministic
# syntax only; ownership proof is verifyEmail's job once the realm has SMTP.
EMAIL_MAX_LENGTH = 254
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
NAME_MAX_LENGTH = 100
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_LOCAL_ATOM_PUNCTUATION = frozenset("!#$%&'*+-/=?^_`{|}~.")

# Simple fixed-window rate limit for account creation attempts.
REGISTRATION_RATE_LIMIT_WINDOW_SECONDS = 300.0
REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS = 30
_registration_attempt_lock = threading.Lock()
_registration_attempt_window_start = 0.0
_registration_attempt_count = 0

# Password-janitor scan bound: pages of 100, hard cap so a huge realm cannot
# turn one janitor pass into an unbounded Admin API crawl.
JANITOR_PAGE_SIZE = 100
JANITOR_MAX_PAGES = 50


class RegistrationRequest(BaseModel):
    """One self-registration submission from a product signup page."""

    email_address: str = Field(min_length=3, max_length=EMAIL_MAX_LENGTH)
    initial_password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH
    )
    first_name: str | None = Field(default=None, max_length=NAME_MAX_LENGTH)
    last_name: str | None = Field(default=None, max_length=NAME_MAX_LENGTH)


class RegistrationResult(BaseModel):
    """Public outcome of a registration; never leaks internals."""

    account_id: str
    email_address: str


class JanitorResult(BaseModel):
    """Outcome of one bootstrap-password janitor pass."""

    scanned_users: int
    revoked_passwords: int


def require_registration_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    """Authenticate the registration bearer token; fail closed when absent."""
    expected = getattr(request.app.state, "registration_api_token", None)
    if not expected:
        raise HTTPException(
            status_code=503, detail="registration authentication unavailable"
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


def get_admin_api(request: Request) -> AdminApi:
    """Return the wired Keycloak Admin API from application state."""
    api = getattr(request.app.state, "keycloak_api", None)
    if api is None:
        raise HTTPException(status_code=503, detail="keycloak api unavailable")
    return api


def _record_registration_attempt() -> None:
    """Enforce the fixed-window registration rate limit."""
    global _registration_attempt_window_start, _registration_attempt_count
    now = time.monotonic()
    with _registration_attempt_lock:
        if now - _registration_attempt_window_start > REGISTRATION_RATE_LIMIT_WINDOW_SECONDS:
            _registration_attempt_window_start = now
            _registration_attempt_count = 0
        _registration_attempt_count += 1
        if _registration_attempt_count > REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429, detail="registration temporarily rate limited"
            )


def _has_valid_email_shape(email_address: str) -> bool:
    """Return whether an email has bounded, non-ambiguous address syntax.

    This deterministic parser avoids a backtracking regular expression on
    caller-controlled text. It deliberately validates syntax rather than
    mailbox ownership; Keycloak's verification flow supplies ownership proof.
    """
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
    """Normalize and shape-check the registration email."""
    email_address = raw_email.strip().lower()
    if (
        len(email_address) > EMAIL_MAX_LENGTH
        or CONTROL_CHARACTER_PATTERN.search(email_address)
        or not _has_valid_email_shape(email_address)
    ):
        raise HTTPException(status_code=422, detail="invalid_email_address")
    return email_address


def _validated_name(raw_name: str | None) -> str | None:
    """Trim an optional display-name part and reject control characters."""
    if raw_name is None:
        return None
    candidate = raw_name.strip()
    if not candidate:
        return None
    if CONTROL_CHARACTER_PATTERN.search(candidate):
        raise HTTPException(status_code=422, detail="invalid_name")
    return candidate


@registration_router.post(
    "/accounts", response_model=RegistrationResult, status_code=201
)
def register_account(
    request_body: RegistrationRequest,
    api: AdminApi = Depends(get_admin_api),
) -> RegistrationResult:
    """Create a Keycloak account for a product-signup submission."""
    _record_registration_attempt()
    email_address = _validated_email(request_body.email_address)
    if CONTROL_CHARACTER_PATTERN.search(request_body.initial_password):
        raise HTTPException(status_code=422, detail="invalid_password")

    if api.find_users_by_email(email_address):
        raise HTTPException(status_code=409, detail="email_already_registered")

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
        raise HTTPException(status_code=502, detail="account_creation_failed")

    # Bootstrap credential + forced passkey enrollment on the first session.
    api.reset_user_password(account_id, request_body.initial_password)
    api.set_user_required_actions(account_id, [PASSKEY_ENROLL_REQUIRED_ACTION])
    return RegistrationResult(account_id=account_id, email_address=email_address)


def revoke_bootstrap_passwords(api: AdminApi) -> JanitorResult:
    """Delete password credentials from accounts that already hold a passkey.

    Keeps the steady state passwordless: the registration password exists only
    to bridge the gap until the first session enrolls a passkey.
    """
    scanned_users = 0
    revoked_passwords = 0
    for page_index in range(JANITOR_MAX_PAGES):
        users = api.list_users(page_index * JANITOR_PAGE_SIZE, JANITOR_PAGE_SIZE)
        if not users:
            break
        for user in users:
            scanned_users += 1
            credentials = api.list_user_credentials(user.user_id)
            credential_types = {item.get("type") for item in credentials}
            if PASSKEY_CREDENTIAL_TYPE not in credential_types:
                continue
            for item in credentials:
                if item.get("type") == PASSWORD_CREDENTIAL_TYPE and item.get("id"):
                    api.delete_user_credential(user.user_id, item["id"])
                    revoked_passwords += 1
        if len(users) < JANITOR_PAGE_SIZE:
            break
    return JanitorResult(scanned_users=scanned_users, revoked_passwords=revoked_passwords)


@registration_router.post("/password-janitor:run", response_model=JanitorResult)
def run_password_janitor(api: AdminApi = Depends(get_admin_api)) -> JanitorResult:
    """Run one janitor pass on demand (also runs periodically in-process)."""
    return revoke_bootstrap_passwords(api)
