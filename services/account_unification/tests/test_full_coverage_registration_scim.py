"""Coverage regressions for passwordless registration and SCIM edge paths."""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from app import registration, scim
from app.models import UserAccount
from app.user_locks import (
    InMemoryUserOperationLocks,
    UserOperationLockTimeout,
)


class _UnavailableApi:
    """Expose only methods needed by direct registration error tests."""

    def find_users_by_email(self, email: str) -> list[UserAccount]:
        """Return no pre-existing accounts."""
        return []

    def create_user(self, user: UserAccount) -> str:
        """Return an empty identifier to model an unusable upstream response."""
        return ""


class _NonConflictCreateApi(_UnavailableApi):
    """Raise a non-conflict Keycloak HTTP error during account creation."""

    def create_user(self, user: UserAccount) -> str:
        """Raise a service-unavailable response that must be preserved."""
        request = httpx.Request("POST", "https://keycloak.example/users")
        response = httpx.Response(503, request=request)
        raise httpx.HTTPStatusError(
            "upstream unavailable",
            request=request,
            response=response,
        )


class _TimeoutLocks:
    """Raise the shared user-mutation timeout on acquisition."""

    @contextmanager
    def hold(self, *user_ids: str):
        """Fail before entering a mutation critical section."""
        raise UserOperationLockTimeout("busy")
        yield


class _MinimalProvisioner:
    """Provide deterministic users and record SCIM mutations."""

    def __init__(self) -> None:
        """Create one enabled user and an empty call log."""
        self.user = UserAccount(
            user_id="user-1",
            user_name="jane",
            email="jane@example.com",
            is_email_verified=True,
        )
        self.calls: list[str] = []

    def find_user_by_username(self, username: str) -> UserAccount | None:
        """Return the known user only for its exact username."""
        return self.user if username == self.user.user_name else None

    def get_user(self, user_id: str) -> UserAccount:
        """Return the known user or raise a KeyError."""
        if user_id != self.user.user_id:
            raise KeyError(user_id)
        return self.user

    def create_user(self, user: UserAccount) -> str:
        """Record creation and return the stable user identifier."""
        self.calls.append("create")
        self.user = user.model_copy(update={"user_id": "user-1"})
        return "user-1"

    def replace_user(self, user_id: str, user: UserAccount) -> None:
        """Replace the stable user representation."""
        self.calls.append("replace")
        self.user = user

    def deactivate_user(self, user_id: str) -> None:
        """Disable the stable user representation."""
        self.calls.append("deactivate")
        self.user = self.user.model_copy(update={"state": "disabled"})

    def get_user_attribute(self, user_id: str, key: str) -> str | None:
        """Return no merge tombstone."""
        return None


def _registration_request() -> SimpleNamespace:
    """Return one valid direct-call registration request body."""
    return SimpleNamespace(
        email_address="new.user@example.com",
        first_name=None,
        last_name=None,
    )


def _registration_http_request() -> SimpleNamespace:
    """Return one request carrying complete enrollment state."""
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                registration_client_id="naruon-web",
                registration_redirect_uri="https://naruon.example/callback",
                registration_action_lifespan_seconds=900,
            )
        ),
        client=None,
    )


def test_registration_requires_a_bearer_header() -> None:
    """A configured registration surface still rejects an absent header."""
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(registration_api_token="expected-token")
        )
    )

    with pytest.raises(HTTPException) as error:
        registration.require_registration_token(request, authorization=None)

    assert error.value.status_code == 401
    assert error.value.headers == {"WWW-Authenticate": "Bearer"}


def test_registration_admin_api_dependency_fails_closed() -> None:
    """Registration cannot proceed without a wired product Keycloak client."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))

    with pytest.raises(HTTPException) as error:
        registration.get_admin_api(request)

    assert error.value.status_code == 503


def test_registration_client_key_handles_missing_peer() -> None:
    """A request without peer metadata uses the bounded unknown-client bucket."""
    request = SimpleNamespace(client=None)

    assert registration._registration_client_key(request) == "unknown-client"


def test_registration_window_resets_after_expiry(monkeypatch) -> None:
    """A fixed-window caller budget resets after the configured duration."""
    registration.reset_rate_limit_state()
    times = iter([0.0, registration.REGISTRATION_RATE_LIMIT_WINDOW_SECONDS + 1.0])
    monkeypatch.setattr(registration.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(registration, "REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS", 1)

    registration._record_registration_attempt("caller")
    registration._record_registration_attempt("caller")


def test_registration_name_normalization_covers_optional_and_invalid_paths() -> None:
    """Display-name normalization handles absent, blank, and control input."""
    assert registration._validated_name(None) is None
    assert registration._validated_name("   ") is None
    assert registration._validated_name("  Jane  ") == "Jane"
    with pytest.raises(HTTPException) as error:
        registration._validated_name("Jane\x00Doe")
    assert error.value.status_code == 422


def test_registration_reports_empty_upstream_identifier() -> None:
    """An upstream create response without an ID becomes a bounded 502."""
    registration.reset_rate_limit_state()

    with pytest.raises(HTTPException) as error:
        registration.register_account(
            _registration_request(),
            _registration_http_request(),
            api=_UnavailableApi(),
        )

    assert error.value.status_code == 502
    assert error.value.detail == "account_creation_failed"


def test_registration_preserves_non_conflict_keycloak_errors() -> None:
    """Only a Keycloak 409 is translated to an email conflict."""
    registration.reset_rate_limit_state()

    with pytest.raises(httpx.HTTPStatusError) as error:
        registration.register_account(
            _registration_request(),
            _registration_http_request(),
            api=_NonConflictCreateApi(),
        )

    assert error.value.response.status_code == 503


def test_scim_dependencies_fail_closed_when_unwired() -> None:
    """SCIM provisioner and shared-lock dependencies reject missing wiring."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))

    with pytest.raises(HTTPException) as api_error:
        scim.get_provisioner(request)
    with pytest.raises(HTTPException) as lock_error:
        scim.get_user_operation_locks(request)

    assert api_error.value.status_code == 503
    assert lock_error.value.status_code == 503


def test_scim_primary_email_handles_absent_and_fallback_entries() -> None:
    """Email extraction returns none or the first non-primary address."""
    assert scim._primary_email({}) is None
    assert scim._primary_email(
        {
            "emails": [
                {"value": "first@example.com"},
                {"value": "second@example.com"},
            ]
        }
    ) == "first@example.com"


def test_scim_model_translation_covers_disabled_minimal_resource() -> None:
    """Minimal disabled resources omit optional SCIM fields on serialization."""
    account = scim._to_user_account(
        {"userName": "disabled", "active": False},
        user_id="disabled-id",
    )

    assert account.state == "disabled"
    assert account.email is None
    resource = scim._to_scim_resource(account)
    assert resource["active"] is False
    assert "externalId" not in resource
    assert "emails" not in resource


def test_scim_create_requires_username() -> None:
    """SCIM create rejects a resource without the required userName."""
    with pytest.raises(HTTPException) as error:
        scim.create_user({}, provisioner=_MinimalProvisioner())

    assert error.value.status_code == 400


def test_scim_search_covers_empty_invalid_and_missing_results() -> None:
    """Search handles no filter, malformed syntax, and an empty exact match."""
    provisioner = _MinimalProvisioner()
    empty_request = SimpleNamespace(query_params={})
    missing_request = SimpleNamespace(
        query_params={"filter": 'userName eq "missing"'}
    )
    invalid_request = SimpleNamespace(
        query_params={"filter": 'email eq "jane@example.com"'}
    )

    empty = scim.search_users(empty_request, provisioner=provisioner)
    missing = scim.search_users(missing_request, provisioner=provisioner)
    with pytest.raises(HTTPException) as invalid_error:
        scim.search_users(invalid_request, provisioner=provisioner)

    assert b'"totalResults": 0' in empty.body
    assert b'"totalResults": 0' in missing.body
    assert invalid_error.value.status_code == 400


def test_scim_replace_translates_unknown_user_and_lock_timeout() -> None:
    """SCIM PUT distinguishes a missing user from lock contention."""
    provisioner = _MinimalProvisioner()
    resource = {"userName": "missing"}

    with pytest.raises(HTTPException) as missing_error:
        scim.replace_user(
            "missing",
            resource,
            provisioner=provisioner,
            user_operation_locks=InMemoryUserOperationLocks(),
        )

    with pytest.raises(HTTPException) as timeout_error:
        scim.replace_user(
            "user-1",
            resource,
            provisioner=provisioner,
            user_operation_locks=_TimeoutLocks(),
        )

    assert missing_error.value.status_code == 404
    assert timeout_error.value.status_code == 503


def test_scim_patch_handles_unknown_and_ignored_operations() -> None:
    """SCIM PATCH rejects unknown users and ignores unsupported operations."""
    provisioner = _MinimalProvisioner()
    locks = InMemoryUserOperationLocks()

    with pytest.raises(HTTPException) as missing_error:
        scim.patch_user(
            "missing",
            {"Operations": []},
            provisioner=provisioner,
            user_operation_locks=locks,
        )

    response = scim.patch_user(
        "user-1",
        {
            "Operations": [
                {"op": "remove", "path": "active", "value": False},
                {"op": "add", "path": "displayName", "value": "Jane"},
                {"op": "replace", "path": "active", "value": "false"},
            ]
        },
        provisioner=provisioner,
        user_operation_locks=locks,
    )

    assert missing_error.value.status_code == 404
    assert response.status_code == 200
    assert "deactivate" in provisioner.calls


def test_scim_patch_translates_lock_timeout() -> None:
    """SCIM PATCH returns a retryable error when the shared lock is busy."""
    with pytest.raises(HTTPException) as error:
        scim.patch_user(
            "user-1",
            {"Operations": []},
            provisioner=_MinimalProvisioner(),
            user_operation_locks=_TimeoutLocks(),
        )

    assert error.value.status_code == 503


def test_scim_delete_rejects_unknown_user() -> None:
    """SCIM DELETE reports a missing resource without mutation."""
    with pytest.raises(HTTPException) as error:
        scim.delete_user(
            "missing",
            provisioner=_MinimalProvisioner(),
            user_operation_locks=InMemoryUserOperationLocks(),
        )

    assert error.value.status_code == 404


def test_scim_delete_translates_lock_timeout() -> None:
    """SCIM DELETE returns a retryable error when the shared lock is busy."""
    with pytest.raises(HTTPException) as error:
        scim.delete_user(
            "user-1",
            provisioner=_MinimalProvisioner(),
            user_operation_locks=_TimeoutLocks(),
        )

    assert error.value.status_code == 503
