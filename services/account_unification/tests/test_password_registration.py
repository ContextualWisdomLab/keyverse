"""Headless password-credential self-registration tests."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import password_registration as password_registration_module
from app.main import create_app
from app.models import UserAccount
from app.password_registration import reset_rate_limit_state

PASSWORD_REGISTRATION_TOKEN = "password-registration-token-for-tests"
REGISTRATION_TOKEN = "registration-token-for-tests"
OPERATOR_TOKEN = "operator-token-for-tests"
VALID_PASSWORD = "correct horse battery staple 1!"


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    """Reset caller-keyed registration limits between tests."""
    reset_rate_limit_state()
    yield
    reset_rate_limit_state()


def _wire_password_registration_app(api):
    """Return an app with the password-registration contract configured."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.password_registration_api_token = PASSWORD_REGISTRATION_TOKEN
    app.state.registration_api_token = REGISTRATION_TOKEN
    app.state.operator_api_token = OPERATOR_TOKEN
    return app


@pytest.fixture
def client(api, monkeypatch):
    """Return a password-registration-authenticated test client.

    Patches the module's fail-closed gate open so these tests exercise the
    account-creation logic itself; the gate's own default-closed behavior is
    covered separately by ``test_registration_fails_closed_by_default``.
    """
    monkeypatch.setattr(
        password_registration_module, "PASSWORD_CREDENTIAL_LOGIN_AVAILABLE", True
    )
    app = _wire_password_registration_app(api)
    headers = {"Authorization": f"Bearer {PASSWORD_REGISTRATION_TOKEN}"}
    with TestClient(app, headers=headers) as test_client:
        yield test_client


def test_registration_fails_closed_by_default(api):
    """Direct Access Grants is disabled, so signup must not create dead accounts."""
    app = _wire_password_registration_app(api)
    headers = {"Authorization": f"Bearer {PASSWORD_REGISTRATION_TOKEN}"}
    with TestClient(app, headers=headers) as test_client:
        response = test_client.post(
            "/registration/accounts/password", json=_registration()
        )

    assert response.status_code == 503
    assert response.json()["detail"] == password_registration_module.PASSWORD_LOGIN_BLOCKED_DETAIL
    assert api.find_users_by_email("new.user@example.com") == []
    assert api.calls == []


def _registration(
    email: str = "new.user@example.com", password: str = VALID_PASSWORD
) -> dict[str, object]:
    """Build one valid password-registration payload."""
    return {
        "email_address": email,
        "password": password,
        "first_name": "New",
        "last_name": "User",
    }


def test_registration_creates_account_with_immediately_usable_password(
    client, api
):
    """Signup creates a password credential, not a WebAuthn enrollment email."""
    response = client.post("/registration/accounts/password", json=_registration())

    assert response.status_code == 201
    body = response.json()
    account_id = body["account_id"]
    assert body["email_address"] == "new.user@example.com"
    assert api.users[account_id].is_email_verified is False
    assert api.password_credentials[account_id] == VALID_PASSWORD
    assert account_id not in api.action_emails
    # Regression: the realm's passwordless-enrollment default required
    # action is an interactive step Direct Access Grants cannot complete.
    # Without an explicit override, every immediate post-signup login
    # failed even though a usable password credential exists.
    assert api.users[account_id].required_actions == []


def test_registration_rolls_back_when_credential_set_fails(client, api, monkeypatch):
    """A failed credential set deletes the newly created account."""

    def fail_reset_password(*args, **kwargs) -> None:
        """Simulate an unavailable Keycloak credential transport."""
        raise RuntimeError("simulated Keycloak credential failure")

    monkeypatch.setattr(api, "reset_password", fail_reset_password)

    response = client.post("/registration/accounts/password", json=_registration())

    assert response.status_code == 502
    assert response.json()["detail"] == "account_credential_failed"
    assert api.find_users_by_email("new.user@example.com") == []
    assert any(call.startswith("delete_user:") for call in api.calls)


def test_registration_reports_rollback_failure(client, api, monkeypatch):
    """A failed cleanup is distinguishable from the credential failure."""

    def fail_reset_password(*args, **kwargs) -> None:
        """Simulate the original credential-set failure."""
        raise RuntimeError("simulated credential failure")

    def fail_delete(*args, **kwargs) -> None:
        """Simulate rollback failure after user creation."""
        raise RuntimeError("simulated rollback failure")

    monkeypatch.setattr(api, "reset_password", fail_reset_password)
    monkeypatch.setattr(api, "delete_user", fail_delete)

    response = client.post("/registration/accounts/password", json=_registration())

    assert response.status_code == 502
    assert response.json()["detail"] == "account_credential_rollback_failed"


def test_registration_normalizes_email_case(client):
    """Email addresses are normalized before account creation."""
    response = client.post(
        "/registration/accounts/password",
        json=_registration(email="Mixed.Case@Example.COM"),
    )
    assert response.status_code == 201
    assert response.json()["email_address"] == "mixed.case@example.com"


def test_registration_rejects_duplicate_email(client):
    """Duplicate normalized email addresses are rejected before creation."""
    assert client.post(
        "/registration/accounts/password", json=_registration()
    ).status_code == 201

    duplicate = client.post("/registration/accounts/password", json=_registration())

    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "email_already_registered"


def test_concurrent_keycloak_duplicate_maps_to_registration_conflict(
    client, api, monkeypatch
):
    """A Keycloak create-user 409 remains an idempotent product conflict."""
    request = httpx.Request("POST", "http://keycloak.test/admin/realms/cwl/users")
    response = httpx.Response(409, request=request)

    def reject_concurrent_duplicate(*args, **kwargs):
        """Model a competing request winning after the preflight lookup."""
        raise httpx.HTTPStatusError(
            "duplicate user", request=request, response=response
        )

    monkeypatch.setattr(api, "create_user", reject_concurrent_duplicate)

    result = client.post("/registration/accounts/password", json=_registration())

    assert result.status_code == 409
    assert result.json()["detail"] == "email_already_registered"


@pytest.mark.parametrize(
    "email",
    [
        "not-an-email",
        "two@@example.com",
        "control\x00@example.com",
        "a@b",
    ],
)
def test_registration_rejects_malformed_email(client, email):
    """Malformed syntax is rejected deterministically."""
    response = client.post(
        "/registration/accounts/password", json=_registration(email=email)
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "password",
    [
        "short",  # below MIN_PASSWORD_LENGTH
        " leading-space-padded-enough",
        "trailing-space-padded-enough ",
        "control\x00character-padded-enough",
    ],
)
def test_registration_rejects_malformed_password(client, password):
    """A malformed password is rejected before any Keycloak call."""
    response = client.post(
        "/registration/accounts/password",
        json=_registration(password=password),
    )
    assert response.status_code == 422


def test_registration_rejects_password_matching_email(client):
    """A password identical to the account's own email is rejected."""
    response = client.post(
        "/registration/accounts/password",
        json=_registration(
            email="new.user@example.com", password="New.User@Example.com"
        ),
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "password_must_not_match_email"


def test_registration_surface_fails_closed_without_token(api):
    """The endpoint is unavailable when its credential is absent."""
    app = _wire_password_registration_app(api)
    app.state.password_registration_api_token = None
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts/password",
            json=_registration(),
            headers={"Authorization": f"Bearer {PASSWORD_REGISTRATION_TOKEN}"},
        )
    assert response.status_code == 503


def test_registration_rejects_wrong_token(api):
    """A mismatched password-registration credential is rejected."""
    app = _wire_password_registration_app(api)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts/password",
            json=_registration(),
            headers={"Authorization": "Bearer wrong-token"},
        )
    assert response.status_code == 403


def test_operator_token_does_not_open_password_registration(api):
    """The operator credential cannot authorize password-based signup."""
    app = _wire_password_registration_app(api)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts/password",
            json=_registration(),
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
    assert response.status_code == 403


def test_passwordless_registration_token_does_not_open_password_registration(api):
    """Naruon's passwordless-enrollment credential cannot cross into ROPC signup."""
    app = _wire_password_registration_app(api)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts/password",
            json=_registration(),
            headers={"Authorization": f"Bearer {REGISTRATION_TOKEN}"},
        )
    assert response.status_code == 403


def test_registration_rate_limit_isolated_by_caller(client, monkeypatch):
    """One caller cannot consume another caller's registration allowance."""
    monkeypatch.setattr(
        password_registration_module,
        "PASSWORD_REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS",
        1,
    )
    caller_keys = iter(["caller-a", "caller-a", "caller-b"])

    def next_caller_key(request) -> str:
        """Return deterministic caller identities for consecutive requests."""
        del request
        return next(caller_keys)

    monkeypatch.setattr(
        password_registration_module,
        "_registration_client_key",
        next_caller_key,
    )

    assert client.post(
        "/registration/accounts/password",
        json=_registration("first@example.com"),
    ).status_code == 201
    limited = client.post(
        "/registration/accounts/password",
        json=_registration("second@example.com"),
    )
    independent = client.post(
        "/registration/accounts/password",
        json=_registration("third@example.com"),
    )

    assert limited.status_code == 429
    assert independent.status_code == 201


def test_password_registration_router_has_no_realm_wide_janitor_endpoint(client):
    """Password-registration credentials cannot invoke a destructive wildcard."""
    response = client.post("/registration/password-janitor:run")
    assert response.status_code == 404


class _UnavailableApi:
    """Expose only methods needed by direct password-registration edge tests."""

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
            "upstream unavailable", request=request, response=response
        )


def _password_registration_request() -> SimpleNamespace:
    """Return one valid direct-call password-registration request body."""
    return SimpleNamespace(
        email_address="new.user@example.com",
        password=VALID_PASSWORD,
        first_name=None,
        last_name=None,
    )


def _password_registration_http_request() -> SimpleNamespace:
    """Return one bare request carrying only the fields the route reads."""
    return SimpleNamespace(client=None)


def test_password_registration_requires_a_bearer_header() -> None:
    """A configured signup surface still rejects an absent header."""
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                password_registration_api_token="expected-token"
            )
        )
    )

    with pytest.raises(HTTPException) as error:
        password_registration_module.require_password_registration_token(
            request, authorization=None
        )

    assert error.value.status_code == 401
    assert error.value.headers == {"WWW-Authenticate": "Bearer"}


def test_password_registration_admin_api_dependency_fails_closed() -> None:
    """Signup cannot proceed without a wired product Keycloak client."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))

    with pytest.raises(HTTPException) as error:
        password_registration_module.get_admin_api(request)

    assert error.value.status_code == 503


def test_password_registration_window_resets_after_expiry(monkeypatch) -> None:
    """A fixed-window caller budget resets after the configured duration."""
    password_registration_module.reset_rate_limit_state()
    times = iter([
        0.0,
        password_registration_module.PASSWORD_REGISTRATION_RATE_LIMIT_WINDOW_SECONDS
        + 1.0,
    ])
    monkeypatch.setattr(
        password_registration_module.time, "monotonic", lambda: next(times)
    )
    monkeypatch.setattr(
        password_registration_module,
        "PASSWORD_REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS",
        1,
    )

    password_registration_module._record_registration_attempt("caller")
    password_registration_module._record_registration_attempt("caller")


def test_password_registration_reports_empty_upstream_identifier(monkeypatch) -> None:
    """An upstream create response without an ID becomes a bounded 502."""
    password_registration_module.reset_rate_limit_state()
    monkeypatch.setattr(
        password_registration_module, "PASSWORD_CREDENTIAL_LOGIN_AVAILABLE", True
    )

    with pytest.raises(HTTPException) as error:
        password_registration_module.register_account_with_password(
            _password_registration_request(),
            _password_registration_http_request(),
            api=_UnavailableApi(),
        )

    assert error.value.status_code == 502
    assert error.value.detail == "account_creation_failed"


def test_password_registration_preserves_non_conflict_keycloak_errors(monkeypatch) -> None:
    """Only a Keycloak 409 is translated to an email conflict."""
    password_registration_module.reset_rate_limit_state()
    monkeypatch.setattr(
        password_registration_module, "PASSWORD_CREDENTIAL_LOGIN_AVAILABLE", True
    )

    with pytest.raises(httpx.HTTPStatusError) as error:
        password_registration_module.register_account_with_password(
            _password_registration_request(),
            _password_registration_http_request(),
            api=_NonConflictCreateApi(),
        )

    assert error.value.response.status_code == 503
