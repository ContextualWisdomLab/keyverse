"""Headless passwordless self-registration tests."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from app import registration as registration_module
from app.main import create_app
from app.registration import reset_rate_limit_state

REGISTRATION_TOKEN = "registration-token-for-tests"
OPERATOR_TOKEN = "operator-token-for-tests"
REGISTRATION_CLIENT_ID = "naruon-web"
REGISTRATION_REDIRECT_URI = "https://naruon.example/auth/passkey-complete"
REGISTRATION_ACTION_LIFESPAN_SECONDS = 900


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    """Reset caller-keyed registration limits between tests."""
    reset_rate_limit_state()
    yield
    reset_rate_limit_state()


def _wire_registration_app(api):
    """Return an app with the complete registration contract configured."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.registration_api_token = REGISTRATION_TOKEN
    app.state.operator_api_token = OPERATOR_TOKEN
    app.state.registration_client_id = REGISTRATION_CLIENT_ID
    app.state.registration_redirect_uri = REGISTRATION_REDIRECT_URI
    app.state.registration_action_lifespan_seconds = (
        REGISTRATION_ACTION_LIFESPAN_SECONDS
    )
    return app


@pytest.fixture
def client(api):
    """Return a registration-authenticated test client."""
    app = _wire_registration_app(api)
    headers = {"Authorization": f"Bearer {REGISTRATION_TOKEN}"}
    with TestClient(app, headers=headers) as test_client:
        yield test_client


def _registration(email: str = "new.user@example.com") -> dict[str, object]:
    """Build one valid registration payload without a password."""
    return {
        "email_address": email,
        "first_name": "New",
        "last_name": "User",
    }


def test_registration_sends_verified_passkey_enrollment_email(client, api):
    """Registration creates no password and sends bounded enrollment actions."""
    response = client.post("/registration/accounts", json=_registration())

    assert response.status_code == 201
    body = response.json()
    account_id = body["account_id"]
    assert body["email_address"] == "new.user@example.com"
    assert api.users[account_id].is_email_verified is False
    assert api.action_emails[account_id] == {
        "action_aliases": [
            "VERIFY_EMAIL",
            "webauthn-register-passwordless",
        ],
        "client_id": REGISTRATION_CLIENT_ID,
        "redirect_uri": REGISTRATION_REDIRECT_URI,
        "lifespan_seconds": REGISTRATION_ACTION_LIFESPAN_SECONDS,
    }
    assert not any(call.startswith("reset_user_password:") for call in api.calls)


def test_registration_rolls_back_when_enrollment_email_fails(
    client, api, monkeypatch
):
    """An action-email failure deletes the newly created account."""

    def fail_action_email(*args, **kwargs) -> None:
        """Simulate an unavailable Keycloak email transport."""
        raise RuntimeError("simulated Keycloak email failure")

    monkeypatch.setattr(api, "send_execute_actions_email", fail_action_email)

    response = client.post("/registration/accounts", json=_registration())

    assert response.status_code == 502
    assert response.json()["detail"] == "account_initialization_failed"
    assert api.find_users_by_email("new.user@example.com") == []
    assert any(call.startswith("delete_user:") for call in api.calls)


def test_registration_reports_rollback_failure(client, api, monkeypatch):
    """A failed cleanup is distinguishable from the enrollment failure."""

    def fail_action_email(*args, **kwargs) -> None:
        """Simulate the original initialization failure."""
        raise RuntimeError("simulated email failure")

    def fail_delete(*args, **kwargs) -> None:
        """Simulate rollback failure after user creation."""
        raise RuntimeError("simulated rollback failure")

    monkeypatch.setattr(api, "send_execute_actions_email", fail_action_email)
    monkeypatch.setattr(api, "delete_user", fail_delete)

    response = client.post("/registration/accounts", json=_registration())

    assert response.status_code == 502
    assert response.json()["detail"] == "account_initialization_rollback_failed"


def test_registration_normalizes_email_case(client):
    """Email addresses are normalized before account creation."""
    response = client.post(
        "/registration/accounts",
        json=_registration(email="Mixed.Case@Example.COM"),
    )
    assert response.status_code == 201
    assert response.json()["email_address"] == "mixed.case@example.com"


def test_registration_accepts_tagged_email(client):
    """Tagged local parts are accepted without regex backtracking."""
    response = client.post(
        "/registration/accounts",
        json=_registration(email="new.user+product@example.com"),
    )
    assert response.status_code == 201


def test_registration_rejects_duplicate_email(client):
    """Duplicate normalized email addresses are rejected before creation."""
    assert client.post(
        "/registration/accounts", json=_registration()
    ).status_code == 201

    duplicate = client.post("/registration/accounts", json=_registration())

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

    result = client.post("/registration/accounts", json=_registration())

    assert result.status_code == 409
    assert result.json()["detail"] == "email_already_registered"


@pytest.mark.parametrize(
    "email",
    [
        "not-an-email",
        "two@@example.com",
        "control\x00@example.com",
        "a@b",
        ".leading@example.com",
        "trailing.@example.com",
        "double..dot@example.com",
        "a@example..com",
        "a@-example.com",
        "a@example-.com",
        "a@exa_mple.com",
    ],
)
def test_registration_rejects_malformed_email(client, email):
    """Malformed syntax is rejected deterministically."""
    response = client.post(
        "/registration/accounts", json=_registration(email=email)
    )
    assert response.status_code == 422


def test_registration_rejects_legacy_password_field(client):
    """A password cannot silently cross the passwordless registration boundary."""
    payload = _registration()
    payload["initial_password"] = "legacy-bootstrap-password"

    response = client.post("/registration/accounts", json=payload)

    assert response.status_code == 422


def test_registration_surface_fails_closed_without_token(api):
    """The endpoint is unavailable when its credential is absent."""
    app = _wire_registration_app(api)
    app.state.registration_api_token = None
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts",
            json=_registration(),
            headers={"Authorization": f"Bearer {REGISTRATION_TOKEN}"},
        )
    assert response.status_code == 503


def test_registration_surface_fails_closed_without_enrollment_config(api):
    """Missing action-email configuration cannot create an unusable account."""
    app = _wire_registration_app(api)
    app.state.registration_redirect_uri = None
    with TestClient(
        app,
        headers={"Authorization": f"Bearer {REGISTRATION_TOKEN}"},
    ) as test_client:
        response = test_client.post(
            "/registration/accounts", json=_registration()
        )
    assert response.status_code == 503
    assert api.find_users_by_email("new.user@example.com") == []


def test_registration_rejects_wrong_token(api):
    """A mismatched registration credential is rejected."""
    app = _wire_registration_app(api)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts",
            json=_registration(),
            headers={"Authorization": "Bearer wrong-token"},
        )
    assert response.status_code == 403


def test_operator_token_does_not_open_registration(api):
    """The operator credential cannot authorize product signup."""
    app = _wire_registration_app(api)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts",
            json=_registration(),
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
    assert response.status_code == 403


def test_registration_rate_limit_isolated_by_caller(client, monkeypatch):
    """One caller cannot consume another caller's registration allowance."""
    monkeypatch.setattr(
        registration_module,
        "REGISTRATION_RATE_LIMIT_MAX_ATTEMPTS",
        1,
    )
    caller_keys = iter(["caller-a", "caller-a", "caller-b"])

    def next_caller_key(request) -> str:
        """Return deterministic caller identities for consecutive requests."""
        del request
        return next(caller_keys)

    monkeypatch.setattr(
        registration_module,
        "_registration_client_key",
        next_caller_key,
    )

    assert client.post(
        "/registration/accounts",
        json=_registration("first@example.com"),
    ).status_code == 201
    limited = client.post(
        "/registration/accounts",
        json=_registration("second@example.com"),
    )
    independent = client.post(
        "/registration/accounts",
        json=_registration("third@example.com"),
    )

    assert limited.status_code == 429
    assert independent.status_code == 201


def test_registration_router_has_no_realm_wide_janitor_endpoint(client):
    """Registration credentials cannot invoke a realm-wide destructive action."""
    response = client.post("/registration/password-janitor:run")
    assert response.status_code == 404
