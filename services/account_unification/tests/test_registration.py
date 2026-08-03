"""Headless self-registration and bootstrap-credential retirement tests."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import registration as registration_module
from app.main import create_app
from app.registration import revoke_bootstrap_passwords

REGISTRATION_TOKEN = "registration-token-for-tests"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """Reset process-local rate-limit state between tests."""
    registration_module._registration_attempt_window_start = 0.0
    registration_module._registration_attempt_count = 0
    yield


@pytest.fixture
def client(api):
    """Return a registration-authenticated test client."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.registration_api_token = REGISTRATION_TOKEN
    headers = {
        "Authorization": f"Bearer {REGISTRATION_TOKEN}"
    }
    with TestClient(app, headers=headers) as test_client:
        yield test_client


def _registration(
    email="new.user@example.com",
    password="bootstrap-pass-1",
):
    """Build one valid registration payload."""
    return {
        "email_address": email,
        "initial_password": password,
        "first_name": "New",
        "last_name": "User",
    }


def test_registration_creates_passwordless_transition_account(
    client, api
):
    """Registration creates a bootstrap credential and passkey action."""
    response = client.post(
        "/registration/accounts",
        json=_registration(),
    )
    assert response.status_code == 201
    body = response.json()
    account_id = body["account_id"]
    assert body["email_address"] == "new.user@example.com"
    assert api.users[account_id].is_email_verified is False
    assert api.required_actions[account_id] == [
        "webauthn-register-passwordless"
    ]
    assert {
        item["type"]
        for item in api.list_user_credentials(account_id)
    } == {"password"}


def test_registration_rolls_back_partial_initialization(
    client, api, monkeypatch
):
    """An initialization failure deletes the newly created account."""
    def fail_required_actions(*args, **kwargs):
        raise RuntimeError("simulated Keycloak failure")

    monkeypatch.setattr(
        api,
        "set_user_required_actions",
        fail_required_actions,
    )
    response = client.post(
        "/registration/accounts",
        json=_registration(),
    )
    assert response.status_code == 502
    assert response.json()["detail"] == (
        "account_initialization_failed"
    )
    assert api.find_users_by_email(
        "new.user@example.com"
    ) == []
    assert any(
        call.startswith("delete_user:")
        for call in api.calls
    )


def test_registration_normalizes_email_case(client):
    """Email addresses are normalized before account creation."""
    response = client.post(
        "/registration/accounts",
        json=_registration(
            email="Mixed.Case@Example.COM"
        ),
    )
    assert response.status_code == 201
    assert response.json()["email_address"] == (
        "mixed.case@example.com"
    )


def test_registration_accepts_tagged_email(client):
    """Tagged local parts are accepted without regex backtracking."""
    response = client.post(
        "/registration/accounts",
        json=_registration(
            email="new.user+product@example.com"
        ),
    )
    assert response.status_code == 201


def test_registration_rejects_duplicate_email(client):
    """Duplicate normalized email addresses are rejected."""
    assert client.post(
        "/registration/accounts",
        json=_registration(),
    ).status_code == 201
    duplicate = client.post(
        "/registration/accounts",
        json=_registration(),
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == (
        "email_already_registered"
    )


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
        "/registration/accounts",
        json=_registration(email=email),
    )
    assert response.status_code == 422


def test_registration_rejects_short_password(client):
    """Bootstrap credentials below the minimum are rejected."""
    response = client.post(
        "/registration/accounts",
        json=_registration(password="short"),
    )
    assert response.status_code == 422


def test_registration_surface_fails_closed_without_token(api):
    """The endpoint is unavailable when its credential is absent."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.registration_api_token = None
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts",
            json=_registration(),
            headers={
                "Authorization":
                    f"Bearer {REGISTRATION_TOKEN}"
            },
        )
    assert response.status_code == 503


def test_registration_rejects_wrong_token(api):
    """A mismatched registration credential is rejected."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.registration_api_token = REGISTRATION_TOKEN
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts",
            json=_registration(),
            headers={
                "Authorization": "Bearer wrong-token"
            },
        )
    assert response.status_code == 403


def test_operator_token_does_not_open_registration(api):
    """The operator credential cannot authorize product signup."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.registration_api_token = REGISTRATION_TOKEN
    app.state.operator_api_token = "operator-token"
    with TestClient(app) as test_client:
        response = test_client.post(
            "/registration/accounts",
            json=_registration(),
            headers={
                "Authorization": "Bearer operator-token"
            },
        )
    assert response.status_code == 403


def test_janitor_revokes_only_after_passkey_enrollment(
    client, api
):
    """Bootstrap credentials survive until a passkey exists."""
    enrolled = client.post(
        "/registration/accounts",
        json=_registration(
            email="enrolled@example.com"
        ),
    ).json()["account_id"]
    pending = client.post(
        "/registration/accounts",
        json=_registration(
            email="pending@example.com"
        ),
    ).json()["account_id"]
    api.add_test_passkey(enrolled)

    result = revoke_bootstrap_passwords(api)

    assert result.revoked_passwords == 1
    enrolled_types = {
        item["type"]
        for item in api.list_user_credentials(enrolled)
    }
    pending_types = {
        item["type"]
        for item in api.list_user_credentials(pending)
    }
    assert "password" not in enrolled_types
    assert "webauthn-passwordless" in enrolled_types
    assert "password" in pending_types


def test_janitor_endpoint_runs_one_pass(client, api):
    """The protected endpoint executes one bounded cleanup pass."""
    account_id = client.post(
        "/registration/accounts",
        json=_registration(
            email="janitor@example.com"
        ),
    ).json()["account_id"]
    api.add_test_passkey(account_id)

    response = client.post(
        "/registration/password-janitor:run"
    )

    assert response.status_code == 200
    assert response.json()["revoked_passwords"] == 1
