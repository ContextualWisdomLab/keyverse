"""Exercise real HTTP header bytes at the separate runtime token gate."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import ServiceConfig
from app.federation import FederationService
from app.kv_store import InMemoryKvStore
from app.main import create_app
from app.start_login import StartLoginService


@pytest.fixture
def runtime_client():
    """Wire the real start-login service with an empty, local registry."""
    app = create_app(wire=False)
    config = ServiceConfig(
        keycloak_server_url="http://keycloak.test",
        keycloak_realm="cwl",
        keycloak_client_id="account-unification-svc",
        keycloak_client_secret="synthetic-fixture-value",
        operator_api_token="synthetic-operator-value",
        runtime_api_token="synthetic-runtime-value",
        public_issuer_url="https://idp.example/realms/cwl",
    )
    app.state.runtime_api_token = config.runtime_api_token
    app.state.start_login_service = StartLoginService(InMemoryKvStore(), config)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def _start_payload() -> dict[str, str]:
    """Return an otherwise-valid request without federation network calls."""
    return {
        "software_unit_id": "naruon-web",
        "client_id": "naruon-web",
        "redirect_uri": "https://naruon.example/callback",
    }


def test_runtime_ascii_token_has_authorized_positive(runtime_client) -> None:
    """A correctly configured ASCII token reaches a successful real handler."""
    response = runtime_client.post(
        "/federation/identity-providers:start-login",
        json=_start_payload(),
        headers={"X-Keyverse-Runtime-Token": "synthetic-runtime-value"},
    )
    assert response.status_code == 200
    assert response.json()["metadata_fetch_performed"] is False


@pytest.mark.parametrize("presented", [b"\xe9", b"\xff", "잘못된값".encode("utf-8")])
def test_runtime_non_ascii_header_fails_closed(runtime_client, presented: bytes) -> None:
    """Raw non-ASCII HTTP header bytes receive the existing fixed denial."""
    response = runtime_client.post(
        "/federation/identity-providers:start-login",
        json=_start_payload(),
        headers=[(b"X-Keyverse-Runtime-Token", presented)],
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "invalid runtime service token"}


@pytest.fixture
def privileged_clients(api):
    """Wire existing operator and registration consumers without external I/O."""
    from app.registration import reset_rate_limit_state

    reset_rate_limit_state()
    operator_app = create_app(wire=False)
    operator_app.state.operator_api_token = "synthetic-operator-value"
    operator_app.state.federation_service = FederationService(InMemoryKvStore(), api)
    registration_app = create_app(wire=False)
    registration_app.state.keycloak_api = api
    registration_app.state.registration_api_token = "synthetic-registration-value"
    registration_app.state.registration_client_id = "naruon-web"
    registration_app.state.registration_redirect_uri = "https://naruon.example/callback"
    registration_app.state.registration_action_lifespan_seconds = 900
    with TestClient(operator_app, raise_server_exceptions=False) as operator_client:
        with TestClient(registration_app, raise_server_exceptions=False) as registration_client:
            yield {"operator": operator_client, "registration": registration_client}
    reset_rate_limit_state()


def _privileged_request(client: TestClient, surface: str, token: bytes):
    """Send raw bearer bytes through the real selected router dependency."""
    headers = [(b"Authorization", b"Bearer " + token)]
    if surface == "operator":
        return client.get("/federation/identity-providers", headers=headers)
    return client.post(
        "/registration/accounts",
        json={"email_address": "fixture@example.com"},
        headers=headers,
    )


@pytest.mark.parametrize("surface", ["operator", "registration"])
def test_sibling_ascii_bearer_has_authorized_positive(privileged_clients, surface) -> None:
    """Each otherwise-valid ASCII credential reaches its existing handler."""
    response = _privileged_request(
        privileged_clients[surface], surface, f"synthetic-{surface}-value".encode("ascii")
    )
    assert response.status_code == (200 if surface == "operator" else 201)


@pytest.mark.parametrize("surface", ["operator", "registration"])
@pytest.mark.parametrize("presented", [b"\xe9", b"\xff", "잘못된값".encode("utf-8")])
def test_sibling_non_ascii_bearer_fails_closed(privileged_clients, surface, presented) -> None:
    """The same raw-byte defect must not remain in sibling bearer guards."""
    response = _privileged_request(privileged_clients[surface], surface, presented)
    assert response.status_code == 403
    assert response.json() == {"detail": f"invalid {surface} token"}
