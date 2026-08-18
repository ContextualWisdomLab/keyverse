"""Start-login helper contracts: local discovery, no metadata fetch."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import ServiceConfig
from app.federation import FEDERATION_PROVIDER_NAMESPACE, IdentityProviderRegistration
from app.kv_store import InMemoryKvStore
from app.main import create_app
from app.start_login import StartLoginService, get_start_login_service


def _oidc_provider_json(*, enabled: bool = True, alias: str = "employer-adfs") -> str:
    """Return one stored OIDC provider registration."""
    return IdentityProviderRegistration.model_validate(
        {
            "provider_alias": alias,
            "display_name": "Employer ADFS",
            "provider_id": "oidc",
            "enabled": enabled,
            "trust_email": False,
            "provider_config": {
                "issuer": "https://login.employer.example/tenant",
                "authorizationUrl": "https://login.employer.example/oauth2/authorize",
                "tokenUrl": "https://login.employer.example/oauth2/token",
                "jwksUrl": "https://login.employer.example/oidc/jwks",
                "clientId": "keyverse",
                "clientSecret": "secret",
                "clientAuthMethod": "client_secret_basic",
                "validateSignature": "true",
                "useJwksUrl": "true",
                "pkceEnabled": "true",
                "pkceMethod": "S256",
                "defaultScope": "openid profile email",
            },
        }
    ).model_dump_json()


@pytest.fixture
def store() -> InMemoryKvStore:
    """Return a federation registry with one enabled employer IdP."""
    backend = InMemoryKvStore()
    backend.put(
        FEDERATION_PROVIDER_NAMESPACE,
        "employer-adfs",
        _oidc_provider_json(),
    )
    return backend


@pytest.fixture
def config() -> ServiceConfig:
    """Return local Keycloak issuer configuration."""
    return ServiceConfig(
        keycloak_server_url="http://keycloak.test",
        keycloak_realm="cwl",
        keycloak_client_id="account-unification-svc",
        keycloak_client_secret="test-secret",
        operator_api_token="test-operator-token",
    )


@pytest.fixture
def client(store: InMemoryKvStore, config: ServiceConfig, auth_header):
    """Return an authenticated app with the start-login helper wired."""
    app = create_app(wire=False)
    app.state.start_login_service = StartLoginService(store, config)
    app.state.operator_api_token = config.operator_api_token
    with TestClient(app, headers=auth_header) as test_client:
        yield test_client


def test_start_login_selects_single_enabled_provider_without_keycloak(client) -> None:
    """One enabled IdP becomes kc_idp_hint; no metadata fetch occurs."""
    response = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["metadata_fetch_performed"] is False
    assert body["federation_ownership"] == "keyverse"
    assert body["selected_provider_alias"] == "employer-adfs"
    assert "kc_idp_hint=employer-adfs" in body["start_login_url"]
    assert body["authorization_endpoint"].endswith("/realms/cwl/protocol/openid-connect/auth")
    assert "clientSecret" not in response.text
    assert "Add PKCE S256" in body["application_next_action"]


def test_start_login_requires_hint_when_multiple_providers(
    store: InMemoryKvStore, client
) -> None:
    """Multiple enabled IdPs return discovery until the RP supplies a hint."""
    store.put(
        FEDERATION_PROVIDER_NAMESPACE,
        "partner-oidc",
        _oidc_provider_json(alias="partner-oidc"),
    )
    discovered = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
        },
    )
    hinted = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "provider_alias_hint": "partner-oidc",
            "public_issuer_url": "https://idp.example/realms/cwl",
        },
    )
    unknown = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "provider_alias_hint": "missing-idp",
        },
    )
    assert discovered.status_code == 200
    assert discovered.json()["selected_provider_alias"] is None
    assert discovered.json()["start_login_url"] is None
    assert {item["provider_alias"] for item in discovered.json()["identity_providers"]} == {
        "employer-adfs",
        "partner-oidc",
    }
    assert hinted.json()["selected_provider_alias"] == "partner-oidc"
    assert hinted.json()["authorization_endpoint"].startswith("https://idp.example/")
    assert unknown.status_code == 404


def test_start_login_rejects_discovery_urls_and_unsafe_redirects(client, store) -> None:
    """The helper refuses discovery documents, HTTP redirects, and disabled IdPs."""
    store.put(
        FEDERATION_PROVIDER_NAMESPACE,
        "disabled-idp",
        _oidc_provider_json(alias="disabled-idp", enabled=False),
    )
    discovery = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "public_issuer_url": "https://idp.example/.well-known/openid-configuration",
        },
    )
    metadata = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "public_issuer_url": "https://idp.example/metadataUrl",
        },
    )
    http_redirect = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "http://naruon.example/callback",
        },
    )
    mismatched = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "other-web",
            "redirect_uri": "https://naruon.example/callback",
        },
    )
    aliases = {
        item["provider_alias"]
        for item in client.post(
            "/federation/identity-providers:start-login",
            json={
                "software_unit_id": "naruon-web",
                "client_id": "naruon-web",
                "redirect_uri": "https://naruon.example/callback",
            },
        ).json()["identity_providers"]
    }
    assert discovery.status_code == 400
    assert metadata.status_code == 400
    assert http_redirect.status_code == 400
    assert mismatched.status_code == 400
    assert "disabled-idp" not in aliases


def test_start_login_public_issuer_and_redirect_bounds(client) -> None:
    """Issuer and redirect inputs stay closed and local."""
    credentials = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "public_issuer_url": "https://user:pass@idp.example/realms/cwl",
        },
    )
    query = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "public_issuer_url": "https://idp.example/realms/cwl?x=1",
        },
    )
    fragment_redirect = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback#frag",
        },
    )
    oversized = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/" + ("a" * 2048),
        },
    )
    auth_endpoint = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "public_issuer_url": (
                "https://idp.example/realms/cwl/protocol/openid-connect/auth"
            ),
        },
    )
    assert credentials.status_code == 400
    assert query.status_code == 400
    assert fragment_redirect.status_code == 400
    assert oversized.status_code == 400
    assert auth_endpoint.json()["authorization_endpoint"].endswith(
        "/protocol/openid-connect/auth"
    )
    ftp = client.post(
        "/federation/identity-providers:start-login",
        json={
            "software_unit_id": "naruon-web",
            "client_id": "naruon-web",
            "redirect_uri": "https://naruon.example/callback",
            "public_issuer_url": "ftp://idp.example/realms/cwl",
        },
    )
    assert ftp.status_code == 400


def test_empty_registry_returns_discovery_without_start_url(
    config: ServiceConfig, auth_header
) -> None:
    """An empty local registry does not invent an identity provider."""
    app = create_app(wire=False)
    app.state.start_login_service = StartLoginService(InMemoryKvStore(), config)
    app.state.operator_api_token = config.operator_api_token
    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:start-login",
            json={
                "software_unit_id": "naruon-web",
                "client_id": "naruon-web",
                "redirect_uri": "https://naruon.example/callback",
            },
        )
    assert response.status_code == 200
    assert response.json()["identity_providers"] == []
    assert response.json()["start_login_url"] is None


def test_corrupt_provider_store_and_missing_service(store: InMemoryKvStore, config) -> None:
    """Corrupt registry rows and missing wiring fail closed."""
    store.put(FEDERATION_PROVIDER_NAMESPACE, "broken", "{")
    service = StartLoginService(store, config)
    with pytest.raises(Exception, match="corrupt"):
        service.discover_enabled_providers()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    with pytest.raises(HTTPException) as captured:
        get_start_login_service(request)
    assert captured.value.status_code == 503
