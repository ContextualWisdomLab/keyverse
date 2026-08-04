"""Coverage regressions for federation storage, validation, and route edges."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.federation import (
    FEDERATION_PROVIDER_NAMESPACE,
    FederationService,
    IdentityProviderRegistration,
    _validate_provider_alias,
    get_federation_service,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app


def _oidc_registration(**updates) -> IdentityProviderRegistration:
    """Return one valid provider-neutral OIDC desired-state record."""
    values = {
        "provider_alias": "partner-oidc",
        "display_name": "Partner OIDC",
        "provider_id": "oidc",
        "enabled": True,
        "trust_email": False,
        "provider_config": {
            "issuer": "https://login.partner.example/tenant",
            "authorizationUrl": (
                "https://login.partner.example/tenant/oauth2/authorize"
            ),
            "tokenUrl": "https://login.partner.example/tenant/oauth2/token",
            "jwksUrl": "https://login.partner.example/tenant/oidc/jwks",
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
    values.update(updates)
    return IdentityProviderRegistration.model_validate(values)


def test_delete_missing_and_unapplied_registration_paths(api) -> None:
    """Delete reports missing state and skips Keycloak deletion when absent."""
    store = InMemoryKvStore()
    federation = FederationService(store, api)

    with pytest.raises(HTTPException) as missing_error:
        federation.delete_registration("partner-oidc")

    registration = _oidc_registration()
    store.put(
        FEDERATION_PROVIDER_NAMESPACE,
        registration.provider_alias,
        registration.model_dump_json(),
    )
    federation.delete_registration(registration.provider_alias)

    assert missing_error.value.status_code == 404
    assert store.get(
        FEDERATION_PROVIDER_NAMESPACE,
        registration.provider_alias,
    ) is None
    assert not any(
        call.startswith("delete_identity_provider:") for call in api.calls
    )


@pytest.mark.parametrize(
    "provider_alias",
    ["", "-leading", "trailing-", "a" * 64, "contains_underscore"],
)
def test_provider_alias_rejects_every_slug_boundary(provider_alias: str) -> None:
    """Alias validation covers empty, edge, length, and alphabet failures."""
    with pytest.raises(HTTPException) as error:
        _validate_provider_alias(provider_alias)

    assert error.value.status_code == 400


@pytest.mark.parametrize(
    "provider_config",
    [
        {"": "value"},
        {"k" * 129: "value"},
        {"key": "v" * 16_385},
    ],
)
def test_provider_config_key_and_value_bounds_fail_before_persistence(
    provider_config: dict[str, str], api
) -> None:
    """Invalid configuration entries cannot enter the desired-state store."""
    store = InMemoryKvStore()
    federation = FederationService(store, api)
    registration = _oidc_registration(provider_config=provider_config)

    with pytest.raises(HTTPException) as error:
        federation.put_registration("partner-oidc", registration)

    assert error.value.status_code == 400
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_http_url_requires_hostname(api) -> None:
    """An HTTP entity or endpoint without an authority fails closed."""
    registration = IdentityProviderRegistration(
        provider_alias="partner-saml",
        display_name="Partner SAML",
        provider_id="saml",
        provider_config={
            "entityId": "urn:keyverse:sp",
            "idpEntityId": "urn:partner:idp",
            "singleSignOnServiceUrl": "https:/missing-authority",
            "validateSignature": "true",
            "useMetadataDescriptorUrl": "false",
            "signingCertificate": "certificate",
        },
    )
    federation = FederationService(InMemoryKvStore(), api)

    with pytest.raises(HTTPException) as error:
        federation.validate_registration(registration)

    assert error.value.status_code == 400
    assert "singleSignOnServiceUrl" in error.value.detail


def test_federation_dependency_fails_closed_when_unwired() -> None:
    """Federation routes return 503 instead of using an absent service."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))

    with pytest.raises(HTTPException) as error:
        get_federation_service(request)

    assert error.value.status_code == 503


def test_http_apply_route_reconciles_stored_desired_state(
    api, auth_header, operator_token
) -> None:
    """The public operator route exposes the stored-state recovery action."""
    store = InMemoryKvStore()
    registration = _oidc_registration()
    store.put(
        FEDERATION_PROVIDER_NAMESPACE,
        registration.provider_alias,
        registration.model_dump_json(),
    )
    app = create_app(wire=False)
    app.state.federation_service = FederationService(store, api)
    app.state.operator_api_token = operator_token

    with TestClient(app, headers=auth_header) as client:
        response = client.post("/federation/identity-providers:apply")

    assert response.status_code == 200
    assert response.json()[0]["applied_to_keycloak"] is True
    assert registration.provider_alias in api.identity_providers
