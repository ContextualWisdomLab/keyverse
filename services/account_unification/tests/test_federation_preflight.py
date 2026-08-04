"""Federation preflight validation, SAML policy, and side-effect tests."""
from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.federation import (
    FEDERATION_PROVIDER_NAMESPACE,
    FederationService,
    IdentityProviderRegistration,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app


def _adfs_body() -> dict:
    """Return a valid employer ADFS desired-state request body."""
    return {
        "provider_alias": "employer-adfs",
        "display_name": "Employer ADFS",
        "provider_id": "saml",
        "enabled": True,
        "trust_email": True,
        "provider_config": {
            "entityId": "https://idp.example/realms/cwl",
            "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",
            "metadataDescriptorUrl": (
                "https://sts.example/FederationMetadata/2007-06/"
                "FederationMetadata.xml"
            ),
            "useMetadataDescriptorUrl": "true",
            "validateSignature": "true",
            "clientSecret": "federation-secret",
            "unclassifiedValue": "must-not-leak",
        },
    }


def _build_app(store, api, operator_token: str):
    """Return a test app with explicit federation dependencies."""
    app = create_app(wire=False)
    app.state.federation_service = FederationService(store, api)
    app.state.operator_api_token = operator_token
    return app


def test_preflight_validates_without_side_effects_and_redacts(
    api, auth_header, operator_token
) -> None:
    """A valid preflight is redacted and never touches storage or Keycloak."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=_adfs_body(),
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ready_to_apply"] is True
    config = payload["registration"]["provider_config"]
    assert config["clientSecret"] == "<redacted>"
    assert config["unclassifiedValue"] == "<redacted>"
    assert config["singleSignOnServiceUrl"] == "https://sts.example/adfs/ls/"
    assert "federation-secret" not in response.text
    assert "must-not-leak" not in response.text
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_preflight_rejects_unresolved_templates_without_side_effects(
    api, auth_header, operator_token
) -> None:
    """Unrendered deployment templates fail before storage or network calls."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"]["metadataDescriptorUrl"] = (
        "{{employer_adfs_metadata_url}}"
    )

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "provider_config contains unresolved template placeholders"
    )
    assert "employer_adfs_metadata_url" not in response.text
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


@pytest.mark.parametrize("removed_key", ["entityId", "singleSignOnServiceUrl"])
def test_saml_preflight_requires_core_urls(
    removed_key: str, api, auth_header, operator_token
) -> None:
    """SAML preflight requires both the SP entity and SSO service URLs."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"].pop(removed_key)

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 400
    assert removed_key in response.json()["detail"]
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    [
        ("entityId", "relative-realm-id"),
        ("singleSignOnServiceUrl", "ftp://sts.example/adfs/ls/"),
        (
            "metadataDescriptorUrl",
            "https://operator:secret@sts.example/FederationMetadata.xml",
        ),
        (
            "metadataDescriptorUrl",
            "https://sts.example/FederationMetadata.xml#certificate",
        ),
        (
            "metadataDescriptorUrl",
            "https://sts.example/FederationMetadata.xml\nInjected: value",
        ),
    ],
)
def test_saml_preflight_rejects_unsafe_urls(
    field_name: str,
    unsafe_value: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """SAML URL fields reject non-HTTP, credentialed, fragmented, or control input."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"][field_name] = unsafe_value

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert unsafe_value not in response.text
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("validateSignature", "false"),
        ("validateSignature", "yes"),
        ("useMetadataDescriptorUrl", "sometimes"),
    ],
)
def test_saml_preflight_rejects_insecure_or_malformed_booleans(
    field_name: str,
    field_value: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """SAML security booleans accept only true/false and require validation."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"][field_name] = field_value

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert field_value not in response.text
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_saml_preflight_requires_metadata_url_when_enabled(
    api, auth_header, operator_token
) -> None:
    """Metadata-backed SAML validation requires a usable descriptor URL."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"].pop("metadataDescriptorUrl")

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 400
    assert "metadataDescriptorUrl" in response.json()["detail"]
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_saml_preflight_requires_manual_certificate_when_metadata_is_disabled(
    api, auth_header, operator_token
) -> None:
    """Manual SAML trust requires an explicit signing certificate."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"]["useMetadataDescriptorUrl"] = "false"
    body["provider_config"].pop("metadataDescriptorUrl")

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 400
    assert "signingCertificate" in response.json()["detail"]
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_saml_preflight_accepts_manual_signing_certificate(
    api, auth_header, operator_token
) -> None:
    """A manual certificate is accepted when metadata retrieval is disabled."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = _adfs_body()
    body["provider_config"]["useMetadataDescriptorUrl"] = "false"
    body["provider_config"].pop("metadataDescriptorUrl")
    body["provider_config"]["signingCertificate"] = "MIIC-test-certificate"

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 200
    config = response.json()["registration"]["provider_config"]
    assert config["signingCertificate"] == "<redacted>"
    assert "MIIC-test-certificate" not in response.text
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_put_rejects_invalid_saml_before_persisting_or_calling_keycloak(
    api,
) -> None:
    """The existing PUT boundary shares preflight validation before mutation."""
    store = InMemoryKvStore()
    federation = FederationService(store, api)
    body = _adfs_body()
    body["provider_config"]["validateSignature"] = "false"
    registration = IdentityProviderRegistration.model_validate(body)

    with pytest.raises(HTTPException) as error:
        federation.put_registration("employer-adfs", registration)

    assert error.value.status_code == 400
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_non_saml_preflight_remains_provider_neutral(
    api, auth_header, operator_token
) -> None:
    """OIDC registrations retain generic validation in this focused slice."""
    store = InMemoryKvStore()
    app = _build_app(store, api, operator_token)
    body = deepcopy(_adfs_body())
    body.update(
        {
            "provider_alias": "partner-oidc",
            "display_name": "Partner OIDC",
            "provider_id": "oidc",
            "trust_email": False,
            "provider_config": {
                "issuer": "https://login.partner.example",
                "clientId": "keyverse",
                "clientSecret": "oidc-secret",
            },
        }
    )

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )

    assert response.status_code == 200
    assert response.json()["registration"]["provider_alias"] == "partner-oidc"
    assert response.json()["registration"]["provider_config"]["issuer"] == (
        "https://login.partner.example"
    )
    assert response.json()["registration"]["provider_config"]["clientSecret"] == (
        "<redacted>"
    )
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []
