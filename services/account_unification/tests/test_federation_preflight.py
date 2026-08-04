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

_VALID_SIGNING_CERTIFICATE = (
    "MIH2MIGpoAMCAQICAQEwBQYDK2VwMBwxGjAYBgNVBAMMEUtleXZlcnNlIFRlc3Qg"
    "SWRQMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowHDEaMBgGA1UE"
    "AwwRS2V5dmVyc2UgVGVzdCBJZFAwKjAFBgMrZXADIQB5tVYuj+ZU+UB4sRLo"
    "qYunkB+FOuaVvtfg45ELrQSWZKMQMA4wDAYDVR0TAQH/BAIwADAFBgMrZXAD"
    "QQBETl77qTx6FIw1ZEqHCxT1BpLpPf/dJwxF1+vXFGiHUC6HEWWqPhXcWEj9"
    "nlg8E6KnnpjzSmaVOL2dtTZMoTkG"
)
_NEXT_SIGNING_CERTIFICATE = (
    "MIIBADCBs6ADAgECAgECMAUGAytlcDAhMR8wHQYDVQQDDBZLZXl2ZXJzZSBOZXh0"
    "IFRlc3QgSWRQMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowITEf"
    "MB0GA1UEAwwWS2V5dmVyc2UgTmV4dCBUZXN0IElkUDAqMAUGAytlcAMhAOfx"
    "YqEL7FWa/qGV5NzoS2lWjV0ssJY+tEbAaF4rF/LwoxAwDjAMBgNVHRMBAf8E"
    "AjAAMAUGAytlcANBAPBvYJMwDJ1k5Jb+BWzYUVirHSILZOjNzvFyOcR4PfMj"
    "DJfk2ivJ/fat8qsQNXspyeplpqOinqXxB/mCruM2Rw0="
)


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
            "idpEntityId": "http://sts.example/adfs/services/trust",
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


def _post_preflight(body: dict, store, api, auth_header, operator_token):
    """Post one preflight body through the authenticated HTTP boundary."""
    app = _build_app(store, api, operator_token)
    with TestClient(app, headers=auth_header) as client:
        return client.post(
            "/federation/identity-providers:validate",
            json=body,
        )


def _assert_no_side_effects(store, api) -> None:
    """Assert that preflight did not persist or call the Keycloak mock."""
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_preflight_validates_without_side_effects_and_redacts(
    api, auth_header, operator_token
) -> None:
    """A valid preflight is redacted and never touches storage or Keycloak."""
    store = InMemoryKvStore()

    response = _post_preflight(
        _adfs_body(), store, api, auth_header, operator_token
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ready_to_apply"] is True
    config = payload["registration"]["provider_config"]
    assert config["clientSecret"] == "<redacted>"
    assert config["unclassifiedValue"] == "<redacted>"
    assert config["idpEntityId"] == "http://sts.example/adfs/services/trust"
    assert config["singleSignOnServiceUrl"] == "https://sts.example/adfs/ls/"
    assert "federation-secret" not in response.text
    assert "must-not-leak" not in response.text
    _assert_no_side_effects(store, api)


def test_preflight_rejects_unresolved_templates_without_side_effects(
    api, auth_header, operator_token
) -> None:
    """Unrendered deployment templates fail before storage or network calls."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["metadataDescriptorUrl"] = (
        "{{employer_adfs_metadata_url}}"
    )

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "provider_config contains unresolved template placeholders"
    )
    assert "employer_adfs_metadata_url" not in response.text
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "removed_key",
    ["entityId", "idpEntityId", "singleSignOnServiceUrl"],
)
def test_saml_preflight_requires_core_identifiers_and_endpoint(
    removed_key: str, api, auth_header, operator_token
) -> None:
    """SAML preflight requires both entity identifiers and the SSO endpoint."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"].pop(removed_key)

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert removed_key in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    [
        ("entityId", "relative-realm-id"),
        ("idpEntityId", "https://operator:secret@sts.example/adfs/trust"),
        ("singleSignOnServiceUrl", "ftp://sts.example/adfs/ls/"),
        ("singleSignOnServiceUrl", " https://sts.example/adfs/ls/"),
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
        ("metadataDescriptorUrl", "https://[broken"),
    ],
)
def test_saml_preflight_rejects_unsafe_uris_and_urls(
    field_name: str,
    unsafe_value: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """SAML identifiers and URLs reject ambiguous or unsafe material."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"][field_name] = unsafe_value

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert unsafe_value not in response.text
    _assert_no_side_effects(store, api)


def test_saml_preflight_rejects_oversized_entity_identifier(
    api, auth_header, operator_token
) -> None:
    """SAML entity identifiers retain the standard 1,024-character ceiling."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["entityId"] = "urn:keyverse:" + ("a" * 1_013)

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "entityId" in response.json()["detail"]
    _assert_no_side_effects(store, api)


def test_saml_preflight_accepts_urn_entity_identifiers(
    api, auth_header, operator_token
) -> None:
    """SAML entity identifiers remain interoperable with absolute URN forms."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["entityId"] = "urn:keyverse:service-provider:cwl"
    body["provider_config"]["idpEntityId"] = "urn:partner:identity-provider"

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 200
    config = response.json()["registration"]["provider_config"]
    assert config["entityId"] == "urn:keyverse:service-provider:cwl"
    assert config["idpEntityId"] == "urn:partner:identity-provider"
    _assert_no_side_effects(store, api)


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
    body = _adfs_body()
    body["provider_config"][field_name] = field_value

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert field_value not in response.text
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "removed_key",
    ["validateSignature", "useMetadataDescriptorUrl"],
)
def test_saml_preflight_requires_explicit_security_mode(
    removed_key: str, api, auth_header, operator_token
) -> None:
    """SAML signature validation and certificate-source mode are explicit."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"].pop(removed_key)

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert removed_key in response.json()["detail"]
    _assert_no_side_effects(store, api)


def test_saml_preflight_requires_metadata_url_when_enabled(
    api, auth_header, operator_token
) -> None:
    """Metadata-backed SAML validation requires a usable descriptor URL."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"].pop("metadataDescriptorUrl")

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "metadataDescriptorUrl" in response.json()["detail"]
    _assert_no_side_effects(store, api)


def test_saml_preflight_requires_manual_certificate_when_metadata_is_disabled(
    api, auth_header, operator_token
) -> None:
    """Manual SAML trust requires an explicit signing certificate."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["useMetadataDescriptorUrl"] = "false"
    body["provider_config"].pop("metadataDescriptorUrl")

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "signingCertificate" in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "signing_certificates",
    [
        _VALID_SIGNING_CERTIFICATE,
        f"{_VALID_SIGNING_CERTIFICATE},{_NEXT_SIGNING_CERTIFICATE}",
    ],
)
def test_saml_preflight_accepts_valid_manual_signing_certificates(
    signing_certificates: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Manual trust accepts one certificate or an active rollover pair."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["useMetadataDescriptorUrl"] = "false"
    body["provider_config"].pop("metadataDescriptorUrl")
    body["provider_config"]["signingCertificate"] = signing_certificates

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 200
    config = response.json()["registration"]["provider_config"]
    assert config["signingCertificate"] == "<redacted>"
    assert signing_certificates not in response.text
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "signing_certificates",
    [
        "MIIC-test-certificate",
        "bm90LWFuLXg1MDktY2VydGlmaWNhdGU=",
        f"-----BEGIN CERTIFICATE-----{_VALID_SIGNING_CERTIFICATE}"
        "-----END CERTIFICATE-----",
        f"{_VALID_SIGNING_CERTIFICATE},",
    ],
)
def test_saml_preflight_rejects_invalid_manual_signing_certificates(
    signing_certificates: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Malformed Base64, non-X.509, PEM, and empty list entries fail closed."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["useMetadataDescriptorUrl"] = "false"
    body["provider_config"].pop("metadataDescriptorUrl")
    body["provider_config"]["signingCertificate"] = signing_certificates

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert response.json()["detail"].startswith("signingCertificate ")
    assert signing_certificates not in response.text
    _assert_no_side_effects(store, api)


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
    _assert_no_side_effects(store, api)


def test_non_saml_preflight_remains_provider_neutral(
    api, auth_header, operator_token
) -> None:
    """OIDC registrations retain generic validation in this focused slice."""
    store = InMemoryKvStore()
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

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 200
    assert response.json()["registration"]["provider_alias"] == "partner-oidc"
    assert response.json()["registration"]["provider_config"]["issuer"] == (
        "https://login.partner.example"
    )
    assert response.json()["registration"]["provider_config"]["clientSecret"] == (
        "<redacted>"
    )
    _assert_no_side_effects(store, api)
