"""Additional SAML URL hardening tests for encoded and ambiguous input."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.federation import FEDERATION_PROVIDER_NAMESPACE, FederationService
from app.kv_store import InMemoryKvStore
from app.main import create_app


def _registration_body(metadata_url: str) -> dict:
    """Return one otherwise-valid metadata-backed SAML registration."""
    return {
        "provider_alias": "employer-adfs",
        "display_name": "Employer ADFS",
        "provider_id": "saml",
        "enabled": True,
        "trust_email": True,
        "provider_config": {
            "entityId": "urn:keyverse:service-provider:cwl",
            "idpEntityId": "urn:partner:identity-provider",
            "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",
            "metadataDescriptorUrl": metadata_url,
            "useMetadataDescriptorUrl": "true",
            "validateSignature": "true",
        },
    }


def _preflight(metadata_url, api, auth_header, operator_token):
    """Post one metadata URL and return the response plus its fresh store."""
    store = InMemoryKvStore()
    app = create_app(wire=False)
    app.state.federation_service = FederationService(store, api)
    app.state.operator_api_token = operator_token
    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=_registration_body(metadata_url),
        )
    return response, store


@pytest.mark.parametrize(
    "metadata_url",
    [
        "https://sts.example/Federation Metadata.xml",
        "https://sts.example\\metadata.example/FederationMetadata.xml",
        "https://sts.example/FederationMetadata.xml%0d%0aInjected",
        "https://sts.example/FederationMetadata.xml\u00a0",
    ],
)
def test_preflight_rejects_whitespace_backslash_and_encoded_controls(
    metadata_url: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Ambiguous URL material fails closed without persistence or network I/O."""
    response, store = _preflight(
        metadata_url, api, auth_header, operator_token
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith("metadataDescriptorUrl ")
    assert metadata_url not in response.text
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


def test_preflight_allows_non_control_percent_encoding(
    api, auth_header, operator_token
) -> None:
    """Ordinary percent encoding remains interoperable for metadata paths."""
    response, store = _preflight(
        "https://sts.example/Federation%20Metadata.xml",
        api,
        auth_header,
        operator_token,
    )

    assert response.status_code == 200
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []
