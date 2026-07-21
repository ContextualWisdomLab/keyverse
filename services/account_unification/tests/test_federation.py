"""Runtime federation registry: IdPs live in the DB/KV store, not realm code."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.federation import (  # noqa: E402
    FEDERATION_PROVIDER_NAMESPACE,
    FederationService,
    IdentityProviderRegistration,
)
from app.kv_store import InMemoryKvStore  # noqa: E402
from app.main import create_app  # noqa: E402

from .mock_keycloak import MockKeycloakAdminApi  # noqa: E402


def _employer_adfs_registration() -> IdentityProviderRegistration:
    """The employer ADFS expressed as runtime DATA, not committed realm code."""
    return IdentityProviderRegistration(
        provider_alias="employer-adfs",
        display_name="Employer ADFS (hssmartdev)",
        provider_id="saml",
        enabled=True,
        trust_email=True,
        provider_config={
            "entityId": "https://idp.example/realms/cwl",
            "idpEntityId": "http://sts.hssmartdev.com/adfs/services/trust",
            "singleSignOnServiceUrl": "https://sts.hssmartdev.com/adfs/ls/",
            "metadataDescriptorUrl": (
                "https://sts.hssmartdev.com/FederationMetadata/2007-06/"
                "FederationMetadata.xml"
            ),
            "useMetadataDescriptorUrl": "true",
            "wantAssertionsSigned": "true",
            "validateSignature": "true",
            "syncMode": "FORCE",
        },
    )


@pytest.fixture
def store() -> InMemoryKvStore:
    return InMemoryKvStore()


@pytest.fixture
def federation(store: InMemoryKvStore, api: MockKeycloakAdminApi) -> FederationService:
    return FederationService(store, api)


def test_put_persists_to_store_and_converges_keycloak(
    federation: FederationService, store: InMemoryKvStore, api: MockKeycloakAdminApi
) -> None:
    registration = _employer_adfs_registration()

    status = federation.put_registration("employer-adfs", registration)

    assert status.applied_to_keycloak is True
    # Source of truth is the store, not the realm file.
    assert store.get(FEDERATION_PROVIDER_NAMESPACE, "employer-adfs") is not None
    applied = api.identity_providers["employer-adfs"]
    assert applied["providerId"] == "saml"
    assert applied["trustEmail"] is True
    assert applied["config"]["singleSignOnServiceUrl"] == "https://sts.hssmartdev.com/adfs/ls/"


def test_put_updates_existing_provider_in_place(
    federation: FederationService, api: MockKeycloakAdminApi
) -> None:
    registration = _employer_adfs_registration()
    federation.put_registration("employer-adfs", registration)

    updated = registration.model_copy(update={"enabled": False})
    federation.put_registration("employer-adfs", updated)

    assert api.identity_providers["employer-adfs"]["enabled"] is False
    assert any(
        call.startswith("update_identity_provider:employer-adfs")
        for call in api.calls
    )


def test_apply_all_reconverges_after_realm_rebuild(
    federation: FederationService, api: MockKeycloakAdminApi
) -> None:
    federation.put_registration("employer-adfs", _employer_adfs_registration())
    # Simulate a realm rebuild: Keycloak lost the IdP but the store still
    # holds the desired state.
    api.identity_providers.clear()

    statuses = federation.apply_all()

    assert [s.registration.provider_alias for s in statuses] == ["employer-adfs"]
    assert statuses[0].applied_to_keycloak is True
    assert "employer-adfs" in api.identity_providers


def test_delete_removes_from_keycloak_and_store(
    federation: FederationService, store: InMemoryKvStore, api: MockKeycloakAdminApi
) -> None:
    federation.put_registration("employer-adfs", _employer_adfs_registration())

    federation.delete_registration("employer-adfs")

    assert store.get(FEDERATION_PROVIDER_NAMESPACE, "employer-adfs") is None
    assert "employer-adfs" not in api.identity_providers


def test_alias_and_provider_id_validation(federation: FederationService) -> None:
    registration = _employer_adfs_registration()

    with pytest.raises(Exception) as mismatch:
        federation.put_registration("other-alias", registration)
    assert getattr(mismatch.value, "status_code", None) == 400

    bad_alias = registration.model_copy(update={"provider_alias": "Bad Alias!"})
    with pytest.raises(Exception) as invalid_alias:
        federation.put_registration("Bad Alias!", bad_alias)
    assert getattr(invalid_alias.value, "status_code", None) == 400

    bad_provider = registration.model_copy(update={"provider_id": "ws-fed"})
    with pytest.raises(Exception) as invalid_provider:
        federation.put_registration("employer-adfs", bad_provider)
    assert getattr(invalid_provider.value, "status_code", None) == 400


def test_http_surface_round_trip(api: MockKeycloakAdminApi, auth_header) -> None:
    app = create_app(wire=False)
    app.state.federation_service = FederationService(InMemoryKvStore(), api)
    app.state.operator_api_token = "test-operator-token"
    client = TestClient(app, headers=auth_header)
    body = _employer_adfs_registration().model_dump()

    put_response = client.put("/federation/identity-providers/employer-adfs", json=body)
    list_response = client.get("/federation/identity-providers")
    get_response = client.get("/federation/identity-providers/employer-adfs")
    delete_response = client.delete("/federation/identity-providers/employer-adfs")
    missing_response = client.get("/federation/identity-providers/employer-adfs")

    assert put_response.status_code == 200
    assert put_response.json()["applied_to_keycloak"] is True
    assert [
        item["registration"]["provider_alias"] for item in list_response.json()
    ] == ["employer-adfs"]
    assert get_response.status_code == 200
    assert delete_response.status_code == 204
    assert missing_response.status_code == 404
