"""Runtime federation desired-state, convergence, and redaction tests."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.federation import (
    FEDERATION_PROVIDER_NAMESPACE,
    FederationService,
    IdentityProviderRegistration,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app


def _employer_adfs_registration() -> IdentityProviderRegistration:
    """Return an employer SAML provider expressed as runtime data."""
    return IdentityProviderRegistration(
        provider_alias="employer-adfs",
        display_name="Employer ADFS",
        provider_id="saml",
        enabled=True,
        trust_email=True,
        provider_config={
            "entityId": "https://idp.example/realms/cwl",
            "singleSignOnServiceUrl":
                "https://sts.example/adfs/ls/",
            "clientSecret": "federation-secret",
            "validateSignature": "true",
        },
    )


@pytest.fixture
def store() -> InMemoryKvStore:
    """Return a fresh desired-state store."""
    return InMemoryKvStore()


@pytest.fixture
def federation(store, api) -> FederationService:
    """Return a federation service with product-capable Keycloak mock."""
    return FederationService(store, api)


def test_put_persists_secret_but_redacts_status(
    federation, store, api
):
    """Secrets reach storage and Keycloak but never the status view."""
    registration = _employer_adfs_registration()

    status = federation.put_registration(
        "employer-adfs", registration
    )

    raw = store.get(
        FEDERATION_PROVIDER_NAMESPACE,
        "employer-adfs",
    )
    assert raw is not None
    assert json.loads(raw)["provider_config"][
        "clientSecret"
    ] == "federation-secret"
    assert api.identity_providers["employer-adfs"][
        "config"
    ]["clientSecret"] == "federation-secret"
    assert status.registration.provider_config[
        "clientSecret"
    ] == "<redacted>"
    assert status.registration.provider_config[
        "singleSignOnServiceUrl"
    ] == "https://sts.example/adfs/ls/"


def test_put_updates_existing_provider_in_place(
    federation, api
):
    """Updating desired state replaces the applied provider."""
    registration = _employer_adfs_registration()
    federation.put_registration(
        "employer-adfs", registration
    )

    updated = registration.model_copy(
        update={"enabled": False}
    )
    federation.put_registration(
        "employer-adfs", updated
    )

    assert api.identity_providers["employer-adfs"][
        "enabled"
    ] is False
    assert any(
        call.startswith(
            "update_identity_provider:employer-adfs"
        )
        for call in api.calls
    )


def test_apply_all_reconverges_after_realm_rebuild(
    federation, api
):
    """Stored desired state recreates providers after realm loss."""
    federation.put_registration(
        "employer-adfs",
        _employer_adfs_registration(),
    )
    api.identity_providers.clear()

    statuses = federation.apply_all()

    assert [
        status.registration.provider_alias
        for status in statuses
    ] == ["employer-adfs"]
    assert statuses[0].applied_to_keycloak is True
    assert "employer-adfs" in api.identity_providers


def test_delete_removes_keycloak_and_store(
    federation, store, api
):
    """Deletion removes both applied and desired provider state."""
    federation.put_registration(
        "employer-adfs",
        _employer_adfs_registration(),
    )

    federation.delete_registration("employer-adfs")

    assert store.get(
        FEDERATION_PROVIDER_NAMESPACE,
        "employer-adfs",
    ) is None
    assert "employer-adfs" not in api.identity_providers


def test_alias_provider_and_config_bounds_are_enforced(
    federation
):
    """Malformed aliases, providers, and oversized config fail closed."""
    registration = _employer_adfs_registration()

    with pytest.raises(Exception) as mismatch:
        federation.put_registration(
            "other-alias", registration
        )
    assert getattr(
        mismatch.value, "status_code", None
    ) == 400

    bad_alias = registration.model_copy(
        update={"provider_alias": "Bad Alias!"}
    )
    with pytest.raises(Exception) as invalid_alias:
        federation.put_registration(
            "Bad Alias!", bad_alias
        )
    assert getattr(
        invalid_alias.value, "status_code", None
    ) == 400

    bad_provider = registration.model_copy(
        update={"provider_id": "ws-fed"}
    )
    with pytest.raises(Exception) as invalid_provider:
        federation.put_registration(
            "employer-adfs", bad_provider
        )
    assert getattr(
        invalid_provider.value, "status_code", None
    ) == 400

    too_many = registration.model_copy(
        update={
            "provider_config": {
                f"entry{index}": "value"
                for index in range(65)
            }
        }
    )
    with pytest.raises(Exception) as oversized:
        federation.put_registration(
            "employer-adfs", too_many
        )
    assert getattr(
        oversized.value, "status_code", None
    ) == 400


def test_http_surface_never_echoes_provider_secret(
    api, auth_header
):
    """PUT, list, and get responses redact credential values."""
    app = create_app(wire=False)
    app.state.federation_service = FederationService(
        InMemoryKvStore(), api
    )
    app.state.operator_api_token = "test-operator-token"
    body = _employer_adfs_registration().model_dump()

    with TestClient(
        app, headers=auth_header
    ) as client:
        put_response = client.put(
            "/federation/identity-providers/employer-adfs",
            json=body,
        )
        list_response = client.get(
            "/federation/identity-providers"
        )
        get_response = client.get(
            "/federation/identity-providers/employer-adfs"
        )
        delete_response = client.delete(
            "/federation/identity-providers/employer-adfs"
        )
        missing_response = client.get(
            "/federation/identity-providers/employer-adfs"
        )

    assert put_response.status_code == 200
    assert put_response.json()["registration"][
        "provider_config"
    ]["clientSecret"] == "<redacted>"
    assert list_response.json()[0]["registration"][
        "provider_config"
    ]["clientSecret"] == "<redacted>"
    assert get_response.json()["registration"][
        "provider_config"
    ]["clientSecret"] == "<redacted>"
    assert "federation-secret" not in (
        put_response.text
        + list_response.text
        + get_response.text
    )
    assert delete_response.status_code == 204
    assert missing_response.status_code == 404
