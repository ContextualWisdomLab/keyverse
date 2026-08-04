"""Runtime federation desired-state, convergence, and redaction tests."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

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
            "idpEntityId": "http://sts.example/adfs/services/trust",
            "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",
            "metadataDescriptorUrl": (
                "https://sts.example/FederationMetadata/2007-06/"
                "FederationMetadata.xml"
            ),
            "useMetadataDescriptorUrl": "true",
            "clientSecret": "federation-secret",
            "unclassifiedValue": "must-not-leak",
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


def test_put_persists_secret_but_redacts_status(federation, store, api) -> None:
    """Secrets reach storage and Keycloak but never the status view."""
    registration = _employer_adfs_registration()

    status = federation.put_registration("employer-adfs", registration)

    raw = store.get(FEDERATION_PROVIDER_NAMESPACE, "employer-adfs")
    assert raw is not None
    stored_config = json.loads(raw)["provider_config"]
    assert stored_config["clientSecret"] == "federation-secret"
    assert stored_config["unclassifiedValue"] == "must-not-leak"
    applied_config = api.identity_providers["employer-adfs"]["config"]
    assert applied_config["clientSecret"] == "federation-secret"
    assert applied_config["unclassifiedValue"] == "must-not-leak"
    assert status.registration.provider_config["clientSecret"] == "<redacted>"
    assert status.registration.provider_config["unclassifiedValue"] == "<redacted>"
    assert status.registration.provider_config["singleSignOnServiceUrl"] == (
        "https://sts.example/adfs/ls/"
    )


def test_put_updates_existing_provider_in_place(federation, api) -> None:
    """Updating desired state replaces the applied provider."""
    registration = _employer_adfs_registration()
    federation.put_registration("employer-adfs", registration)

    updated = registration.model_copy(update={"enabled": False})
    federation.put_registration("employer-adfs", updated)

    assert api.identity_providers["employer-adfs"]["enabled"] is False
    assert any(
        call.startswith("update_identity_provider:employer-adfs")
        for call in api.calls
    )


def test_put_retains_desired_state_when_keycloak_is_unavailable(
    federation, store, api, monkeypatch
) -> None:
    """A failed convergence is explicit and remains retryable from stored state."""

    def fail_create(*args, **kwargs) -> None:
        """Simulate a temporarily unavailable Keycloak Admin REST API."""
        raise RuntimeError("keycloak unavailable")

    monkeypatch.setattr(api, "create_identity_provider", fail_create)

    status = federation.put_registration(
        "employer-adfs", _employer_adfs_registration()
    )

    assert status.applied_to_keycloak is False
    assert store.get(FEDERATION_PROVIDER_NAMESPACE, "employer-adfs") is not None


def test_stored_status_remains_readable_during_keycloak_outage(
    store, api, monkeypatch
) -> None:
    """Desired state remains observable and redacted when status I/O fails."""
    registration = _employer_adfs_registration()
    store.put(
        FEDERATION_PROVIDER_NAMESPACE,
        registration.provider_alias,
        registration.model_dump_json(),
    )
    federation = FederationService(store, api)

    def fail_status(*args, **kwargs):
        """Simulate Keycloak being unavailable during a status read."""
        raise RuntimeError("keycloak unavailable")

    monkeypatch.setattr(api, "get_identity_provider", fail_status)

    statuses = federation.list_registrations()

    assert len(statuses) == 1
    assert statuses[0].applied_to_keycloak is False
    assert statuses[0].registration.provider_config["clientSecret"] == "<redacted>"
    assert (
        statuses[0].registration.provider_config["unclassifiedValue"]
        == "<redacted>"
    )


def test_status_network_call_does_not_hold_desired_state_lock(
    store, api, monkeypatch
) -> None:
    """A slow Keycloak status call does not block another stored-state read."""
    registration = _employer_adfs_registration()
    store.put(
        FEDERATION_PROVIDER_NAMESPACE,
        registration.provider_alias,
        registration.model_dump_json(),
    )
    federation = FederationService(store, api)
    first_call_started = threading.Event()
    release_first_call = threading.Event()
    second_call_started = threading.Event()
    call_guard = threading.Lock()
    call_count = 0

    def blocking_status(provider_alias: str):
        """Block the first network call and signal entry into the second."""
        nonlocal call_count
        with call_guard:
            call_count += 1
            current_call = call_count
        if current_call == 1:
            first_call_started.set()
            assert release_first_call.wait(timeout=5)
        else:
            second_call_started.set()
        return None

    monkeypatch.setattr(api, "get_identity_provider", blocking_status)

    with ThreadPoolExecutor(max_workers=2) as executor:
        list_future = executor.submit(federation.list_registrations)
        assert first_call_started.wait(timeout=2)
        get_future = executor.submit(
            federation.get_registration, "employer-adfs"
        )
        second_reached_network = second_call_started.wait(timeout=0.5)
        release_first_call.set()
        list_future.result(timeout=5)
        get_future.result(timeout=5)

    assert second_reached_network


def test_apply_all_reconverges_after_realm_rebuild(federation, api) -> None:
    """Stored desired state recreates providers after realm loss."""
    federation.put_registration(
        "employer-adfs", _employer_adfs_registration()
    )
    api.identity_providers.clear()

    statuses = federation.apply_all()

    assert [
        status.registration.provider_alias for status in statuses
    ] == ["employer-adfs"]
    assert statuses[0].applied_to_keycloak is True
    assert "employer-adfs" in api.identity_providers


def test_delete_removes_keycloak_and_store(federation, store, api) -> None:
    """Deletion removes both applied and desired provider state."""
    federation.put_registration(
        "employer-adfs", _employer_adfs_registration()
    )

    federation.delete_registration("employer-adfs")

    assert store.get(FEDERATION_PROVIDER_NAMESPACE, "employer-adfs") is None
    assert "employer-adfs" not in api.identity_providers


def test_alias_provider_and_config_bounds_are_enforced(federation) -> None:
    """Malformed aliases, providers, and oversized config fail closed."""
    registration = _employer_adfs_registration()

    with pytest.raises(HTTPException) as mismatch:
        federation.put_registration("other-alias", registration)
    assert mismatch.value.status_code == 400

    bad_alias = registration.model_copy(
        update={"provider_alias": "Bad Alias!"}
    )
    with pytest.raises(HTTPException) as invalid_alias:
        federation.put_registration("Bad Alias!", bad_alias)
    assert invalid_alias.value.status_code == 400

    unicode_alias = registration.model_copy(
        update={"provider_alias": "employer-аdfs"}
    )
    with pytest.raises(HTTPException) as non_ascii_alias:
        federation.put_registration("employer-аdfs", unicode_alias)
    assert non_ascii_alias.value.status_code == 400

    bad_provider = registration.model_copy(update={"provider_id": "ws-fed"})
    with pytest.raises(HTTPException) as invalid_provider:
        federation.put_registration("employer-adfs", bad_provider)
    assert invalid_provider.value.status_code == 400

    too_many = registration.model_copy(
        update={
            "provider_config": {
                f"entry{index}": "value" for index in range(65)
            }
        }
    )
    with pytest.raises(HTTPException) as oversized:
        federation.put_registration("employer-adfs", too_many)
    assert oversized.value.status_code == 400


def test_http_surface_never_echoes_provider_secret(
    api, auth_header, operator_token
) -> None:
    """PUT, list, and get responses redact credential and unknown values."""
    app = create_app(wire=False)
    app.state.federation_service = FederationService(InMemoryKvStore(), api)
    app.state.operator_api_token = operator_token
    body = _employer_adfs_registration().model_dump()

    with TestClient(app, headers=auth_header) as client:
        put_response = client.put(
            "/federation/identity-providers/employer-adfs",
            json=body,
        )
        list_response = client.get("/federation/identity-providers")
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
    put_config = put_response.json()["registration"]["provider_config"]
    list_config = list_response.json()[0]["registration"]["provider_config"]
    get_config = get_response.json()["registration"]["provider_config"]
    for response_config in (put_config, list_config, get_config):
        assert response_config["clientSecret"] == "<redacted>"
        assert response_config["unclassifiedValue"] == "<redacted>"
    combined_text = put_response.text + list_response.text + get_response.text
    assert "federation-secret" not in combined_text
    assert "must-not-leak" not in combined_text
    assert delete_response.status_code == 204
    assert missing_response.status_code == 404
