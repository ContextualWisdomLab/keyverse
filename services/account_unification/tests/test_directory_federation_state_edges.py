"""Failure, corruption, and dependency edge tests for directory reconciliation."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.directory_federation_state import (
    DIRECTORY_FEDERATION_NAMESPACE,
    DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
    DirectoryConvergenceState,
    DirectoryFederationService,
    _observable_component_matches,
    get_directory_federation_service,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app

from .test_directory_federation_desired_state import (
    _active_directory_registration,
)


def _seed_registration(store: InMemoryKvStore, *, key: str = "corp-ldap"):
    """Persist one realistic private registration without contacting Keycloak."""
    registration = _active_directory_registration()
    store.put(
        DIRECTORY_FEDERATION_NAMESPACE,
        key,
        registration.model_dump_json(by_alias=True),
    )
    return registration


def test_delete_preserves_local_state_when_keycloak_observation_fails(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unavailable component inventory cannot destroy recovery intent."""
    store = InMemoryKvStore()
    _seed_registration(store)
    service = DirectoryFederationService(store, api)

    def fail_observation(_name: str) -> list[dict]:
        """Model a temporary Keycloak Admin REST outage."""
        raise RuntimeError("keycloak unavailable")

    monkeypatch.setattr(api, "list_user_storage_components", fail_observation)

    with pytest.raises(HTTPException) as error:
        service.delete_registration("corp-ldap")

    assert error.value.status_code == 503
    assert error.value.detail == "keycloak_unavailable"
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None


def test_delete_rejects_duplicate_components_without_local_mutation(api) -> None:
    """Ambiguous remote identity keeps both desired state and apply receipt."""
    store = InMemoryKvStore()
    registration = _seed_registration(store)
    store.put(
        DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
        registration.name,
        "receipt-value",
    )
    api.create_user_storage_component(registration.model_dump(by_alias=True))
    api.create_user_storage_component(registration.model_dump(by_alias=True))
    service = DirectoryFederationService(store, api)

    with pytest.raises(HTTPException) as error:
        service.delete_registration("corp-ldap")

    assert error.value.status_code == 409
    assert error.value.detail == "duplicate_components"
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None
    assert (
        store.get(DIRECTORY_FEDERATION_RECEIPT_NAMESPACE, "corp-ldap")
        == "receipt-value"
    )


def test_delete_absent_remote_component_clears_local_recovery_records(api) -> None:
    """A confirmed absent remote component permits local desired-state cleanup."""
    store = InMemoryKvStore()
    registration = _seed_registration(store)
    store.put(
        DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
        registration.name,
        "receipt-value",
    )
    service = DirectoryFederationService(store, api)

    service.delete_registration("corp-ldap")

    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is None
    assert store.get(DIRECTORY_FEDERATION_RECEIPT_NAMESPACE, "corp-ldap") is None


def test_stored_key_and_body_name_mismatch_fails_closed(api) -> None:
    """A corrupted KV alias cannot redirect another private registration."""
    store = InMemoryKvStore()
    _seed_registration(store, key="other-ldap")
    service = DirectoryFederationService(store, api)

    with pytest.raises(HTTPException) as error:
        service.get_registration("other-ldap")

    assert error.value.status_code == 500
    assert error.value.detail == "stored_state_invalid"


def test_status_reports_unavailable_without_reflecting_private_state(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read-only inventory remains bounded when Keycloak cannot be observed."""
    store = InMemoryKvStore()
    _seed_registration(store)
    service = DirectoryFederationService(store, api)

    def fail_observation(_name: str) -> list[dict]:
        """Model an unavailable Keycloak component collection."""
        raise RuntimeError("keycloak unavailable")

    monkeypatch.setattr(api, "list_user_storage_components", fail_observation)

    status = service.get_registration("corp-ldap")

    assert status.convergence_state is DirectoryConvergenceState.UNAVAILABLE
    assert status.last_convergence_error_code == "keycloak_unavailable"
    assert "rendered-private-value" not in status.model_dump_json(by_alias=True)


def test_status_reports_ambiguous_for_multiple_exact_components(api) -> None:
    """Inventory reports duplicate remote components without choosing one."""
    store = InMemoryKvStore()
    registration = _seed_registration(store)
    api.create_user_storage_component(registration.model_dump(by_alias=True))
    api.create_user_storage_component(registration.model_dump(by_alias=True))
    service = DirectoryFederationService(store, api)

    status = service.get_registration("corp-ldap")

    assert status.convergence_state is DirectoryConvergenceState.AMBIGUOUS
    assert status.last_convergence_error_code == "duplicate_components"
    assert status.component_id is None


def test_create_failure_returns_retryable_apply_failed_status(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed remote create retains desired state for later reconciliation."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)

    def fail_create(_payload: dict) -> str:
        """Model a failed Keycloak component creation."""
        raise RuntimeError("create failed")

    monkeypatch.setattr(api, "create_user_storage_component", fail_create)

    status = service.put_registration(
        "corp-ldap",
        _active_directory_registration(),
    )

    assert status.convergence_state is DirectoryConvergenceState.APPLY_FAILED
    assert status.last_convergence_error_code == "component_create_failed"
    assert status.last_apply_receipt_matches is False
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None


def test_update_failure_returns_retryable_apply_failed_status(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed drift repair keeps the existing component and desired revision."""
    store = InMemoryKvStore()
    registration = _active_directory_registration()
    component_id = api.create_user_storage_component(
        registration.model_dump(by_alias=True)
    )
    api.user_storage_components[component_id]["config"]["readTimeout"] = [
        "30000"
    ]
    service = DirectoryFederationService(store, api)

    def fail_update(_component_id: str, _payload: dict) -> None:
        """Model a failed Keycloak component replacement."""
        raise RuntimeError("update failed")

    monkeypatch.setattr(api, "update_user_storage_component", fail_update)

    status = service.put_registration("corp-ldap", registration)

    assert status.convergence_state is DirectoryConvergenceState.APPLY_FAILED
    assert status.component_id == component_id
    assert status.last_convergence_error_code == "component_update_failed"
    assert status.last_apply_receipt_matches is False


@pytest.mark.parametrize("directory_name", ["Bad-Name", "-leading", "trailing-"])
def test_public_directory_paths_reject_invalid_names(
    api, directory_name: str
) -> None:
    """Unsafe or noncanonical aliases fail before storage or transport access."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)

    with pytest.raises(HTTPException) as error:
        service.get_registration(directory_name)

    assert error.value.status_code == 400
    assert store.get_all(DIRECTORY_FEDERATION_NAMESPACE) == {}
    assert api.calls == []


def test_status_rejects_exact_component_without_identifier(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed Keycloak component cannot masquerade as observable state."""
    store = InMemoryKvStore()
    registration = _seed_registration(store)
    malformed = registration.model_dump(by_alias=True)

    monkeypatch.setattr(
        api,
        "list_user_storage_components",
        lambda _name: [malformed],
    )
    service = DirectoryFederationService(store, api)

    with pytest.raises(HTTPException) as error:
        service.get_registration("corp-ldap")

    assert error.value.status_code == 500
    assert error.value.detail == "keycloak component omitted its identifier"


def test_observable_comparison_rejects_wrong_identity_and_config_shape() -> None:
    """Only an exact component identity with a mapping config can be in sync."""
    registration = _active_directory_registration()
    wrong_identity = registration.model_dump(by_alias=True)
    wrong_identity["name"] = "other-ldap"
    wrong_config = registration.model_dump(by_alias=True)
    wrong_config["config"] = ["not-a-mapping"]

    assert _observable_component_matches(registration, wrong_identity) is False
    assert _observable_component_matches(registration, wrong_config) is False


def test_dependency_factory_fails_closed_then_caches_constructed_service(api) -> None:
    """Lazy wiring requires both dependencies and reuses the constructed service."""
    app = create_app(wire=False)
    request = Request({"type": "http", "app": app})

    with pytest.raises(HTTPException) as error:
        get_directory_federation_service(request)
    assert error.value.status_code == 503

    store = InMemoryKvStore()
    app.state.config_store = store
    app.state.keycloak_api = api

    created = get_directory_federation_service(request)
    repeated = get_directory_federation_service(request)

    assert isinstance(created, DirectoryFederationService)
    assert repeated is created
    assert app.state.directory_federation_service is created
