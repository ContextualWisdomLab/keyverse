"""Realistic lifecycle tests for LDAP desired-state reconciliation."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.directory_federation_state import (
    DIRECTORY_FEDERATION_NAMESPACE,
    DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
    DirectoryConvergenceState,
    DirectoryFederationService,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app

from .test_directory_federation_desired_state import (
    _active_directory_registration,
)


def _component_store(api) -> dict[str, dict]:
    """Return the deterministic mock component store created by the adapter."""
    store = getattr(api, "user_storage_components", None)
    assert isinstance(store, dict)
    return store


def test_repeated_put_is_noop_when_observable_state_and_receipt_match(api) -> None:
    """An identical private registration does not churn the live component."""
    service = DirectoryFederationService(InMemoryKvStore(), api)
    registration = _active_directory_registration()
    first = service.put_registration("corp-ldap", registration)
    api.calls.clear()

    second = service.put_registration("corp-ldap", registration)

    assert second.convergence_state is DirectoryConvergenceState.IN_SYNC
    assert second.component_id == first.component_id
    assert api.calls == ["list_user_storage_components:corp-ldap"]


def test_private_secret_rotation_forces_update_without_disclosing_secret(api) -> None:
    """A new private revision is reapplied even when Keycloak masks secrets."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)
    initial = _active_directory_registration()
    service.put_registration("corp-ldap", initial)
    rotated = initial.model_copy(deep=True)
    rotated.config["bindCredential"] = ["rotated-private-value"]
    api.calls.clear()

    status = service.put_registration("corp-ldap", rotated)

    assert status.convergence_state is DirectoryConvergenceState.IN_SYNC
    assert status.last_apply_receipt_matches is True
    assert any(
        call.startswith("update_user_storage_component:") for call in api.calls
    )
    assert "rotated-private-value" in (
        store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") or ""
    )
    assert "rotated-private-value" not in status.model_dump_json(by_alias=True)


def test_observable_drift_is_repaired(api) -> None:
    """A changed Keycloak timeout is restored from validated desired state."""
    service = DirectoryFederationService(InMemoryKvStore(), api)
    registration = _active_directory_registration()
    created = service.put_registration("corp-ldap", registration)
    component = _component_store(api)[created.component_id]
    component["config"]["readTimeout"] = ["30000"]
    api.calls.clear()

    statuses = service.reconcile_all()

    assert statuses[0].convergence_state is DirectoryConvergenceState.IN_SYNC
    assert component["config"]["readTimeout"] == ["30000"]
    repaired = _component_store(api)[created.component_id]
    assert repaired["config"]["readTimeout"] == ["10000"]
    assert any(
        call.startswith("update_user_storage_component:") for call in api.calls
    )


def test_keycloak_outage_preserves_private_desired_state(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A temporary Admin REST outage never rolls back stored operator intent."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)

    def fail_observation(_name: str):
        """Simulate a temporarily unavailable Keycloak component endpoint."""
        raise RuntimeError("keycloak unavailable")

    monkeypatch.setattr(api, "list_user_storage_components", fail_observation)

    status = service.put_registration(
        "corp-ldap",
        _active_directory_registration(),
    )

    assert status.convergence_state is DirectoryConvergenceState.UNAVAILABLE
    assert status.last_convergence_error_code == "keycloak_unavailable"
    stored = store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap")
    assert stored is not None and "rendered-private-value" in stored
    assert store.get(DIRECTORY_FEDERATION_RECEIPT_NAMESPACE, "corp-ldap") is None


def test_reconcile_recovers_after_realm_rebuild(api) -> None:
    """Stored private intent recreates a component lost with a rebuilt realm."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)
    service.put_registration("corp-ldap", _active_directory_registration())
    _component_store(api).clear()
    api.calls.clear()

    statuses = service.reconcile_all()

    assert statuses[0].convergence_state is DirectoryConvergenceState.IN_SYNC
    assert len(_component_store(api)) == 1
    assert any(
        call.startswith("create_user_storage_component:") for call in api.calls
    )


def test_duplicate_components_fail_closed_without_mutation(api) -> None:
    """Multiple exact live components produce an ambiguous non-mutating status."""
    service = DirectoryFederationService(InMemoryKvStore(), api)
    registration = _active_directory_registration()
    first_id = api.create_user_storage_component(
        registration.model_dump(by_alias=True)
    )
    second_id = api.create_user_storage_component(
        registration.model_dump(by_alias=True)
    )
    api.calls.clear()

    status = service.put_registration("corp-ldap", registration)

    assert first_id != second_id
    assert status.convergence_state is DirectoryConvergenceState.AMBIGUOUS
    assert status.last_convergence_error_code == "duplicate_components"
    assert len(_component_store(api)) == 2
    assert not any("update_user_storage_component" in call for call in api.calls)
    assert not any("delete_user_storage_component" in call for call in api.calls)


def test_remote_delete_failure_preserves_desired_state(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delete removes local intent only after Keycloak confirms remote removal."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)
    service.put_registration("corp-ldap", _active_directory_registration())

    def fail_delete(_component_id: str) -> None:
        """Simulate a Keycloak failure after the exact component is selected."""
        raise RuntimeError("delete failed")

    monkeypatch.setattr(api, "delete_user_storage_component", fail_delete)

    with pytest.raises(HTTPException) as error:
        service.delete_registration("corp-ldap")

    assert error.value.status_code == 502
    assert error.value.detail == "component_delete_failed"
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None
    assert len(_component_store(api)) == 1


def test_successful_delete_removes_component_desired_state_and_receipt(api) -> None:
    """A successful remote-first delete clears every directory lifecycle record."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)
    service.put_registration("corp-ldap", _active_directory_registration())

    service.delete_registration("corp-ldap")

    assert _component_store(api) == {}
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is None
    assert store.get(DIRECTORY_FEDERATION_RECEIPT_NAMESPACE, "corp-ldap") is None


def test_list_is_sorted_and_every_status_is_secret_free(api) -> None:
    """Operator inventory is deterministic and never exposes private LDAP values."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)
    second = _active_directory_registration().model_copy(deep=True)
    second.name = "backup-ldap"
    service.put_registration("corp-ldap", _active_directory_registration())
    service.put_registration("backup-ldap", second)

    statuses = service.list_registrations()

    assert [item.registration.name for item in statuses] == [
        "backup-ldap",
        "corp-ldap",
    ]
    serialized = "".join(item.model_dump_json(by_alias=True) for item in statuses)
    assert "rendered-private-value" not in serialized
    assert "svc-keycloak" not in serialized


def test_corrupt_stored_state_fails_closed_without_reflection(api) -> None:
    """Malformed private storage never reaches an operator error response."""
    store = InMemoryKvStore()
    store.put(
        DIRECTORY_FEDERATION_NAMESPACE,
        "corp-ldap",
        '{"bindCredential":"stored-private-value"}',
    )
    service = DirectoryFederationService(store, api)

    with pytest.raises(HTTPException) as error:
        service.get_registration("corp-ldap")

    assert error.value.status_code == 500
    assert error.value.detail == "stored_state_invalid"
    assert "stored-private-value" not in str(error.value.detail)


def test_blocked_network_call_does_not_hold_desired_state_lock(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow Keycloak observation cannot block another stored-state snapshot."""
    store = InMemoryKvStore()
    registration = _active_directory_registration()
    store.put(
        DIRECTORY_FEDERATION_NAMESPACE,
        registration.name,
        registration.model_dump_json(by_alias=True),
    )
    service = DirectoryFederationService(store, api)
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    call_lock = threading.Lock()
    call_count = 0

    def blocking_list(_name: str) -> list[dict]:
        """Block the first remote call and expose entry into the second."""
        nonlocal call_count
        with call_lock:
            call_count += 1
            current = call_count
        if current == 1:
            first_started.set()
            assert release_first.wait(timeout=5)
        else:
            second_started.set()
        return []

    monkeypatch.setattr(api, "list_user_storage_components", blocking_list)

    with ThreadPoolExecutor(max_workers=2) as executor:
        list_future = executor.submit(service.list_registrations)
        assert first_started.wait(timeout=2)
        get_future = executor.submit(service.get_registration, "corp-ldap")
        second_reached_network = second_started.wait(timeout=0.5)
        release_first.set()
        list_future.result(timeout=5)
        get_future.result(timeout=5)

    assert second_reached_network


def test_http_crud_and_reconcile_surface_is_authenticated(
    api,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """The mounted API exposes one authenticated, redacted lifecycle contract."""
    store = InMemoryKvStore()
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    app.state.directory_federation_service = DirectoryFederationService(store, api)
    body = _active_directory_registration().model_dump(by_alias=True)

    with TestClient(app, headers=auth_header) as client:
        put_response = client.put(
            "/federation/user-directories/corp-ldap",
            json=body,
        )
        list_response = client.get("/federation/user-directories")
        get_response = client.get("/federation/user-directories/corp-ldap")
        reconcile_response = client.post(
            "/federation/user-directories:reconcile"
        )
        delete_response = client.delete(
            "/federation/user-directories/corp-ldap"
        )
        missing_response = client.get(
            "/federation/user-directories/corp-ldap"
        )

    assert put_response.status_code == 200
    assert list_response.status_code == 200
    assert get_response.status_code == 200
    assert reconcile_response.status_code == 200
    for response in (
        put_response,
        list_response,
        get_response,
        reconcile_response,
    ):
        assert "rendered-private-value" not in response.text
        assert "svc-keycloak" not in response.text
    assert delete_response.status_code == 204
    assert missing_response.status_code == 404


def test_path_body_mismatch_is_rejected_before_storage(api) -> None:
    """A path alias cannot redirect a private body into another desired-state key."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)

    with pytest.raises(HTTPException) as error:
        service.put_registration(
            "other-ldap",
            _active_directory_registration(),
        )

    assert error.value.status_code == 400
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "other-ldap") is None
