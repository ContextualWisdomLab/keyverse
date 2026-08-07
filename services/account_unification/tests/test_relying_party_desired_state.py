"""OIDC relying-party desired-state lifecycle tests."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.kv_store import InMemoryKvStore
from app.main import create_app
from app.relying_party_state import (
    RELYING_PARTY_NAMESPACE,
    RELYING_PARTY_RECEIPT_NAMESPACE,
    RelyingPartyConvergenceState,
    RelyingPartyService,
    parse_relying_party_registration,
)

from .test_relying_party_preflight import _confidential_web_client


def _registration(client_id: str = "naruon-web"):
    """Return one validated production-shaped relying-party registration."""
    payload = _confidential_web_client()
    payload["clientId"] = client_id
    payload["name"] = client_id
    return parse_relying_party_registration(payload)


def _client_store(api) -> dict[str, dict]:
    """Return the deterministic mock client store."""
    store = getattr(api, "relying_party_clients", None)
    assert isinstance(store, dict)
    return store


def test_put_persists_creates_and_returns_in_sync_status(api) -> None:
    """A validated secret-free relying party becomes durable and observable."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)

    status = service.put_registration("naruon-web", _registration())

    stored = store.get(RELYING_PARTY_NAMESPACE, "naruon-web")
    assert stored is not None
    assert status.desired_state_stored is True
    assert status.convergence_state is RelyingPartyConvergenceState.IN_SYNC
    assert status.last_apply_receipt_matches is True
    assert status.client_uuid is not None
    assert len(_client_store(api)) == 1
    serialized = status.model_dump_json(by_alias=True)
    assert "clientSecret" not in serialized
    assert "registrationAccessToken" not in serialized


def test_repeated_put_is_noop_when_state_and_receipt_match(api) -> None:
    """An identical client revision does not churn the live Keycloak client."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    registration = _registration()
    first = service.put_registration("naruon-web", registration)
    api.calls.clear()

    second = service.put_registration("naruon-web", registration)

    assert second.convergence_state is RelyingPartyConvergenceState.IN_SYNC
    assert second.client_uuid == first.client_uuid
    assert api.calls == ["list_relying_party_clients:naruon-web"]


def test_observable_drift_is_repaired(api) -> None:
    """A changed live token lifetime is restored from desired state."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    created = service.put_registration("naruon-web", _registration())
    _client_store(api)[created.client_uuid]["attributes"][
        "access.token.lifespan"
    ] = "900"
    api.calls.clear()

    statuses = service.reconcile_all()

    assert statuses[0].convergence_state is RelyingPartyConvergenceState.IN_SYNC
    repaired = _client_store(api)[created.client_uuid]
    assert repaired["attributes"]["access.token.lifespan"] == "300"
    assert any(call.startswith("update_relying_party_client:") for call in api.calls)


def test_keycloak_outage_preserves_desired_state(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A temporary Admin REST outage never rolls back stored operator intent."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)

    def fail_observation(_client_id: str):
        """Simulate a temporarily unavailable Keycloak client endpoint."""
        raise RuntimeError("keycloak unavailable")

    monkeypatch.setattr(api, "list_relying_party_clients", fail_observation)

    status = service.put_registration("naruon-web", _registration())

    assert status.convergence_state is RelyingPartyConvergenceState.UNAVAILABLE
    assert status.last_convergence_error_code == "keycloak_unavailable"
    assert store.get(RELYING_PARTY_NAMESPACE, "naruon-web") is not None
    assert store.get(RELYING_PARTY_RECEIPT_NAMESPACE, "naruon-web") is None


def test_status_reports_absent_drifted_ambiguous_and_unavailable(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every non-mutating observable state has one bounded classification."""
    store = InMemoryKvStore()
    registration = _registration()
    store.put(
        RELYING_PARTY_NAMESPACE,
        registration.client_id,
        registration.model_dump_json(by_alias=True),
    )
    service = RelyingPartyService(store, api)

    absent = service.get_registration("naruon-web")
    assert absent.convergence_state is RelyingPartyConvergenceState.ABSENT

    first_uuid = api.create_relying_party_client(
        registration.model_dump(by_alias=True)
    )
    drifted = service.get_registration("naruon-web")
    assert drifted.convergence_state is RelyingPartyConvergenceState.DRIFTED
    assert drifted.client_uuid == first_uuid

    api.create_relying_party_client(registration.model_dump(by_alias=True))
    ambiguous = service.get_registration("naruon-web")
    assert ambiguous.convergence_state is RelyingPartyConvergenceState.AMBIGUOUS
    assert ambiguous.last_convergence_error_code == "duplicate_clients"

    def fail_observation(_client_id: str):
        """Simulate an unavailable status observation."""
        raise RuntimeError("offline")

    monkeypatch.setattr(api, "list_relying_party_clients", fail_observation)
    unavailable = service.get_registration("naruon-web")
    assert unavailable.convergence_state is RelyingPartyConvergenceState.UNAVAILABLE


def test_duplicate_clients_fail_closed_without_mutation(api) -> None:
    """Multiple exact live clients produce an ambiguous non-mutating status."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    registration = _registration()
    api.create_relying_party_client(registration.model_dump(by_alias=True))
    api.create_relying_party_client(registration.model_dump(by_alias=True))
    api.calls.clear()

    status = service.put_registration("naruon-web", registration)

    assert status.convergence_state is RelyingPartyConvergenceState.AMBIGUOUS
    assert status.last_convergence_error_code == "duplicate_clients"
    assert len(_client_store(api)) == 2
    assert not any("update_relying_party_client" in call for call in api.calls)
    assert not any("delete_relying_party_client" in call for call in api.calls)


def test_create_and_update_failures_return_recoverable_status(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Remote mutation failures retain desired state and never write a receipt."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)

    def fail_create(_payload: dict):
        """Simulate a Keycloak create failure."""
        raise RuntimeError("create failed")

    monkeypatch.setattr(api, "create_relying_party_client", fail_create)
    create_status = service.put_registration("naruon-web", _registration())
    assert create_status.convergence_state is RelyingPartyConvergenceState.APPLY_FAILED
    assert create_status.last_convergence_error_code == "client_create_failed"
    assert store.get(RELYING_PARTY_RECEIPT_NAMESPACE, "naruon-web") is None

    monkeypatch.undo()
    initial = service.put_registration("naruon-web", _registration())
    changed = _registration().model_copy(deep=True)
    changed.attributes["access.token.lifespan"] = "600"

    def fail_update(_client_uuid: str, _payload: dict) -> None:
        """Simulate a Keycloak update failure."""
        raise RuntimeError("update failed")

    monkeypatch.setattr(api, "update_relying_party_client", fail_update)
    update_status = service.put_registration("naruon-web", changed)
    assert update_status.convergence_state is RelyingPartyConvergenceState.APPLY_FAILED
    assert update_status.client_uuid == initial.client_uuid
    assert update_status.last_convergence_error_code == "client_update_failed"


@pytest.mark.parametrize(
    ("scenario", "expected_state", "expected_code"),
    [
        (
            "observation_error",
            RelyingPartyConvergenceState.APPLY_FAILED,
            "post_apply_observation_failed",
        ),
        (
            "missing",
            RelyingPartyConvergenceState.APPLY_FAILED,
            "client_missing_after_apply",
        ),
        (
            "duplicate",
            RelyingPartyConvergenceState.AMBIGUOUS,
            "duplicate_clients_after_apply",
        ),
        (
            "identity_changed",
            RelyingPartyConvergenceState.APPLY_FAILED,
            "client_identity_changed_after_apply",
        ),
        (
            "state_mismatch",
            RelyingPartyConvergenceState.APPLY_FAILED,
            "client_state_mismatch_after_apply",
        ),
    ],
)
def test_create_requires_successful_exact_post_apply_observation(
    api,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    expected_state: RelyingPartyConvergenceState,
    expected_code: str,
) -> None:
    """A create receipt is withheld until exact observable state is verified."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    registration = _registration()
    original_list = api.list_relying_party_clients
    call_count = 0

    def controlled_list(client_id: str) -> list[dict]:
        """Return an empty pre-create view and one adversarial post-create view."""
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return []
        if scenario == "observation_error":
            raise RuntimeError("observation failed")
        clients = original_list(client_id)
        if scenario == "missing":
            return []
        if scenario == "duplicate":
            duplicate = dict(clients[0])
            duplicate["id"] = "duplicate-client"
            return [clients[0], duplicate]
        if scenario == "identity_changed":
            clients[0]["id"] = "different-client"
            return clients
        clients[0]["enabled"] = False
        return clients

    monkeypatch.setattr(api, "list_relying_party_clients", controlled_list)

    status = service.put_registration("naruon-web", registration)

    assert status.convergence_state is expected_state
    assert status.last_convergence_error_code == expected_code
    assert store.get(RELYING_PARTY_RECEIPT_NAMESPACE, "naruon-web") is None


def test_reconcile_recovers_after_realm_rebuild(api) -> None:
    """Stored intent recreates a relying party lost with a rebuilt realm."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    service.put_registration("naruon-web", _registration())
    _client_store(api).clear()
    api.calls.clear()

    statuses = service.reconcile_all()

    assert statuses[0].convergence_state is RelyingPartyConvergenceState.IN_SYNC
    assert len(_client_store(api)) == 1
    assert any(call.startswith("create_relying_party_client:") for call in api.calls)


def test_remote_delete_failure_preserves_recovery_intent(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delete removes local intent only after Keycloak confirms removal."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    service.put_registration("naruon-web", _registration())

    def fail_delete(_client_uuid: str) -> None:
        """Simulate a remote delete failure."""
        raise RuntimeError("delete failed")

    monkeypatch.setattr(api, "delete_relying_party_client", fail_delete)

    with pytest.raises(HTTPException) as error:
        service.delete_registration("naruon-web")

    assert error.value.status_code == 502
    assert error.value.detail == "client_delete_failed"
    assert store.get(RELYING_PARTY_NAMESPACE, "naruon-web") is not None
    assert len(_client_store(api)) == 1


def test_delete_observation_and_duplicate_fail_closed(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deletion retains intent when selection is unavailable or ambiguous."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    registration = _registration()
    store.put(
        RELYING_PARTY_NAMESPACE,
        registration.client_id,
        registration.model_dump_json(by_alias=True),
    )

    def fail_observation(_client_id: str):
        """Simulate an unavailable client listing."""
        raise RuntimeError("offline")

    monkeypatch.setattr(api, "list_relying_party_clients", fail_observation)
    with pytest.raises(HTTPException) as unavailable:
        service.delete_registration("naruon-web")
    assert unavailable.value.status_code == 503

    monkeypatch.undo()
    api.create_relying_party_client(registration.model_dump(by_alias=True))
    api.create_relying_party_client(registration.model_dump(by_alias=True))
    with pytest.raises(HTTPException) as duplicate:
        service.delete_registration("naruon-web")
    assert duplicate.value.status_code == 409
    assert store.get(RELYING_PARTY_NAMESPACE, "naruon-web") is not None


def test_successful_and_already_absent_delete_clear_all_records(api) -> None:
    """Remote-first deletion clears live state, desired state, and receipt."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    service.put_registration("naruon-web", _registration())

    service.delete_registration("naruon-web")

    assert _client_store(api) == {}
    assert store.get(RELYING_PARTY_NAMESPACE, "naruon-web") is None
    assert store.get(RELYING_PARTY_RECEIPT_NAMESPACE, "naruon-web") is None

    registration = _registration("portal-web")
    store.put(
        RELYING_PARTY_NAMESPACE,
        registration.client_id,
        registration.model_dump_json(by_alias=True),
    )
    service.delete_registration("portal-web")
    assert store.get(RELYING_PARTY_NAMESPACE, "portal-web") is None


def test_list_is_sorted_and_secret_fields_are_impossible(api) -> None:
    """Operator inventory is deterministic and contains no credential metadata."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    service.put_registration("naruon-web", _registration())
    service.put_registration("analytics-web", _registration("analytics-web"))

    statuses = service.list_registrations()

    assert [item.registration.client_id for item in statuses] == [
        "analytics-web",
        "naruon-web",
    ]
    serialized = "".join(item.model_dump_json(by_alias=True) for item in statuses)
    assert "clientSecret" not in serialized
    assert "registrationAccessToken" not in serialized


def test_corrupt_or_miskeyed_stored_state_fails_without_reflection(api) -> None:
    """Malformed storage produces one bounded error without submitted values."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    store.put(
        RELYING_PARTY_NAMESPACE,
        "naruon-web",
        '{"clientSecret":"stored-private-value"}',
    )

    with pytest.raises(HTTPException) as corrupt:
        service.get_registration("naruon-web")
    assert corrupt.value.status_code == 500
    assert corrupt.value.detail == "stored_state_invalid"
    assert "stored-private-value" not in str(corrupt.value.detail)

    store.put(
        RELYING_PARTY_NAMESPACE,
        "naruon-web",
        _registration("other-web").model_dump_json(by_alias=True),
    )
    with pytest.raises(HTTPException) as miskeyed:
        service.get_registration("naruon-web")
    assert miskeyed.value.detail == "stored_state_invalid"


def test_missing_or_malformed_live_uuid_fails_closed(api) -> None:
    """A live representation without a safe identity is never reported in sync."""
    store = InMemoryKvStore()
    registration = _registration()
    store.put(
        RELYING_PARTY_NAMESPACE,
        registration.client_id,
        registration.model_dump_json(by_alias=True),
    )
    api.relying_party_clients["broken"] = registration.model_dump(by_alias=True)
    service = RelyingPartyService(store, api)

    with pytest.raises(HTTPException) as error:
        service.get_registration("naruon-web")

    assert error.value.status_code == 500
    assert error.value.detail == "keycloak client omitted its identifier"


def test_path_body_mismatch_and_invalid_path_are_rejected_before_storage(api) -> None:
    """A path cannot redirect desired state or contain unsafe client syntax."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)

    with pytest.raises(HTTPException) as mismatch:
        service.put_registration("other-web", _registration())
    assert mismatch.value.status_code == 400
    assert store.get(RELYING_PARTY_NAMESPACE, "other-web") is None

    with pytest.raises(HTTPException) as invalid:
        service.get_registration("Bad Client!")
    assert invalid.value.status_code == 400


def test_blocked_network_call_does_not_hold_desired_state_lock(
    api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow Keycloak call cannot block another stored-state snapshot."""
    store = InMemoryKvStore()
    registration = _registration()
    store.put(
        RELYING_PARTY_NAMESPACE,
        registration.client_id,
        registration.model_dump_json(by_alias=True),
    )
    service = RelyingPartyService(store, api)
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    call_guard = threading.Lock()
    call_count = 0

    def blocking_list(_client_id: str) -> list[dict]:
        """Block the first remote call and expose entry into the second."""
        nonlocal call_count
        with call_guard:
            call_count += 1
            current = call_count
        if current == 1:
            first_started.set()
            assert release_first.wait(timeout=5)
        else:
            second_started.set()
        return []

    monkeypatch.setattr(api, "list_relying_party_clients", blocking_list)

    with ThreadPoolExecutor(max_workers=2) as executor:
        list_future = executor.submit(service.list_registrations)
        assert first_started.wait(timeout=2)
        get_future = executor.submit(service.get_registration, "naruon-web")
        second_reached_network = second_started.wait(timeout=0.5)
        release_first.set()
        list_future.result(timeout=5)
        get_future.result(timeout=5)

    assert second_reached_network


def test_bulk_reconcile_skips_concurrently_deleted_record(api, monkeypatch) -> None:
    """A key snapshot cannot resurrect desired state deleted before its turn."""
    store = InMemoryKvStore()
    first = _registration("alpha-web")
    second = _registration("beta-web")
    for registration in (first, second):
        store.put(
            RELYING_PARTY_NAMESPACE,
            registration.client_id,
            registration.model_dump_json(by_alias=True),
        )
    service = RelyingPartyService(store, api)
    original_get = service._get_stored_registration

    def deleting_get(client_id: str):
        """Delete the second key while the first snapshot item is processed."""
        if client_id == "alpha-web":
            store.delete(RELYING_PARTY_NAMESPACE, "beta-web")
        return original_get(client_id)

    monkeypatch.setattr(service, "_get_stored_registration", deleting_get)

    statuses = service.reconcile_all()

    assert [status.registration.client_id for status in statuses] == ["alpha-web"]
    assert not any(
        client.get("clientId") == "beta-web"
        for client in _client_store(api).values()
    )


def test_bulk_reconcile_propagates_non_missing_storage_failure(api) -> None:
    """Corrupt current state aborts reconciliation instead of being skipped."""
    store = InMemoryKvStore()
    store.put(RELYING_PARTY_NAMESPACE, "naruon-web", "not-json")
    service = RelyingPartyService(store, api)

    with pytest.raises(HTTPException) as error:
        service.reconcile_all()

    assert error.value.status_code == 500


def test_http_crud_reconcile_and_lazy_wiring_are_authenticated(
    api,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """The mounted API exposes one authenticated side-effect-bounded lifecycle."""
    store = InMemoryKvStore()
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    app.state.config_store = store
    app.state.keycloak_api = api
    body = _confidential_web_client()

    with TestClient(app, headers=auth_header) as client:
        put_response = client.put("/clients/relying-parties/naruon-web", json=body)
        list_response = client.get("/clients/relying-parties")
        get_response = client.get("/clients/relying-parties/naruon-web")
        reconcile_response = client.post("/clients/relying-parties:reconcile")
        delete_response = client.delete("/clients/relying-parties/naruon-web")
        missing_response = client.get("/clients/relying-parties/naruon-web")

    assert put_response.status_code == 200
    assert list_response.status_code == 200
    assert get_response.status_code == 200
    assert reconcile_response.status_code == 200
    assert delete_response.status_code == 204
    assert missing_response.status_code == 404
    assert hasattr(app.state, "relying_party_service")


def test_http_surface_fails_closed_when_service_is_unwired(operator_token) -> None:
    """The desired-state endpoint is unavailable without storage and API ports."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    with TestClient(
        app,
        headers={"Authorization": f"Bearer {operator_token}"},
    ) as client:
        response = client.get("/clients/relying-parties")
    assert response.status_code == 503


def test_malformed_http_body_never_reflects_private_values(
    api,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Manual parsing returns bounded errors without reflecting hostile fields."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    app.state.relying_party_service = RelyingPartyService(InMemoryKvStore(), api)
    body = _confidential_web_client()
    body["clientSecret"] = "must-never-appear"

    with TestClient(app, headers=auth_header) as client:
        response = client.put("/clients/relying-parties/naruon-web", json=body)

    assert response.status_code == 422
    assert "must-never-appear" not in response.text
