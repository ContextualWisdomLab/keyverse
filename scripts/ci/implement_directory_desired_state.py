#!/usr/bin/env python3
"""Write and verify the bounded LDAP desired-state implementation in two phases."""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "services/account_unification/app/directory_federation.py"
PRODUCT_CLIENT = ROOT / "services/account_unification/app/product_keycloak_client.py"
MAIN = ROOT / "services/account_unification/app/main.py"
MOCK = ROOT / "services/account_unification/tests/mock_product_keycloak.py"
TESTS = ROOT / "services/account_unification/tests/test_directory_federation_desired_state.py"
HTTP_TESTS = ROOT / "services/account_unification/tests/test_full_coverage_http_clients.py"


def _replace_once(content: str, old: str, new: str, label: str) -> str:
    """Replace one reviewed anchor or accept an already-applied replacement."""
    if old in content:
        return content.replace(old, new, 1)
    if new in content:
        return content
    raise RuntimeError(f"missing reviewed anchor: {label}")


def write_tests() -> None:
    """Write the full desired-state behavior contract before production code."""
    TESTS.write_text(
        '''"""LDAP desired-state persistence and reconciliation tests."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.audit import AuditLogger, InMemoryAuditSink
from app.directory_federation import (
    DIRECTORY_FEDERATION_NAMESPACE,
    DirectoryConvergenceState,
    DirectoryFederationRegistration,
    DirectoryFederationService,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app


PRIVATE_BIND_CREDENTIAL = "rendered-private-value"
PRIVATE_BIND_DN = "CN=svc-keycloak,OU=ServiceAccounts,DC=corp,DC=example"


def _active_directory_registration(
    *, name: str = "corp-ldap", read_timeout: str = "10000"
) -> DirectoryFederationRegistration:
    """Return one realistic read-only Active Directory registration."""
    return DirectoryFederationRegistration(
        name=name,
        providerId="ldap",
        providerType="org.keycloak.storage.UserStorageProvider",
        config={
            "enabled": ["true"],
            "priority": ["1"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "vendor": ["ad"],
            "connectionUrl": [
                "ldaps://ad-01.corp.example:636 "
                "ldaps://ad-02.corp.example:636"
            ],
            "usersDn": ["OU=Users,DC=corp,DC=example"],
            "bindDn": [PRIVATE_BIND_DN],
            "bindCredential": [PRIVATE_BIND_CREDENTIAL],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "searchScope": ["2"],
            "trustEmail": ["false"],
            "useTruststoreSpi": ["always"],
            "connectionPooling": ["true"],
            "connectionTimeout": ["10000"],
            "readTimeout": [read_timeout],
            "allowKerberosAuthentication": ["false"],
        },
    )


def _service(api, *, store=None, audit=None) -> DirectoryFederationService:
    """Return a desired-state service with explicit in-memory dependencies."""
    return DirectoryFederationService(
        store or InMemoryKvStore(),
        api,
        audit,
    )


def test_put_persists_creates_and_returns_redacted_status(api) -> None:
    """A validated directory becomes durable desired state and one component."""
    store = InMemoryKvStore()
    service = _service(api, store=store)

    status = service.put_registration(
        "corp-ldap",
        _active_directory_registration(),
    )

    stored = store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap")
    assert stored is not None
    assert PRIVATE_BIND_CREDENTIAL in stored
    assert status.desired_state_stored is True
    assert status.convergence_state is DirectoryConvergenceState.IN_SYNC
    assert status.secret_observation == "not_observable"
    assert status.registration is not None
    assert status.registration.config["bindCredential"] == ["<redacted>"]
    assert status.registration.config["bindDn"] == ["<redacted>"]
    assert PRIVATE_BIND_CREDENTIAL not in status.model_dump_json(by_alias=True)
    assert PRIVATE_BIND_DN not in status.model_dump_json(by_alias=True)
    assert status.component_id is not None
    assert len(api.user_storage_components) == 1


def test_repeated_put_is_noop_and_non_secret_drift_updates(api) -> None:
    """Exact observable state is a no-op while changed timeout is reconciled."""
    service = _service(api)
    service.put_registration("corp-ldap", _active_directory_registration())
    api.calls.clear()

    unchanged = service.put_registration(
        "corp-ldap", _active_directory_registration()
    )
    assert unchanged.convergence_state is DirectoryConvergenceState.IN_SYNC
    assert not any("create_user_storage_component" in call for call in api.calls)
    assert not any("update_user_storage_component" in call for call in api.calls)

    changed = service.put_registration(
        "corp-ldap",
        _active_directory_registration(read_timeout="12000"),
    )
    assert changed.convergence_state is DirectoryConvergenceState.IN_SYNC
    assert any("update_user_storage_component" in call for call in api.calls)
    component = next(iter(api.user_storage_components.values()))
    assert component["config"]["readTimeout"] == ["12000"]


def test_put_preserves_desired_state_when_keycloak_is_unavailable(
    api, monkeypatch
) -> None:
    """Persistence succeeds and reports an honest unavailable status on outage."""
    store = InMemoryKvStore()
    service = _service(api, store=store)

    def fail_list(name: str):
        """Simulate an unavailable Keycloak component endpoint."""
        raise RuntimeError("remote unavailable")

    monkeypatch.setattr(api, "list_user_storage_components", fail_list)
    status = service.put_registration(
        "corp-ldap", _active_directory_registration()
    )

    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None
    assert status.convergence_state is DirectoryConvergenceState.UNAVAILABLE
    assert status.last_convergence_error_code == "keycloak_unavailable"
    assert PRIVATE_BIND_CREDENTIAL not in status.model_dump_json(by_alias=True)


def test_reconcile_recovers_after_realm_rebuild(api) -> None:
    """Stored private intent recreates a missing component after realm loss."""
    service = _service(api)
    service.put_registration("corp-ldap", _active_directory_registration())
    api.user_storage_components.clear()

    statuses = service.reconcile_all()

    assert [status.directory_name for status in statuses] == ["corp-ldap"]
    assert statuses[0].convergence_state is DirectoryConvergenceState.IN_SYNC
    assert len(api.user_storage_components) == 1


def test_duplicate_components_fail_closed_without_remote_mutation(api) -> None:
    """More than one exact live component blocks ambiguous PUT and delete."""
    registration = _active_directory_registration()
    api.user_storage_components = {
        "component-a": {
            "id": "component-a",
            **registration.model_dump(by_alias=True),
        },
        "component-b": {
            "id": "component-b",
            **registration.model_dump(by_alias=True),
        },
    }
    store = InMemoryKvStore()
    service = _service(api, store=store)

    with pytest.raises(HTTPException) as put_error:
        service.put_registration("corp-ldap", registration)
    assert put_error.value.status_code == 409
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None
    assert not any("update_user_storage_component" in call for call in api.calls)
    assert not any("delete_user_storage_component" in call for call in api.calls)

    with pytest.raises(HTTPException) as delete_error:
        service.delete_registration("corp-ldap")
    assert delete_error.value.status_code == 409
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None


def test_delete_removes_remote_before_local_and_preserves_retry_state(
    api, monkeypatch
) -> None:
    """A failed remote delete leaves desired state; a retry completes safely."""
    store = InMemoryKvStore()
    service = _service(api, store=store)
    service.put_registration("corp-ldap", _active_directory_registration())
    original_delete = api.delete_user_storage_component

    def fail_delete(component_id: str) -> None:
        """Simulate a remote delete failure after component lookup."""
        raise RuntimeError("delete unavailable")

    monkeypatch.setattr(api, "delete_user_storage_component", fail_delete)
    with pytest.raises(HTTPException) as error:
        service.delete_registration("corp-ldap")
    assert error.value.status_code == 502
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is not None
    assert api.user_storage_components

    monkeypatch.setattr(api, "delete_user_storage_component", original_delete)
    service.delete_registration("corp-ldap")
    assert store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap") is None
    assert not api.user_storage_components


def test_list_get_and_status_are_sorted_redacted_and_observe_drift(api) -> None:
    """Stored records are sorted and status exposes only observable drift."""
    store = InMemoryKvStore()
    service = _service(api, store=store)
    service.put_registration(
        "zeta-ldap", _active_directory_registration(name="zeta-ldap")
    )
    service.put_registration(
        "alpha-ldap", _active_directory_registration(name="alpha-ldap")
    )
    component = next(
        value
        for value in api.user_storage_components.values()
        if value["name"] == "alpha-ldap"
    )
    component["config"]["readTimeout"] = ["25000"]
    component["config"]["bindCredential"] = ["masked-or-rotated"]

    statuses = service.list_registrations()
    alpha = service.get_registration("alpha-ldap")

    assert [status.directory_name for status in statuses] == [
        "alpha-ldap",
        "zeta-ldap",
    ]
    assert alpha.convergence_state is DirectoryConvergenceState.DRIFTED
    assert alpha.last_convergence_error_code is None
    serialized = json.dumps(
        [status.model_dump(by_alias=True) for status in statuses],
        sort_keys=True,
    )
    assert PRIVATE_BIND_CREDENTIAL not in serialized
    assert PRIVATE_BIND_DN not in serialized
    assert "masked-or-rotated" not in serialized


def test_missing_and_corrupt_stored_state_fail_with_bounded_errors(api) -> None:
    """Absent and malformed records never expose raw private storage text."""
    private_marker = "stored-private-marker"
    store = InMemoryKvStore(
        {
            DIRECTORY_FEDERATION_NAMESPACE: {
                "broken-ldap": f'{{"bindCredential":"{private_marker}"}}'
            }
        }
    )
    service = _service(api, store=store)

    with pytest.raises(HTTPException) as missing:
        service.get_registration("missing-ldap")
    assert missing.value.status_code == 404

    with pytest.raises(HTTPException) as corrupt:
        service.get_registration("broken-ldap")
    assert corrupt.value.status_code == 500
    assert private_marker not in str(corrupt.value.detail)

    statuses = service.list_registrations()
    assert statuses[0].registration is None
    assert statuses[0].convergence_state is DirectoryConvergenceState.INVALID
    assert statuses[0].last_convergence_error_code == "stored_state_invalid"
    assert private_marker not in statuses[0].model_dump_json(by_alias=True)


def test_path_body_mismatch_and_invalid_path_fail_before_storage(api) -> None:
    """Desired-state keys and validated component names remain identical."""
    store = InMemoryKvStore()
    service = _service(api, store=store)

    with pytest.raises(HTTPException) as mismatch:
        service.put_registration("other-ldap", _active_directory_registration())
    assert mismatch.value.status_code == 400

    with pytest.raises(HTTPException) as invalid:
        service.get_registration("Bad Alias!")
    assert invalid.value.status_code == 400
    assert store.get_all(DIRECTORY_FEDERATION_NAMESPACE) == {}


def test_network_observation_does_not_hold_desired_state_lock(api, monkeypatch) -> None:
    """A blocked status call does not prevent another record from reaching I/O."""
    store = InMemoryKvStore()
    service = _service(api, store=store)
    service.put_registration("corp-ldap", _active_directory_registration())
    service.put_registration(
        "other-ldap", _active_directory_registration(name="other-ldap")
    )
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    call_lock = threading.Lock()
    call_count = 0
    original_list = api.list_user_storage_components

    def blocking_list(name: str):
        """Block one network call and signal when another enters the adapter."""
        nonlocal call_count
        with call_lock:
            call_count += 1
            current = call_count
        if current == 1:
            first_started.set()
            assert release_first.wait(timeout=5)
        else:
            second_started.set()
        return original_list(name)

    monkeypatch.setattr(api, "list_user_storage_components", blocking_list)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service.get_registration, "corp-ldap")
        assert first_started.wait(timeout=2)
        second = executor.submit(service.get_registration, "other-ldap")
        reached_second = second_started.wait(timeout=0.5)
        release_first.set()
        first.result(timeout=5)
        second.result(timeout=5)
    assert reached_second


def test_same_name_mutations_are_serialized(api, monkeypatch) -> None:
    """Two writes for one directory cannot race their create/update decisions."""
    service = _service(api)
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    original_list = api.list_user_storage_components
    count_lock = threading.Lock()
    call_count = 0

    def blocking_list(name: str):
        """Hold the first convergence lookup and detect a premature second one."""
        nonlocal call_count
        with count_lock:
            call_count += 1
            current = call_count
        if current == 1:
            first_started.set()
            assert release_first.wait(timeout=5)
        else:
            second_started.set()
        return original_list(name)

    monkeypatch.setattr(api, "list_user_storage_components", blocking_list)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            service.put_registration,
            "corp-ldap",
            _active_directory_registration(),
        )
        assert first_started.wait(timeout=2)
        second = executor.submit(
            service.put_registration,
            "corp-ldap",
            _active_directory_registration(read_timeout="12000"),
        )
        assert not second_started.wait(timeout=0.3)
        release_first.set()
        first.result(timeout=5)
        second.result(timeout=5)
    assert second_started.is_set()
    assert len(api.user_storage_components) == 1


def test_audit_events_are_bounded_and_secret_free(api) -> None:
    """Mutation audit payloads contain action and outcome, never private config."""
    sink = InMemoryAuditSink()
    audit = AuditLogger(sink)
    service = _service(api, audit=audit)

    service.put_registration("corp-ldap", _active_directory_registration())
    service.reconcile_all()
    service.delete_registration("corp-ldap")

    assert [event.event_type for event in sink.events] == [
        "directory_desired_state_saved",
        "directory_desired_state_reconciled",
        "directory_desired_state_deleted",
    ]
    serialized = "".join(event.payload_json for event in sink.events)
    assert PRIVATE_BIND_CREDENTIAL not in serialized
    assert PRIVATE_BIND_DN not in serialized
    assert "corp-ldap" in serialized


def test_authenticated_http_crud_reconcile_and_secret_safe_errors(
    api, auth_header, operator_token
) -> None:
    """The operator API completes the lifecycle without reflecting private values."""
    app = create_app(wire=False)
    store = InMemoryKvStore()
    app.state.directory_federation_service = _service(api, store=store)
    app.state.operator_api_token = operator_token
    body = _active_directory_registration().model_dump(by_alias=True)

    with TestClient(app) as anonymous:
        assert anonymous.get("/federation/user-directories").status_code == 401

    with TestClient(app, headers=auth_header) as client:
        put_response = client.put(
            "/federation/user-directories/corp-ldap", json=body
        )
        list_response = client.get("/federation/user-directories")
        get_response = client.get("/federation/user-directories/corp-ldap")
        reconcile_response = client.post(
            "/federation/user-directories:reconcile"
        )
        mismatch_response = client.put(
            "/federation/user-directories/other-ldap", json=body
        )
        malformed_response = client.put(
            "/federation/user-directories/corp-ldap",
            json={**body, "config": {"bindCredential": PRIVATE_BIND_CREDENTIAL}},
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
    assert mismatch_response.status_code == 400
    assert malformed_response.status_code == 422
    assert delete_response.status_code == 204
    assert missing_response.status_code == 404
    combined = "".join(
        response.text
        for response in (
            put_response,
            list_response,
            get_response,
            reconcile_response,
            mismatch_response,
            malformed_response,
            missing_response,
        )
    )
    assert PRIVATE_BIND_CREDENTIAL not in combined
    assert PRIVATE_BIND_DN not in combined


def test_http_returns_503_when_directory_service_is_not_wired(
    auth_header, operator_token
) -> None:
    """An unwired test app fails closed instead of dereferencing missing state."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    with TestClient(app, headers=auth_header) as client:
        response = client.get("/federation/user-directories")
    assert response.status_code == 503
    assert response.json() == {"detail": "directory federation service not ready"}
''',
        encoding="utf-8",
    )

    content = HTTP_TESTS.read_text(encoding="utf-8")
    marker = "def test_product_user_storage_component_methods_cover_transport_contract()"
    if marker not in content:
        content += '''\n\n
def test_product_user_storage_component_methods_cover_transport_contract() -> None:
    """The hardened adapter lists, creates, updates, and deletes components."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return deterministic component responses after token authentication."""
        requests.append(request)
        token = _token_response(request)
        if token is not None:
            return token
        if request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "component-1",
                        "name": "corp-ldap",
                        "providerId": "ldap",
                        "providerType": "org.keycloak.storage.UserStorageProvider",
                        "config": {"enabled": ["true"]},
                    }
                ],
            )
        if request.method == "POST":
            return httpx.Response(
                201,
                headers={
                    "Location": (
                        "https://keycloak.example/admin/realms/cwl/components/"
                        "component-2"
                    )
                },
            )
        return httpx.Response(204)

    api = ProductHttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )
    payload = {
        "name": "corp-ldap",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {"enabled": ["true"]},
    }

    components = api.list_user_storage_components("corp-ldap")
    created_id = api.create_user_storage_component(payload)
    api.update_user_storage_component("component-1", payload)
    api.delete_user_storage_component("component-1")
    api.close()

    assert components[0]["id"] == "component-1"
    assert created_id == "component-2"
    component_request = next(
        request
        for request in requests
        if request.method == "GET" and request.url.path.endswith("/components")
    )
    assert component_request.url.params["name"] == "corp-ldap"
    assert component_request.url.params["type"] == (
        "org.keycloak.storage.UserStorageProvider"
    )
    post_request = next(request for request in requests if request.method == "POST")
    assert b'"parentId":"cwl"' in post_request.content
    assert {request.method for request in requests} >= {
        "GET",
        "POST",
        "PUT",
        "DELETE",
    }


def test_product_component_adapter_fails_closed_on_bad_shapes_and_ids() -> None:
    """Unexpected component JSON and unsafe generated IDs never cross paths."""
    responses = iter(
        [
            httpx.Response(200, json={"not": "a list"}),
            httpx.Response(200, json=["not-an-object"]),
            httpx.Response(201),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        """Authenticate and return the next malformed or empty response."""
        token = _token_response(request)
        if token is not None:
            return token
        response = next(responses)
        response.request = request
        return response

    api = ProductHttpAdminApi(
        "https://keycloak.example",
        "cwl",
        "service-client",
        "secret",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ValueError, match="component list"):
        api.list_user_storage_components("corp-ldap")
    with pytest.raises(ValueError, match="component entry"):
        api.list_user_storage_components("corp-ldap")
    assert api.create_user_storage_component(
        {
            "name": "corp-ldap",
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "config": {},
        }
    ) is None
    with pytest.raises(InvalidIdentifierError):
        api.update_user_storage_component("../unsafe", {})
    with pytest.raises(InvalidIdentifierError):
        api.delete_user_storage_component("bad/id")
    api.close()
'''
        HTTP_TESTS.write_text(content, encoding="utf-8")


def write_production() -> None:
    """Apply the minimal reviewed production implementation for the tests."""
    content = PRODUCT_CLIENT.read_text(encoding="utf-8")
    content = _replace_once(
        content,
        '    ("identity-provider", "instances", None),\n)',
        '    ("identity-provider", "instances", None),\n'
        '    ("components",),\n'
        '    ("components", None),\n)',
        "component route allowlist",
    )
    protocol_anchor = '''    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete an identity-provider instance."""
        ...
'''
    protocol_replacement = protocol_anchor + '''
    def list_user_storage_components(self, component_name: str) -> list[dict]:
        """List exact-name Keycloak user-storage components."""
        ...

    def create_user_storage_component(self, component_payload: dict) -> str | None:
        """Create one Keycloak user-storage component and return its ID if exposed."""
        ...

    def update_user_storage_component(
        self, component_id: str, component_payload: dict
    ) -> None:
        """Replace one Keycloak user-storage component."""
        ...

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one Keycloak user-storage component."""
        ...
'''
    content = _replace_once(
        content,
        protocol_anchor,
        protocol_replacement,
        "component protocol methods",
    )
    concrete_anchor = '''    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete one Keycloak identity-provider instance."""
        safe_alias = self._safe_segment(provider_alias, "provider_alias")
        self._delete(
            f"/admin/realms/{self._realm}/identity-provider/instances/"
            f"{safe_alias}"
        )
'''
    concrete_replacement = concrete_anchor + '''

    def list_user_storage_components(self, component_name: str) -> list[dict]:
        """Return exact-name user-storage components from the configured realm."""
        safe_name = self._safe_segment(component_name, "component_name")
        data = self._get(
            f"/admin/realms/{self._realm}/components",
            params={
                "name": safe_name,
                "type": "org.keycloak.storage.UserStorageProvider",
            },
        )
        if not isinstance(data, list):
            raise ValueError("Keycloak component list response must be a list")
        if any(not isinstance(component, dict) for component in data):
            raise ValueError("Keycloak component entry must be an object")
        return [dict(component) for component in data]

    def create_user_storage_component(self, component_payload: dict) -> str | None:
        """Create one component with the configured realm as its parent."""
        safe_name = self._safe_segment(
            component_payload.get("name"), "component_name"
        )
        payload = dict(component_payload)
        payload["name"] = safe_name
        payload.setdefault("parentId", self._realm)
        path = self._guard_path(f"/admin/realms/{self._realm}/components")
        response = self._send_with_reauth(
            lambda: self._client.post(
                path,
                json=payload,
                headers=self._auth_header(),
            )
        )
        location = response.headers.get("Location", "")
        if not location:
            return None
        component_id = location.rstrip("/").rsplit("/", 1)[-1]
        return self._safe_segment(component_id, "component_id")

    def update_user_storage_component(
        self, component_id: str, component_payload: dict
    ) -> None:
        """Replace one component after validating its generated identifier."""
        safe_id = self._safe_segment(component_id, "component_id")
        safe_name = self._safe_segment(
            component_payload.get("name"), "component_name"
        )
        payload = dict(component_payload)
        payload["id"] = safe_id
        payload["name"] = safe_name
        payload.setdefault("parentId", self._realm)
        self._put(
            f"/admin/realms/{self._realm}/components/{safe_id}",
            payload,
        )

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one component after validating its generated identifier."""
        safe_id = self._safe_segment(component_id, "component_id")
        self._delete(f"/admin/realms/{self._realm}/components/{safe_id}")
'''
    content = _replace_once(
        content,
        concrete_anchor,
        concrete_replacement,
        "component HTTP methods",
    )
    PRODUCT_CLIENT.write_text(content, encoding="utf-8")

    content = MOCK.read_text(encoding="utf-8")
    content = _replace_once(
        content,
        '        self.identity_providers: dict[str, dict] = {}\n'
        '        self.action_emails: dict[str, dict] = {}\n',
        '        self.identity_providers: dict[str, dict] = {}\n'
        '        self.user_storage_components: dict[str, dict] = {}\n'
        '        self._component_sequence = 0\n'
        '        self.action_emails: dict[str, dict] = {}\n',
        "component mock state",
    )
    mock_anchor = '''    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete one applied identity provider."""
        self.calls.append(f"delete_identity_provider:{provider_alias}")
        self.identity_providers.pop(provider_alias, None)
'''
    mock_replacement = mock_anchor + '''

    def list_user_storage_components(self, component_name: str) -> list[dict]:
        """Return defensive copies of components with one exact name."""
        self.calls.append(f"list_user_storage_components:{component_name}")
        return [
            dict(component)
            for component in self.user_storage_components.values()
            if component.get("name") == component_name
        ]

    def create_user_storage_component(self, component_payload: dict) -> str:
        """Create one deterministic in-memory user-storage component."""
        self._component_sequence += 1
        component_id = f"component-{self._component_sequence}"
        self.calls.append(f"create_user_storage_component:{component_id}")
        self.user_storage_components[component_id] = {
            **dict(component_payload),
            "id": component_id,
            "parentId": component_payload.get("parentId", "cwl"),
            "config": {
                key: list(values)
                for key, values in component_payload.get("config", {}).items()
            },
        }
        return component_id

    def update_user_storage_component(
        self, component_id: str, component_payload: dict
    ) -> None:
        """Replace one deterministic in-memory component."""
        self.calls.append(f"update_user_storage_component:{component_id}")
        self.user_storage_components[component_id] = {
            **dict(component_payload),
            "id": component_id,
            "parentId": component_payload.get("parentId", "cwl"),
            "config": {
                key: list(values)
                for key, values in component_payload.get("config", {}).items()
            },
        }

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one deterministic in-memory component."""
        self.calls.append(f"delete_user_storage_component:{component_id}")
        self.user_storage_components.pop(component_id, None)
'''
    content = _replace_once(
        content,
        mock_anchor,
        mock_replacement,
        "component mock methods",
    )
    MOCK.write_text(content, encoding="utf-8")

    content = SERVICE.read_text(encoding="utf-8")
    content = _replace_once(
        content,
        'import re\nfrom typing import Any, NoReturn, cast\n',
        'import json\nimport re\nimport threading\nfrom enum import StrEnum\nfrom typing import Any, NoReturn, cast\n',
        "directory service imports",
    )
    content = _replace_once(
        content,
        'from fastapi import APIRouter, Body, HTTPException\n',
        'from fastapi import APIRouter, Body, Depends, HTTPException, Request\n',
        "FastAPI dependency imports",
    )
    content = _replace_once(
        content,
        'from pydantic import BaseModel, ConfigDict, Field, StrictStr\n',
        'from pydantic import BaseModel, ConfigDict, Field, StrictStr\n\n'
        'from .audit import AuditLogger\n'
        'from .identifiers import InvalidIdentifierError, validate_path_segment\n'
        'from .kv_store import KvStore\n'
        'from .product_keycloak_client import ProductAdminApi\n',
        "directory service dependencies",
    )
    service_anchor = '''directory_federation_router = APIRouter(
    prefix="/federation",
    tags=["directory-federation"],
)
'''
    service_code = '''DIRECTORY_FEDERATION_NAMESPACE = "directory_federation_sources"
_DIRECTORY_PROVIDER_TYPE_PUBLIC = "org.keycloak.storage.UserStorageProvider"
_PRIVATE_DIRECTORY_CONFIG_KEYS = frozenset({"bindCredential", "bindDn"})


class DirectoryConvergenceState(StrEnum):
    """Bounded operator vocabulary for one desired/live comparison."""

    IN_SYNC = "in_sync"
    DRIFTED = "drifted"
    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"
    APPLY_FAILED = "apply_failed"
    INVALID = "invalid"


class DirectoryFederationStatus(BaseModel):
    """Redacted desired-state status without false secret-equality claims."""

    directory_name: str
    registration: DirectoryFederationView | None
    desired_state_stored: bool = True
    convergence_state: DirectoryConvergenceState
    component_id: str | None = None
    secret_observation: str = "not_observable"
    last_convergence_error_code: str | None = None


class _StoredDirectoryStateError(RuntimeError):
    """Mark one unreadable private desired-state record without retaining it."""


class DirectoryFederationService:
    """Persist private LDAP intent and reconcile Keycloak outside storage locks."""

    def __init__(
        self,
        store: KvStore,
        api: ProductAdminApi,
        audit: AuditLogger | None = None,
    ) -> None:
        """Create a service over one store, Keycloak adapter, and optional audit."""
        self._store = store
        self._api = api
        self._audit = audit
        self._state_lock = threading.RLock()
        self._convergence_lock = threading.RLock()

    @staticmethod
    def _validate_directory_name(directory_name: str) -> str:
        """Return one validated desired-state key and path alias."""
        if (
            not isinstance(directory_name, str)
            or len(directory_name) > _MAX_COMPONENT_NAME_LENGTH
            or _COMPONENT_NAME.fullmatch(directory_name) is None
        ):
            _directory_error(
                "directory_name",
                "must be a lowercase ASCII alphanumeric-and-hyphen slug",
            )
        return directory_name

    @staticmethod
    def _parse_stored(
        directory_name: str, raw_value: str
    ) -> DirectoryFederationRegistration:
        """Parse and revalidate private stored state without reflecting failures."""
        try:
            registration = DirectoryFederationRegistration.model_validate_json(
                raw_value
            )
            if registration.name != directory_name:
                raise ValueError("stored alias mismatch")
            validate_directory_registration(registration)
        except Exception as error:
            raise _StoredDirectoryStateError(
                "stored directory state is invalid"
            ) from error
        return registration

    @staticmethod
    def _observable_config(config: dict) -> dict[str, list[str]]:
        """Return exact non-secret Keycloak config values suitable for comparison."""
        return {
            key: list(values)
            for key, values in config.items()
            if key not in _PRIVATE_DIRECTORY_CONFIG_KEYS
            and isinstance(values, list)
        }

    @classmethod
    def _component_matches(
        cls,
        registration: DirectoryFederationRegistration,
        component: dict,
    ) -> bool:
        """Compare only exact observable fields while treating secrets as opaque."""
        if (
            component.get("name") != registration.name
            or component.get("providerId") != registration.provider_id
            or component.get("providerType") != registration.provider_type
        ):
            return False
        live_config = component.get("config")
        if not isinstance(live_config, dict):
            return False
        desired = cls._observable_config(registration.config)
        observed = cls._observable_config(live_config)
        return all(observed.get(key) == value for key, value in desired.items())

    @staticmethod
    def _component_id(component: dict) -> str:
        """Return one validated generated Keycloak component identifier."""
        component_id = component.get("id")
        if not isinstance(component_id, str):
            raise InvalidIdentifierError("component_id must be a string")
        return validate_path_segment(component_id, field_name="component_id")

    def _exact_components(
        self, registration: DirectoryFederationRegistration
    ) -> list[dict]:
        """Return exact LDAP user-storage matches from the bounded adapter query."""
        components = self._api.list_user_storage_components(registration.name)
        return [
            component
            for component in components
            if component.get("name") == registration.name
            and component.get("providerId") == registration.provider_id
            and component.get("providerType") == registration.provider_type
        ]

    def _status_from_live(
        self,
        registration: DirectoryFederationRegistration,
    ) -> DirectoryFederationStatus:
        """Observe Keycloak and classify exact public convergence state."""
        try:
            components = self._exact_components(registration)
        except Exception:
            return self._status(
                registration,
                DirectoryConvergenceState.UNAVAILABLE,
                error_code="keycloak_unavailable",
            )
        if not components:
            return self._status(registration, DirectoryConvergenceState.ABSENT)
        if len(components) > 1:
            return self._status(
                registration,
                DirectoryConvergenceState.AMBIGUOUS,
                error_code="duplicate_components",
            )
        component = components[0]
        try:
            component_id = self._component_id(component)
        except InvalidIdentifierError:
            return self._status(
                registration,
                DirectoryConvergenceState.UNAVAILABLE,
                error_code="keycloak_unavailable",
            )
        state = (
            DirectoryConvergenceState.IN_SYNC
            if self._component_matches(registration, component)
            else DirectoryConvergenceState.DRIFTED
        )
        return self._status(registration, state, component_id=component_id)

    def _status(
        self,
        registration: DirectoryFederationRegistration,
        state: DirectoryConvergenceState,
        *,
        component_id: str | None = None,
        error_code: str | None = None,
    ) -> DirectoryFederationStatus:
        """Build one redacted status from validated private desired state."""
        return DirectoryFederationStatus(
            directory_name=registration.name,
            registration=DirectoryFederationView.from_registration(registration),
            convergence_state=state,
            component_id=component_id,
            last_convergence_error_code=error_code,
        )

    @staticmethod
    def _invalid_status(directory_name: str) -> DirectoryFederationStatus:
        """Return a bounded placeholder for unreadable desired-state storage."""
        safe_name = (
            directory_name
            if _COMPONENT_NAME.fullmatch(directory_name or "") is not None
            else "<invalid>"
        )
        return DirectoryFederationStatus(
            directory_name=safe_name,
            registration=None,
            convergence_state=DirectoryConvergenceState.INVALID,
            last_convergence_error_code="stored_state_invalid",
        )

    def _emit_audit(
        self,
        event_type: str,
        registration: DirectoryFederationRegistration,
        status: DirectoryFederationStatus | None = None,
    ) -> None:
        """Emit one bounded event that contains no directory private values."""
        if self._audit is None:
            return
        payload = {"directory_name": registration.name}
        if status is not None:
            payload.update(
                {
                    "convergence_state": status.convergence_state.value,
                    "error_code": status.last_convergence_error_code,
                }
            )
        self._audit.emit(
            audit_id=self._audit.new_correlation_id(),
            event_type=event_type,
            actor="operator",
            payload=payload,
        )

    def _converge(
        self, registration: DirectoryFederationRegistration
    ) -> DirectoryFederationStatus:
        """Create, update, no-op, or report one bounded convergence failure."""
        observed = self._status_from_live(registration)
        if observed.convergence_state is DirectoryConvergenceState.UNAVAILABLE:
            return observed
        if observed.convergence_state is DirectoryConvergenceState.AMBIGUOUS:
            return observed
        if observed.convergence_state is DirectoryConvergenceState.IN_SYNC:
            return observed
        try:
            if observed.convergence_state is DirectoryConvergenceState.ABSENT:
                self._api.create_user_storage_component(
                    registration.model_dump(by_alias=True)
                )
            else:
                if observed.component_id is None:
                    raise InvalidIdentifierError("missing component id")
                self._api.update_user_storage_component(
                    observed.component_id,
                    registration.model_dump(by_alias=True),
                )
        except Exception:
            return self._status(
                registration,
                DirectoryConvergenceState.APPLY_FAILED,
                component_id=observed.component_id,
                error_code=(
                    "component_create_failed"
                    if observed.convergence_state is DirectoryConvergenceState.ABSENT
                    else "component_update_failed"
                ),
            )
        verified = self._status_from_live(registration)
        if verified.convergence_state is DirectoryConvergenceState.ABSENT:
            return self._status(
                registration,
                DirectoryConvergenceState.APPLY_FAILED,
                error_code="component_create_failed",
            )
        return verified

    def put_registration(
        self,
        directory_name: str,
        registration: DirectoryFederationRegistration,
    ) -> DirectoryFederationStatus:
        """Persist one validated private intent and attempt exact convergence."""
        safe_name = self._validate_directory_name(directory_name)
        if registration.name != safe_name:
            _directory_error("name", "must match the directory_name path")
        validate_directory_registration(registration)
        with self._convergence_lock:
            with self._state_lock:
                self._store.put(
                    DIRECTORY_FEDERATION_NAMESPACE,
                    safe_name,
                    registration.model_dump_json(by_alias=True),
                )
            status = self._converge(registration)
            self._emit_audit(
                "directory_desired_state_saved", registration, status
            )
            if status.convergence_state is DirectoryConvergenceState.AMBIGUOUS:
                raise HTTPException(
                    status_code=409,
                    detail="multiple exact directory components exist",
                )
            return status

    def list_registrations(self) -> list[DirectoryFederationStatus]:
        """Return sorted redacted desired-state and live convergence statuses."""
        with self._state_lock:
            snapshot = self._store.get_all(DIRECTORY_FEDERATION_NAMESPACE)
        statuses: list[DirectoryFederationStatus] = []
        for directory_name, raw_value in sorted(snapshot.items()):
            try:
                registration = self._parse_stored(directory_name, raw_value)
            except _StoredDirectoryStateError:
                statuses.append(self._invalid_status(directory_name))
                continue
            statuses.append(self._status_from_live(registration))
        return statuses

    def get_registration(
        self, directory_name: str
    ) -> DirectoryFederationStatus:
        """Return one redacted desired-state status or bounded 404/500."""
        safe_name = self._validate_directory_name(directory_name)
        with self._state_lock:
            raw_value = self._store.get(
                DIRECTORY_FEDERATION_NAMESPACE, safe_name
            )
        if raw_value is None:
            raise HTTPException(
                status_code=404, detail="directory desired state not found"
            )
        try:
            registration = self._parse_stored(safe_name, raw_value)
        except _StoredDirectoryStateError as error:
            raise HTTPException(
                status_code=500, detail="stored directory state is invalid"
            ) from error
        return self._status_from_live(registration)

    def delete_registration(self, directory_name: str) -> None:
        """Delete the remote component before removing private desired state."""
        safe_name = self._validate_directory_name(directory_name)
        with self._convergence_lock:
            with self._state_lock:
                raw_value = self._store.get(
                    DIRECTORY_FEDERATION_NAMESPACE, safe_name
                )
            if raw_value is None:
                raise HTTPException(
                    status_code=404, detail="directory desired state not found"
                )
            try:
                registration = self._parse_stored(safe_name, raw_value)
            except _StoredDirectoryStateError as error:
                raise HTTPException(
                    status_code=500, detail="stored directory state is invalid"
                ) from error
            status = self._status_from_live(registration)
            if status.convergence_state is DirectoryConvergenceState.UNAVAILABLE:
                raise HTTPException(
                    status_code=503, detail="Keycloak component status unavailable"
                )
            if status.convergence_state is DirectoryConvergenceState.AMBIGUOUS:
                raise HTTPException(
                    status_code=409,
                    detail="multiple exact directory components exist",
                )
            if status.component_id is not None:
                try:
                    self._api.delete_user_storage_component(status.component_id)
                except Exception as error:
                    raise HTTPException(
                        status_code=502,
                        detail="Keycloak component delete failed",
                    ) from error
            with self._state_lock:
                self._store.delete(DIRECTORY_FEDERATION_NAMESPACE, safe_name)
            self._emit_audit("directory_desired_state_deleted", registration)

    def reconcile_all(self) -> list[DirectoryFederationStatus]:
        """Reconcile a storage snapshot while refetching each current record."""
        with self._state_lock:
            directory_names = sorted(
                self._store.get_all(DIRECTORY_FEDERATION_NAMESPACE)
            )
        statuses: list[DirectoryFederationStatus] = []
        with self._convergence_lock:
            for directory_name in directory_names:
                with self._state_lock:
                    raw_value = self._store.get(
                        DIRECTORY_FEDERATION_NAMESPACE, directory_name
                    )
                if raw_value is None:
                    continue
                try:
                    registration = self._parse_stored(
                        directory_name, raw_value
                    )
                except _StoredDirectoryStateError:
                    statuses.append(self._invalid_status(directory_name))
                    continue
                status = self._converge(registration)
                statuses.append(status)
                self._emit_audit(
                    "directory_desired_state_reconciled",
                    registration,
                    status,
                )
        return statuses


'''
    content = _replace_once(
        content,
        service_anchor,
        service_code + service_anchor,
        "directory desired-state service",
    )
    routes_anchor = '''@directory_federation_router.post(
    "/user-directories:validate",
    response_model=DirectoryFederationValidationResult,
)
def validate_user_directory(
    payload: Any = Body(...),
) -> DirectoryFederationValidationResult:
    """Validate LDAP desired input without storage or network side effects."""
    registration = _parse_directory_registration(payload)
    return validate_directory_registration(registration)
'''
    routes_replacement = routes_anchor + '''


def get_directory_federation_service(
    request: Request,
) -> DirectoryFederationService:
    """Return the wired directory desired-state service from application state."""
    service = getattr(request.app.state, "directory_federation_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="directory federation service not ready",
        )
    return service


@directory_federation_router.get(
    "/user-directories",
    response_model=list[DirectoryFederationStatus],
)
def list_user_directories(
    service: DirectoryFederationService = Depends(
        get_directory_federation_service
    ),
) -> list[DirectoryFederationStatus]:
    """List all redacted directory desired-state statuses."""
    return service.list_registrations()


@directory_federation_router.post(
    "/user-directories:reconcile",
    response_model=list[DirectoryFederationStatus],
)
def reconcile_user_directories(
    service: DirectoryFederationService = Depends(
        get_directory_federation_service
    ),
) -> list[DirectoryFederationStatus]:
    """Reconcile every current private desired-state record."""
    return service.reconcile_all()


@directory_federation_router.get(
    "/user-directories/{directory_name}",
    response_model=DirectoryFederationStatus,
)
def get_user_directory(
    directory_name: str,
    service: DirectoryFederationService = Depends(
        get_directory_federation_service
    ),
) -> DirectoryFederationStatus:
    """Return one redacted directory desired-state status."""
    return service.get_registration(directory_name)


@directory_federation_router.put(
    "/user-directories/{directory_name}",
    response_model=DirectoryFederationStatus,
)
def put_user_directory(
    directory_name: str,
    payload: Any = Body(...),
    service: DirectoryFederationService = Depends(
        get_directory_federation_service
    ),
) -> DirectoryFederationStatus:
    """Persist one private desired state and attempt Keycloak convergence."""
    registration = _parse_directory_registration(payload)
    return service.put_registration(directory_name, registration)


@directory_federation_router.delete(
    "/user-directories/{directory_name}", status_code=204
)
def delete_user_directory(
    directory_name: str,
    service: DirectoryFederationService = Depends(
        get_directory_federation_service
    ),
) -> None:
    """Delete one remote component before its private desired state."""
    service.delete_registration(directory_name)
'''
    content = _replace_once(
        content,
        routes_anchor,
        routes_replacement,
        "directory desired-state routes",
    )
    SERVICE.write_text(content, encoding="utf-8")

    content = MAIN.read_text(encoding="utf-8")
    content = _replace_once(
        content,
        'from .directory_federation import directory_federation_router\n',
        'from .directory_federation import (\n'
        '    DirectoryFederationService,\n'
        '    directory_federation_router,\n'
        ')\n',
        "main directory import",
    )
    content = _replace_once(
        content,
        '    app.state.federation_service = FederationService(store, api)\n',
        '    app.state.federation_service = FederationService(store, api)\n'
        '    app.state.directory_federation_service = DirectoryFederationService(\n'
        '        store, api, audit\n'
        '    )\n',
        "main directory service wiring",
    )
    MAIN.write_text(content, encoding="utf-8")


def main() -> None:
    """Apply one requested TDD phase."""
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("tests", "production"))
    args = parser.parse_args()
    if args.phase == "tests":
        write_tests()
    else:
        write_production()


if __name__ == "__main__":
    main()
