"""Inbound SCIM 2.0 provisioning shim -> Keycloak Admin API."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import MergeRequest
from app.service import TOMBSTONE_ATTRIBUTE_KEY, UnificationService

from .mock_keycloak import MockKeycloakAdminApi


class _TestUserOperationLocks:
    """Small keyed lock manager used to prove cross-path serialization."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, threading.RLock] = {}

    @contextmanager
    def hold(self, *user_ids: str):
        """Hold all requested user locks in stable order."""
        ordered_ids = sorted(set(user_ids))
        with self._guard:
            locks = [self._locks.setdefault(user_id, threading.RLock()) for user_id in ordered_ids]
        for lock in locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()


class _BlockingReplaceApi(MockKeycloakAdminApi):
    """Pause SCIM replacement after its tombstone check to expose the race."""

    def __init__(self) -> None:
        super().__init__()
        self.replace_started = threading.Event()
        self.allow_replace = threading.Event()
        self.tombstone_started = threading.Event()

    def replace_user(self, user_id, user) -> None:
        """Wait until the test permits the full Keycloak representation PUT."""
        self.replace_started.set()
        if not self.allow_replace.wait(timeout=5):
            raise AssertionError("test did not release the blocked SCIM replacement")
        super().replace_user(user_id, user)
        # Keycloak's full user-representation PUT can remove attributes omitted
        # from the payload and re-enable the account via SCIM's active=true.
        self.attributes = {
            attribute: value
            for attribute, value in self.attributes.items()
            if attribute[0] != user_id
        }
        self.deactivated.discard(user_id)

    def set_user_attribute(self, user_id: str, key: str, value: str) -> None:
        """Signal when merge begins writing the duplicate tombstone."""
        if user_id == "dup" and key == TOMBSTONE_ATTRIBUTE_KEY:
            self.tombstone_started.set()
        super().set_user_attribute(user_id, key, value)


@pytest.fixture
def user_operation_locks():
    return _TestUserOperationLocks()


@pytest.fixture
def client(api, user_operation_locks):
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.user_operation_locks = user_operation_locks
    with TestClient(app) as test_client:
        yield test_client


def _scim_user(username="jane", email="jane@corp.com", external_id="hr-1"):
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "externalId": external_id,
        "name": {"givenName": "Jane", "familyName": "Doe"},
        "emails": [{"value": email, "primary": True}],
        "active": True,
    }


def test_service_provider_config(client):
    response = client.get("/scim/v2/ServiceProviderConfig")
    assert response.status_code == 200
    body = response.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True


def test_scim_create_provisions_into_keycloak(client, api):
    response = client.post("/scim/v2/Users", json=_scim_user())
    assert response.status_code == 201
    body = response.json()
    assert body["userName"] == "jane"
    assert body["emails"][0]["value"] == "jane@corp.com"
    # The user now exists in the (mock) Keycloak store, provisioned + verified.
    provisioned = api.find_user_by_username("jane")
    assert provisioned is not None
    assert provisioned.is_email_verified is True
    assert provisioned.external_id == "hr-1"


def test_scim_create_duplicate_conflicts(client, api):
    client.post("/scim/v2/Users", json=_scim_user())
    response = client.post("/scim/v2/Users", json=_scim_user())
    assert response.status_code == 409


def test_scim_get_user(client):
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    response = client.get(f"/scim/v2/Users/{created['id']}")
    assert response.status_code == 200
    assert response.json()["userName"] == "jane"


def test_scim_get_unknown_user_404(client):
    response = client.get("/scim/v2/Users/does-not-exist")
    assert response.status_code == 404


def test_scim_filter_by_username(client):
    client.post("/scim/v2/Users", json=_scim_user())
    response = client.get('/scim/v2/Users?filter=userName eq "jane"')
    assert response.status_code == 200
    body = response.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "jane"


def test_scim_replace_updates_user(client, api):
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    updated = _scim_user(email="jane.doe@corp.com")
    response = client.put(f"/scim/v2/Users/{created['id']}", json=updated)
    assert response.status_code == 200
    assert api.get_user(created["id"]).email == "jane.doe@corp.com"


def test_scim_replace_refuses_to_resurrect_a_tombstoned_duplicate(client, api):
    """A merged-away (tombstoned) duplicate must not be re-enabled via SCIM PUT.

    After a merge the duplicate is disabled and carries a merged_into_user_id
    pointer. A routine upstream full-sync PUT (``active`` defaults to true) must
    be refused with 409, leaving the duplicate disabled with its survivor pointer
    intact -- never silently reactivated.
    """
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    dup_id = created["id"]
    # Simulate the post-merge tombstone state (service._tombstone does exactly this).
    api.set_user_attribute(dup_id, "merged_into_user_id", "survivor-id")
    api.deactivate_user(dup_id)

    response = client.put(f"/scim/v2/Users/{dup_id}", json=_scim_user())

    assert response.status_code == 409
    assert dup_id in api.deactivated
    assert api.get_user(dup_id).state == "disabled"
    assert api.get_user_attribute(dup_id, "merged_into_user_id") == "survivor-id"


def test_scim_replace_is_serialized_with_concurrent_merge(config, audit):
    """A concurrent merge cannot slip between SCIM's tombstone check and PUT."""
    api = _BlockingReplaceApi()
    locks = _TestUserOperationLocks()
    service = UnificationService(
        api,
        audit,
        config,
        user_operation_locks=locks,
    )
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.user_operation_locks = locks
    app.state.unification_service = service
    api.create_test_user(
        "survivor", email="jane@corp.com", is_email_verified=True
    )
    api.create_test_user("dup", email="jane@corp.com", is_email_verified=True)
    merge_invoked = threading.Event()

    def run_merge():
        merge_invoked.set()
        return service.merge_accounts(
            MergeRequest(
                survivor_user_id="survivor",
                duplicate_user_id="dup",
                actor="admin@cwl",
            )
        )

    with TestClient(app) as test_client, ThreadPoolExecutor(max_workers=2) as executor:
        scim_future = executor.submit(
            test_client.put,
            "/scim/v2/Users/dup",
            json=_scim_user(username="dup"),
        )
        assert api.replace_started.wait(timeout=2)
        merge_future = executor.submit(run_merge)
        assert merge_invoked.wait(timeout=2)

        merge_was_serialized = not api.tombstone_started.wait(timeout=0.25)
        api.allow_replace.set()
        response = scim_future.result(timeout=5)
        merge_result = merge_future.result(timeout=5)

    assert merge_was_serialized
    assert response.status_code == 200
    assert merge_result.duplicate_tombstoned is True
    assert api.get_user("dup").state == "disabled"
    assert api.get_user_attribute("dup", TOMBSTONE_ATTRIBUTE_KEY) == "survivor"


def test_scim_patch_deactivates_user(client, api):
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    response = client.patch(
        f"/scim/v2/Users/{created['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": False}}],
        },
    )
    assert response.status_code == 200
    assert response.json()["active"] is False
    assert created["id"] in api.deactivated


def test_scim_delete_deprovisions_by_disabling(client, api):
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    response = client.delete(f"/scim/v2/Users/{created['id']}")
    assert response.status_code == 204
    assert created["id"] in api.deactivated
