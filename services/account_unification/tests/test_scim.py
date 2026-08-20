"""Authenticated SCIM 2.0 provisioning and merge serialization tests."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from app.errors import InactiveAccountError
from app.main import create_app
from app.models import MergeRequest
from app.service import TOMBSTONE_ATTRIBUTE_KEY, UnificationService
from app.user_locks import InMemoryUserOperationLocks

from .mock_product_keycloak import MockProductKeycloakAdminApi


class _BlockingReplaceApi(MockProductKeycloakAdminApi):
    """Pause SCIM replacement after its tombstone check."""

    def __init__(self) -> None:
        """Create synchronization events for the race test."""
        super().__init__()
        self.replace_started = threading.Event()
        self.allow_replace = threading.Event()

    def replace_user(self, user_id, user) -> None:
        """Block the full representation PUT until released."""
        self.replace_started.set()
        if not self.allow_replace.wait(timeout=5):
            raise AssertionError("test did not release the SCIM replacement")
        super().replace_user(user_id, user)
        self.attributes = {
            attribute: value
            for attribute, value in self.attributes.items()
            if attribute[0] != user_id
        }
        self.deactivated.discard(user_id)


class _BlockingDeactivateApi(MockProductKeycloakAdminApi):
    """Pause the first deactivation so a merge can contend on the same user."""

    def __init__(self) -> None:
        """Create synchronization events for the deactivation race test."""
        super().__init__()
        self.deactivate_started = threading.Event()
        self.allow_deactivate = threading.Event()
        self.merge_deactivate_started = threading.Event()
        self._block_next_deactivation = True

    def deactivate_user(self, user_id: str) -> None:
        """Block only the first deactivation, then use the normal fake."""
        if self._block_next_deactivation:
            self._block_next_deactivation = False
            self.deactivate_started.set()
            if not self.allow_deactivate.wait(timeout=5):
                raise AssertionError("test did not release the SCIM deactivation")
        else:
            self.merge_deactivate_started.set()
        super().deactivate_user(user_id)


@pytest.fixture
def client(
    api,
    user_operation_locks,
    config,
    auth_header,
):
    """Return an authenticated SCIM test client."""
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.user_operation_locks = user_operation_locks
    app.state.operator_api_token = config.operator_api_token
    with TestClient(app, headers=auth_header) as test_client:
        yield test_client


def _scim_user(
    username: str = "jane",
    email: str = "jane@corp.com",
    external_id: str = "hr-1",
) -> dict[str, object]:
    """Build one valid SCIM User resource."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "externalId": external_id,
        "name": {"givenName": "Jane", "familyName": "Doe"},
        "emails": [{"value": email, "primary": True}],
        "active": True,
    }


def test_service_provider_config(client) -> None:
    """SCIM clients can discover supported protocol features."""
    response = client.get("/scim/v2/ServiceProviderConfig")
    assert response.status_code == 200
    body = response.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True


def test_scim_create_provisions_into_keycloak(client, api) -> None:
    """SCIM create provisions a verified authoritative account."""
    response = client.post("/scim/v2/Users", json=_scim_user())
    assert response.status_code == 201
    body = response.json()
    assert body["userName"] == "jane"
    assert body["emails"][0]["value"] == "jane@corp.com"
    provisioned = api.find_user_by_username("jane")
    assert provisioned is not None
    assert provisioned.is_email_verified is True
    assert provisioned.external_id == "hr-1"


def test_scim_create_duplicate_conflicts(client) -> None:
    """A duplicate SCIM username produces HTTP 409."""
    assert client.post("/scim/v2/Users", json=_scim_user()).status_code == 201
    response = client.post("/scim/v2/Users", json=_scim_user())
    assert response.status_code == 409


def test_scim_get_and_filter_user(client) -> None:
    """Created users are retrievable directly and by username filter."""
    created = client.post("/scim/v2/Users", json=_scim_user()).json()

    get_response = client.get(f"/scim/v2/Users/{created['id']}")
    filter_response = client.get(
        '/scim/v2/Users?filter=userName eq "jane"'
    )

    assert get_response.status_code == 200
    assert get_response.json()["userName"] == "jane"
    assert filter_response.status_code == 200
    assert filter_response.json()["totalResults"] == 1


def test_scim_get_unknown_user_404(client) -> None:
    """Unknown SCIM resources produce HTTP 404."""
    response = client.get("/scim/v2/Users/does-not-exist")
    assert response.status_code == 404


def test_scim_replace_updates_user(client, api) -> None:
    """SCIM PUT replaces the Keycloak user representation."""
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    response = client.put(
        f"/scim/v2/Users/{created['id']}",
        json=_scim_user(email="jane.doe@corp.com"),
    )
    assert response.status_code == 200
    assert api.get_user(created["id"]).email == "jane.doe@corp.com"


def test_scim_replace_refuses_tombstone_resurrection(client, api) -> None:
    """A merged-away duplicate cannot be re-enabled by SCIM PUT."""
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    duplicate_id = created["id"]
    api.set_user_attribute(
        duplicate_id,
        TOMBSTONE_ATTRIBUTE_KEY,
        "survivor-id",
    )
    api.deactivate_user(duplicate_id)

    response = client.put(
        f"/scim/v2/Users/{duplicate_id}",
        json=_scim_user(),
    )

    assert response.status_code == 409
    assert duplicate_id in api.deactivated
    assert api.get_user(duplicate_id).state == "disabled"
    assert api.get_user_attribute(
        duplicate_id,
        TOMBSTONE_ATTRIBUTE_KEY,
    ) == "survivor-id"


def test_scim_replace_is_serialized_with_merge(
    config, audit, auth_header, monkeypatch
) -> None:
    """The production lock manager closes the SCIM/merge TOCTOU window."""
    api = _BlockingReplaceApi()
    locks = InMemoryUserOperationLocks()
    merge_lock_attempted = threading.Event()
    original_hold = locks.hold

    @contextmanager
    def observed_hold(*user_ids: str):
        """Record the merge's lock attempt while delegating to production code."""
        if set(user_ids) == {"survivor", "dup"}:
            merge_lock_attempted.set()
        with original_hold(*user_ids):
            yield

    monkeypatch.setattr(locks, "hold", observed_hold)
    service = UnificationService(api, audit, config, locks)
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.user_operation_locks = locks
    app.state.unification_service = service
    app.state.audit_logger = audit
    app.state.operator_api_token = config.operator_api_token
    api.create_test_user(
        "survivor",
        email="jane@corp.com",
        is_email_verified=True,
    )
    api.create_test_user(
        "dup",
        email="jane@corp.com",
        is_email_verified=True,
    )

    def run_merge():
        """Start one merge that contends on the duplicate-user lock."""
        return service.merge_accounts(
            MergeRequest(
                survivor_user_id="survivor",
                duplicate_user_id="dup",
                actor="admin@cwl",
            )
        )

    with (
        TestClient(app, headers=auth_header) as test_client,
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        scim_future = executor.submit(
            test_client.put,
            "/scim/v2/Users/dup",
            json=_scim_user(username="dup"),
        )
        # replace_user is called only after SCIM has acquired the production lock.
        assert api.replace_started.wait(timeout=2)
        merge_future = executor.submit(run_merge)
        # The hook fires immediately before the same production hold blocks on dup.
        assert merge_lock_attempted.wait(timeout=2)
        assert not merge_future.done()

        api.allow_replace.set()
        response = scim_future.result(timeout=5)
        merge_result = merge_future.result(timeout=5)

    assert response.status_code == 200
    assert merge_result.duplicate_tombstoned is True
    assert api.get_user("dup").state == "disabled"
    assert api.get_user_attribute("dup", TOMBSTONE_ATTRIBUTE_KEY) == "survivor"


def test_scim_patch_is_serialized_with_merge(
    config, audit, auth_header
) -> None:
    """SCIM deactivation and merge share the duplicate-user lock boundary."""
    api = _BlockingDeactivateApi()
    locks = InMemoryUserOperationLocks()
    merge_lock_attempted = threading.Event()
    original_hold = locks.hold

    @contextmanager
    def observed_hold(*user_ids: str):
        """Record the merge lock attempt while using the production lock."""
        if set(user_ids) == {"survivor", "dup"}:
            merge_lock_attempted.set()
        with original_hold(*user_ids):
            yield

    locks.hold = observed_hold
    service = UnificationService(api, audit, config, locks)
    app = create_app(wire=False)
    app.state.keycloak_api = api
    app.state.user_operation_locks = locks
    app.state.unification_service = service
    app.state.audit_logger = audit
    app.state.operator_api_token = config.operator_api_token
    api.create_test_user(
        "survivor",
        email="jane@corp.com",
        is_email_verified=True,
    )
    api.create_test_user(
        "dup",
        email="jane@corp.com",
        is_email_verified=True,
    )

    def run_merge():
        """Start one merge that contends on the duplicate-user lock."""
        return service.merge_accounts(
            MergeRequest(
                survivor_user_id="survivor",
                duplicate_user_id="dup",
                actor="admin@cwl",
            )
        )

    with (
        TestClient(app, headers=auth_header) as test_client,
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        patch_future = executor.submit(
            test_client.patch,
            "/scim/v2/Users/dup",
            json={
                "Operations": [
                    {"op": "replace", "value": {"active": False}}
                ]
            },
        )
        assert api.deactivate_started.wait(timeout=2)
        merge_future = executor.submit(run_merge)
        assert merge_lock_attempted.wait(timeout=2)
        merge_reached_deactivation = api.merge_deactivate_started.wait(timeout=0.25)

        api.allow_deactivate.set()
        response = patch_future.result(timeout=5)
        with pytest.raises(InactiveAccountError):
            merge_future.result(timeout=5)

    assert not merge_reached_deactivation
    assert response.status_code == 200
    assert response.json()["active"] is False
    assert api.get_user("dup").state == "disabled"
    assert api.get_user_attribute("dup", TOMBSTONE_ATTRIBUTE_KEY) is None


def test_scim_patch_deactivates_user(client, api) -> None:
    """SCIM PATCH active=false disables the Keycloak account."""
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    response = client.patch(
        f"/scim/v2/Users/{created['id']}",
        json={
            "schemas": [
                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
            ],
            "Operations": [
                {"op": "replace", "value": {"active": False}}
            ],
        },
    )
    assert response.status_code == 200
    assert response.json()["active"] is False
    assert created["id"] in api.deactivated


def test_scim_delete_deprovisions_by_disabling(client, api) -> None:
    """SCIM DELETE performs a non-destructive soft deprovision."""
    created = client.post("/scim/v2/Users", json=_scim_user()).json()
    response = client.delete(f"/scim/v2/Users/{created['id']}")
    assert response.status_code == 204
    assert created["id"] in api.deactivated
