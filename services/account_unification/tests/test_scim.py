"""Inbound SCIM 2.0 provisioning shim -> Keycloak Admin API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(api):
    app = create_app(wire=False)
    app.state.keycloak_api = api
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
