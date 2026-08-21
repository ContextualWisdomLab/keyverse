"""HTTP and persistence contracts for the authorization-plane PDP."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.authorization_plane import (
    MENU_GRANT_NAMESPACE,
    SOFTWARE_UNIT_GRANT_NAMESPACE,
    SSO_COMBINATION_NAMESPACE,
    AuthorizationPlaneService,
    authorization_router,
    get_authorization_service,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app
from app.org_authorization import AuthorizationGrant, SsoCombinationScope


PERSON_PATH = (
    "/group_company/acme/legal_entity/holdco/business_unit/sales/"
    "team/alpha/person/jdoe"
)
SNAPSHOT = {
    "keyverse_subject": "sub-jdoe-opaque",
    "tenant_deployment_id": "default-deployment",
    "org_path": PERSON_PATH,
    "assignment_record_id": "assignment-record-77",
    "request_attributes": {"purpose": "hr-review"},
}
SOFTWARE_GRANT = {
    "grant_key": "acme-naruon",
    "tenant_deployment_id": "default-deployment",
    "grant_scope_code": "software_unit",
    "org_path": "/group_company/acme",
    "software_unit_id": "naruon-web",
    "effect_code": "allow",
    "actor_identity_id": "operator-ida",
}
MENU_GRANT = {
    "grant_key": "acme-naruon-invoices",
    "tenant_deployment_id": "default-deployment",
    "grant_scope_code": "menu",
    "org_path": "/group_company/acme",
    "software_unit_id": "naruon-web",
    "menu_path": "/invoices",
    "effect_code": "allow",
    "capability_codes": ["menu.read", "menu.approve"],
    "attribute_constraints": {"purpose": "hr-review"},
    "actor_identity_id": "operator-ida",
}
COMBINATION = {
    "combination_name": "finance-suite",
    "tenant_deployment_id": "default-deployment",
    "software_unit_ids": ["naruon-web", "clearfolio-web"],
    "actor_identity_id": "operator-ida",
}


@pytest.fixture
def store() -> InMemoryKvStore:
    """Return an empty KV store for authorization grants."""
    return InMemoryKvStore()


@pytest.fixture
def client(store: InMemoryKvStore, auth_header):
    """Return an authenticated app with the authorization plane wired."""
    app = create_app(wire=False)
    app.state.authorization_service = AuthorizationPlaneService(store)
    app.state.operator_api_token = "test-operator-token"
    with TestClient(app, headers=auth_header) as test_client:
        yield test_client


def test_software_unit_grant_round_trip_and_inherited_decision(client) -> None:
    """Operators persist a grant and descendants inherit the allow."""
    created = client.put("/authorization/software-unit-grants/acme-naruon", json=SOFTWARE_GRANT)
    assert created.status_code == 200
    listed = client.get("/authorization/software-unit-grants")
    fetched = client.get("/authorization/software-unit-grants/acme-naruon")
    decision = client.post(
        "/authorization/software-units:decide",
        json={"snapshot": SNAPSHOT, "software_unit_id": "naruon-web"},
    )
    assert listed.json()[0]["grant_key"] == "acme-naruon"
    assert fetched.json()["software_unit_id"] == "naruon-web"
    body = decision.json()
    assert body["effect"] == "allow"
    assert body["decision_code"] == "inherited_allow"
    assert body["pep_enforcement_required"] is True
    assert "org" not in body["authorization_attributes"]
    assert body["authorization_attributes"]["group_company"] == "acme"


def test_embedded_authorization_router_requires_operator_authentication() -> None:
    """A directly embedded authorization router cannot be mounted open."""
    app = FastAPI()
    app.state.authorization_service = AuthorizationPlaneService(InMemoryKvStore())
    app.state.operator_api_token = "test-operator-token"
    app.include_router(authorization_router)
    with TestClient(app) as embedded_client:
        denied = embedded_client.get("/authorization/software-unit-grants")
        allowed = embedded_client.get(
            "/authorization/software-unit-grants",
            headers={"Authorization": "Bearer test-operator-token"},
        )
    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_menu_and_sso_combination_http_surface(client) -> None:
    """Menu ABAC/RBAC and SSO combination decisions use stored grants."""
    client.put("/authorization/software-unit-grants/acme-naruon", json=SOFTWARE_GRANT)
    client.put(
        "/authorization/software-unit-grants/acme-clearfolio",
        json={
            **SOFTWARE_GRANT,
            "grant_key": "acme-clearfolio",
            "software_unit_id": "clearfolio-web",
        },
    )
    menu = client.put("/authorization/menu-grants/acme-naruon-invoices", json=MENU_GRANT)
    combo = client.put(
        "/authorization/sso-combination-scopes/finance-suite",
        json=COMBINATION,
    )
    allowed_menu = client.post(
        "/authorization/menus:decide",
        json={
            "snapshot": SNAPSHOT,
            "software_unit_id": "naruon-web",
            "menu_path": "/invoices/approve",
        },
    )
    denied_menu = client.post(
        "/authorization/menus:decide",
        json={
            "snapshot": {**SNAPSHOT, "request_attributes": {}},
            "software_unit_id": "naruon-web",
            "menu_path": "/invoices/approve",
        },
    )
    combo_decision = client.post(
        "/authorization/sso-combinations:decide",
        json={"snapshot": SNAPSHOT, "combination_name": "finance-suite"},
    )
    assert menu.status_code == 200
    assert combo.status_code == 200
    assert client.get("/authorization/menu-grants/acme-naruon-invoices").status_code == 200
    assert client.get("/authorization/sso-combination-scopes/finance-suite").status_code == 200
    assert client.get("/authorization/menu-grants").json()[0]["menu_path"] == "/invoices"
    assert client.get("/authorization/sso-combination-scopes").json()[0]["combination_name"] == (
        "finance-suite"
    )
    assert allowed_menu.json()["effect"] == "allow"
    assert allowed_menu.json()["capability_codes"] == ["menu.read", "menu.approve"]
    assert denied_menu.json()["decision_code"] == "attribute_mismatch"
    assert combo_decision.json()["effect"] == "allow"


def test_authorization_decisions_are_isolated_by_tenant(client) -> None:
    """Same paths and names remain separate across tenant deployments."""
    for tenant, effect in (("default-deployment", "allow"), ("other-deployment", "deny")):
        for software_unit_id in ("naruon-web", "clearfolio-web"):
            grant_key = f"{tenant.split('-')[0]}-{software_unit_id.split('-')[0]}"
            response = client.put(
                f"/authorization/software-unit-grants/{grant_key}",
                json={
                    **SOFTWARE_GRANT,
                    "grant_key": grant_key,
                    "tenant_deployment_id": tenant,
                    "software_unit_id": software_unit_id,
                    "effect_code": effect,
                },
            )
            assert response.status_code == 200
        response = client.put(
            "/authorization/sso-combination-scopes/finance-suite",
            json={**COMBINATION, "tenant_deployment_id": tenant},
        )
        assert response.status_code == 200

    listed = client.get("/authorization/sso-combination-scopes")
    default_decision = client.post(
        "/authorization/sso-combinations:decide",
        json={"snapshot": SNAPSHOT, "combination_name": "finance-suite"},
    )
    other_decision = client.post(
        "/authorization/sso-combinations:decide",
        json={
            "snapshot": {**SNAPSHOT, "tenant_deployment_id": "other-deployment"},
            "combination_name": "finance-suite",
        },
    )
    assert len(listed.json()) == 2
    assert client.get("/authorization/sso-combination-scopes/finance-suite").status_code == 409
    assert client.delete("/authorization/sso-combination-scopes/finance-suite").status_code == 409
    assert client.get(
        "/authorization/sso-combination-scopes/finance-suite"
        "?tenant_deployment_id=other-deployment"
    ).status_code == 200
    assert client.delete(
        "/authorization/sso-combination-scopes/finance-suite"
        "?tenant_deployment_id=other-deployment"
    ).status_code == 204
    assert default_decision.json()["effect"] == "allow"
    assert other_decision.json()["effect"] == "deny"


def test_authorization_plane_rejects_mismatches_duplicates_and_unknowns(client) -> None:
    """Path mismatches, duplicate identities, and missing keys fail closed."""
    mismatch = client.put(
        "/authorization/software-unit-grants/other-key",
        json=SOFTWARE_GRANT,
    )
    wrong_scope = client.put(
        "/authorization/software-unit-grants/acme-naruon-invoices",
        json=MENU_GRANT,
    )
    client.put("/authorization/software-unit-grants/acme-naruon", json=SOFTWARE_GRANT)
    duplicate = client.put(
        "/authorization/software-unit-grants/acme-naruon-dup",
        json={**SOFTWARE_GRANT, "grant_key": "acme-naruon-dup"},
    )
    missing = client.get("/authorization/software-unit-grants/missing-grant")
    missing_delete = client.delete("/authorization/software-unit-grants/missing-grant")
    combo_mismatch = client.put(
        "/authorization/sso-combination-scopes/other-name",
        json=COMBINATION,
    )
    missing_combo = client.get("/authorization/sso-combination-scopes/missing-combo")
    missing_combo_delete = client.delete(
        "/authorization/sso-combination-scopes/missing-combo"
    )
    menu_mismatch = client.put(
        "/authorization/menu-grants/other-menu",
        json=MENU_GRANT,
    )
    missing_menu = client.get("/authorization/menu-grants/missing-menu")
    missing_menu_delete = client.delete("/authorization/menu-grants/missing-menu")
    assert mismatch.status_code == 400
    assert wrong_scope.status_code == 400
    assert duplicate.status_code == 409
    assert missing.status_code == 404
    assert missing_delete.status_code == 404
    assert combo_mismatch.status_code == 400
    assert missing_combo.status_code == 404
    assert missing_combo_delete.status_code == 404
    assert menu_mismatch.status_code == 400
    assert missing_menu.status_code == 404
    assert missing_menu_delete.status_code == 404


def test_authorization_grants_with_same_identity_are_isolated_by_tenant(client) -> None:
    """Equivalent grant geometry is valid once per tenant deployment."""
    first = client.put(
        "/authorization/software-unit-grants/shared-grant",
        json={**SOFTWARE_GRANT, "grant_key": "shared-grant"},
    )
    second = client.put(
        "/authorization/software-unit-grants/shared-grant-other",
        json={
            **SOFTWARE_GRANT,
            "grant_key": "shared-grant-other",
            "tenant_deployment_id": "other-deployment",
        },
    )
    other_snapshot = {**SNAPSHOT, "tenant_deployment_id": "other-deployment"}
    decision = client.post(
        "/authorization/software-units:decide",
        json={"snapshot": other_snapshot, "software_unit_id": "naruon-web"},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert decision.json()["effect"] == "allow"


def test_ambiguous_tenant_identifiers_require_scoped_lookup(
    store: InMemoryKvStore,
) -> None:
    """Legacy identifier-only reads fail closed when tenants share a name."""
    service = AuthorizationPlaneService(store)
    service.put_software_unit_grant(
        "shared-grant",
        AuthorizationGrant.model_validate({**SOFTWARE_GRANT, "grant_key": "shared-grant"}),
    )
    service.put_software_unit_grant(
        "shared-grant",
        AuthorizationGrant.model_validate(
            {
                **SOFTWARE_GRANT,
                "grant_key": "shared-grant",
                "tenant_deployment_id": "other-deployment",
            }
        ),
    )
    service.put_combination(
        "shared-suite",
        SsoCombinationScope.model_validate(
            {**COMBINATION, "combination_name": "shared-suite"}
        ),
    )
    service.put_combination(
        "shared-suite",
        SsoCombinationScope.model_validate(
            {
                **COMBINATION,
                "combination_name": "shared-suite",
                "tenant_deployment_id": "other-deployment",
            }
        ),
    )
    with pytest.raises(Exception, match="tenant_deployment_id"):
        service.get_software_unit_grant("shared-grant")
    with pytest.raises(Exception, match="tenant_deployment_id"):
        service.get_combination("shared-suite")


def test_authorization_plane_delete_and_replace(client) -> None:
    """Deletes remove grants and combinations; replace keeps one identity."""
    client.put("/authorization/software-unit-grants/acme-naruon", json=SOFTWARE_GRANT)
    client.put("/authorization/menu-grants/acme-naruon-invoices", json=MENU_GRANT)
    client.put("/authorization/sso-combination-scopes/finance-suite", json=COMBINATION)
    replaced = client.put(
        "/authorization/software-unit-grants/acme-naruon",
        json={**SOFTWARE_GRANT, "effect_code": "deny"},
    )
    assert replaced.json()["effect_code"] == "deny"
    assert client.delete("/authorization/software-unit-grants/acme-naruon").status_code == 204
    assert client.delete("/authorization/menu-grants/acme-naruon-invoices").status_code == 204
    assert client.delete("/authorization/sso-combination-scopes/finance-suite").status_code == 204
    assert client.get("/authorization/software-unit-grants").json() == []


def test_corrupt_store_fails_closed_over_http(client, store: InMemoryKvStore) -> None:
    """Corrupt grant or combination rows never silently authorize over HTTP."""
    store.put(SOFTWARE_UNIT_GRANT_NAMESPACE, "broken", "{")
    store.put(MENU_GRANT_NAMESPACE, "broken-menu", "{")
    store.put(SSO_COMBINATION_NAMESPACE, "broken-combo", "{")
    assert client.get("/authorization/software-unit-grants").status_code == 500
    assert client.get("/authorization/menu-grants").status_code == 500
    assert client.get("/authorization/sso-combination-scopes").status_code == 500


def test_corrupt_store_fails_closed(store: InMemoryKvStore) -> None:
    """Corrupt grant or combination rows never silently authorize."""
    service = AuthorizationPlaneService(store)
    store.put(SOFTWARE_UNIT_GRANT_NAMESPACE, "broken", "{")
    store.put(MENU_GRANT_NAMESPACE, "broken-menu", "{")
    store.put(SSO_COMBINATION_NAMESPACE, "broken-combo", "{")
    with pytest.raises(Exception, match="corrupt"):
        service.list_software_unit_grants()
    with pytest.raises(Exception, match="corrupt"):
        service.list_menu_grants()
    with pytest.raises(Exception, match="corrupt"):
        service.list_combinations()


def test_authorization_service_missing_is_unavailable() -> None:
    """Unwired authorization routes fail closed with HTTP 503."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    with pytest.raises(HTTPException) as captured:
        get_authorization_service(request)
    assert captured.value.status_code == 503


def test_decision_endpoints_reject_invalid_snapshots(client) -> None:
    """Decision routes validate snapshots before consulting grants."""
    response = client.post(
        "/authorization/software-units:decide",
        json={
            "snapshot": {**SNAPSHOT, "org_path": "/org/acme"},
            "software_unit_id": "naruon-web",
        },
    )
    combo = client.post(
        "/authorization/sso-combinations:decide",
        json={"snapshot": SNAPSHOT, "combination_name": "missing-combo"},
    )
    menu = client.post(
        "/authorization/menus:decide",
        json={
            "snapshot": SNAPSHOT,
            "software_unit_id": "naruon-web",
            "menu_path": "invoices",
        },
    )
    assert response.status_code == 400
    assert combo.status_code == 404
    assert menu.status_code == 400


def test_direct_service_helpers_cover_getters(store: InMemoryKvStore) -> None:
    """Service getters and combination helpers are reachable without HTTP."""
    service = AuthorizationPlaneService(store)
    grant = AuthorizationGrant.model_validate(SOFTWARE_GRANT)
    menu = AuthorizationGrant.model_validate(MENU_GRANT)
    combination = SsoCombinationScope.model_validate(COMBINATION)
    service.put_software_unit_grant("acme-naruon", grant)
    service.put_menu_grant("acme-naruon-invoices", menu)
    service.put_combination("finance-suite", combination)
    service.put_combination(
        "other-suite",
        combination.model_copy(update={"combination_name": "other-suite"}),
    )
    assert service.get_software_unit_grant("acme-naruon").grant_key == "acme-naruon"
    assert service.get_menu_grant("acme-naruon-invoices").menu_path == "/invoices"
    assert service.get_combination("finance-suite").combination_name == "finance-suite"
    service.delete_combination("finance-suite")
