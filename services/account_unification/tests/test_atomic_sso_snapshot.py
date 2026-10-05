"""Real SQLite and ASGI regression for coherent SSO definition/software grants.

Synthetic operator and assignment inputs exercise the canonical router/service/PDP,
not deployed HTTP, authoritative membership, or relying-party enforcement.
"""
from __future__ import annotations

import json
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.authorization_plane import (
    SOFTWARE_UNIT_GRANT_NAMESPACE,
    SSO_COMBINATION_NAMESPACE,
    AuthorizationPlaneService,
    authorization_router,
)
from app.kv_store import InMemoryKvStore, SqliteKvStore
from app.org_authorization import AuthorizationGrant, SsoCombinationScope

TENANT = "fixture-deployment"
ROOT_PATH = "/group_company/fixture"
SNAPSHOT = {
    "keyverse_subject": "fixture-subject-77",
    "tenant_deployment_id": TENANT,
    "org_path": ROOT_PATH + "/legal_entity/fixture/business_unit/sales/team/alpha/person/person-77",
    "assignment_record_id": "fixture-assignment-77",
    "request_attributes": {},
}
NAMESPACES = (SSO_COMBINATION_NAMESPACE, SOFTWARE_UNIT_GRANT_NAMESPACE)


def grant(unit: str, effect: str) -> AuthorizationGrant:
    """Build a valid software grant for the synthetic tenant."""
    return AuthorizationGrant(
        grant_key=unit, tenant_deployment_id=TENANT,
        grant_scope_code="software_unit", org_path=ROOT_PATH,
        software_unit_id=unit, effect_code=effect,
        actor_identity_id="fixture-operator",
    )


def combination(member: str) -> SsoCombinationScope:
    """Build an ordinary two-member suite satisfying the canonical 2–16 contract."""
    return SsoCombinationScope(
        combination_name="fixture-suite", tenant_deployment_id=TENANT,
        software_unit_ids=[member, "common-web"], actor_identity_id="fixture-operator",
    )


def replace_version(writer: SqliteKvStore, member: str, naruon: str, clearfolio: str) -> None:
    """Commit the complete definition and grants in one second-connection transaction."""
    values = [
        (SSO_COMBINATION_NAMESPACE, TENANT + "::fixture-suite", combination(member).model_dump_json()),
        *[(SOFTWARE_UNIT_GRANT_NAMESPACE, TENANT + "::" + unit, grant(unit, effect).model_dump_json())
          for unit, effect in (("naruon-web", naruon), ("clearfolio-web", clearfolio), ("common-web", "allow"))],
    ]
    with writer._lock, writer._connection:
        writer._connection.executemany(
            "INSERT INTO idp_config_entries(config_namespace,entry_key,entry_value) VALUES(?,?,?) "
            "ON CONFLICT(config_namespace,entry_key) DO UPDATE SET entry_value=excluded.entry_value",
            values,
        )
    assert not writer._connection.in_transaction


@pytest.fixture
def sqlite_plane(tmp_path):
    """Provide actual ASGI routing and two distinct canonical SQLite connections."""
    path = str(tmp_path / "sso_authorization.sqlite3")
    reader, writer = SqliteKvStore(path), SqliteKvStore(path)
    assert reader._connection is not writer._connection
    assert reader._lock is not writer._lock
    service = AuthorizationPlaneService(reader)
    app = FastAPI()
    app.state.operator_api_token = "fixture-operator-only"
    app.state.authorization_service = service
    app.include_router(authorization_router)
    try:
        replace_version(writer, "naruon-web", "deny", "allow")
        with TestClient(app, headers={"Authorization": "Bearer fixture-operator-only"}) as client:
            yield reader, writer, service, client
    finally:
        writer.close()
        reader.close()


def decide(client: TestClient, label: str) -> dict:
    """Invoke the real authenticated route and retain its entire response in the log."""
    response = client.post(
        "/authorization/sso-combinations:decide",
        json={"snapshot": SNAPSHOT, "combination_name": "fixture-suite"},
    )
    print(json.dumps({"label": label, "http_status": response.status_code, "body": response.json()}))
    assert response.status_code == 200
    return response.json()


def test_complete_before_and_after_versions_both_deny(sqlite_plane) -> None:
    """Neither complete committed generation authorizes the named suite."""
    _, writer, _, client = sqlite_plane
    before = decide(client, "complete-before")
    replace_version(writer, "clearfolio-web", "allow", "deny")
    after = decide(client, "complete-after")
    assert before["effect"] == after["effect"] == "deny"
    assert [item["software_unit_id"] for item in before["member_decisions"]] == ["naruon-web", "common-web"]
    assert [item["software_unit_id"] for item in after["member_decisions"]] == ["clearfolio-web", "common-web"]


def test_stable_authorized_positive(sqlite_plane) -> None:
    """A nonempty complete authorized suite stays allowed by the unchanged PDP."""
    _, writer, _, client = sqlite_plane
    replace_version(writer, "naruon-web", "allow", "deny")
    body = decide(client, "stable-positive")
    assert body["effect"] == "allow"
    assert body["pep_enforcement_required"] is True
    assert len(body["member_decisions"]) == 2
    assert all(item["effect"] == "allow" for item in body["member_decisions"])


def test_definition_and_grants_never_form_an_uncommitted_allow(sqlite_plane, monkeypatch) -> None:
    """After real definition capture, a real commit must not produce a torn Allow."""
    reader, writer, _, client = sqlite_plane
    before = decide(client, "coherent-before")
    release, committed = threading.Event(), threading.Event()
    errors: list[BaseException] = []
    boundaries: list[str] = []
    original_single = reader.get_all
    original_atomic = reader.get_all_namespaces

    def cutover() -> None:
        """Wait for the real read boundary, then commit the complete after generation."""
        try:
            assert release.wait(5), "real read boundary never released writer"
            replace_version(writer, "clearfolio-web", "allow", "deny")
        except BaseException as exc:
            errors.append(exc)
        finally:
            committed.set()

    def after_capture(boundary: str) -> None:
        """Hold the reader after persisted rows are copied until the commit settles."""
        if not release.is_set():
            boundaries.append(boundary)
            release.set()
            assert committed.wait(5), "independent writer did not settle"
            assert not errors, errors

    def single_read(namespace):
        """Return untouched actual legacy rows and release at definition capture."""
        values = original_single(namespace)
        if namespace == SSO_COMBINATION_NAMESPACE:
            after_capture("legacy-get_all")
        return values

    def atomic_read(namespaces):
        """Return untouched actual atomic rows with the same post-read release schedule."""
        values = original_atomic(namespaces)
        if SSO_COMBINATION_NAMESPACE in namespaces:
            assert set(values) == set(NAMESPACES)
            after_capture("atomic-get_all_namespaces")
        return values

    monkeypatch.setattr(reader, "get_all", single_read)
    monkeypatch.setattr(reader, "get_all_namespaces", atomic_read)
    worker = threading.Thread(target=cutover, name="fixture-sso-cutover")
    worker.start()
    try:
        raced = decide(client, "definition-captured-then-commit")
        after = decide(client, "fresh-after")
        worker.join(5)
        assert not worker.is_alive()
        assert not errors, errors
        assert committed.is_set() and len(boundaries) == 1
        assert before["effect"] == after["effect"] == "deny"
        assert [item["software_unit_id"] for item in after["member_decisions"]] == ["clearfolio-web", "common-web"]
        print(json.dumps({"actual_second_connection_commit": committed.is_set(), "read_boundary": boundaries}))
        assert raced["effect"] == "deny", "Neither committed generation allows; torn definition/grants falsely authorized"
        assert raced == before
    finally:
        release.set()
        worker.join(5)
        assert not worker.is_alive(), "owned writer must settle before fixture cleanup"


@pytest.fixture(params=["sqlite", "memory"])
def backend_plane(request, tmp_path):
    """Characterize both canonical backends through the real authenticated router."""
    store = (SqliteKvStore(str(tmp_path / "sso_compatibility.sqlite3"))
             if request.param == "sqlite" else InMemoryKvStore())
    service = AuthorizationPlaneService(store)
    app = FastAPI()
    app.state.operator_api_token = "fixture-operator-only"
    app.state.authorization_service = service
    app.include_router(authorization_router)
    try:
        for unit in ("naruon-web", "common-web"):
            value = grant(unit, "allow")
            service.put_software_unit_grant(value.grant_key, value)
        service.put_combination("fixture-suite", combination("naruon-web"))
        with TestClient(app, headers={"Authorization": "Bearer fixture-operator-only"}) as client:
            yield store, service, client
    finally:
        store.close()


@pytest.mark.parametrize("namespace", NAMESPACES)
@pytest.mark.parametrize("corruption", ["json", "semantic"])
def test_all_captured_rows_validate_before_pdp(backend_plane, namespace, corruption, monkeypatch) -> None:
    """Unrelated corrupt rows still reject, even when the selected suite would deny."""
    store, service, client = backend_plane
    denied = grant("naruon-web", "deny")
    service.put_software_unit_grant(denied.grant_key, denied)
    if corruption == "json":
        raw, status = "{", 500
    else:
        value = (combination("naruon-web").model_copy(update={
            "combination_name": "other-suite", "tenant_deployment_id": "other-deployment",
            "software_unit_ids": ["naruon-web"],
        }) if namespace == SSO_COMBINATION_NAMESPACE else grant("clearfolio-web", "allow").model_copy(update={
            "tenant_deployment_id": "other-deployment", "org_path": "/org/invalid",
        }))
        raw, status = value.model_dump_json(), 400
    store.put(namespace, "fixture-unrelated-corrupt-row", raw)
    calls = []
    from app import authorization_plane
    original = authorization_plane.decide_sso_combination

    def observe_pdp(*args, **kwargs):
        """Observe calls without changing the canonical decision function."""
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(authorization_plane, "decide_sso_combination", observe_pdp)
    response = client.post("/authorization/sso-combinations:decide",
                           json={"snapshot": SNAPSHOT, "combination_name": "fixture-suite"})
    assert response.status_code == status
    assert not calls, "captured row rejection must precede the unchanged PDP"


def test_tenant_name_selection_and_ambiguity_compatibility(backend_plane) -> None:
    """Select validated body identity, keep cross-tenant isolation, and preserve 404/409."""
    store, service, client = backend_plane
    store.delete(SSO_COMBINATION_NAMESPACE, TENANT + "::fixture-suite")
    store.put(SSO_COMBINATION_NAMESPACE, "noncanonical-own-key", combination("naruon-web").model_dump_json())
    other = combination("clearfolio-web").model_copy(update={"tenant_deployment_id": "other-deployment"})
    store.put(SSO_COMBINATION_NAMESPACE, "noncanonical-other-key", other.model_dump_json())
    assert decide(client, "tenant-qualified-positive")["effect"] == "allow"
    other_response = client.post("/authorization/sso-combinations:decide", json={
        "snapshot": {**SNAPSHOT, "tenant_deployment_id": "other-deployment"},
        "combination_name": "fixture-suite",
    })
    assert other_response.status_code == 200
    assert other_response.json()["effect"] == "deny"
    assert client.get("/authorization/sso-combination-scopes/fixture-suite").status_code == 409
    assert client.get("/authorization/sso-combination-scopes/fixture-suite",
                      params={"tenant_deployment_id": TENANT}).status_code == 200
    assert client.delete("/authorization/sso-combination-scopes/fixture-suite").status_code == 409
    missing = client.post("/authorization/sso-combinations:decide", json={
        "snapshot": SNAPSHOT, "combination_name": "missing-suite",
    })
    assert missing.status_code == 404
    assert missing.json()["detail"] == "sso combination is not registered"
    # A different physical key cannot make a duplicate validated identity unambiguous.
    store.put(SSO_COMBINATION_NAMESPACE, "duplicate-physical-key", combination("naruon-web").model_dump_json())
    ambiguous = client.post("/authorization/sso-combinations:decide", json={
        "snapshot": SNAPSHOT, "combination_name": "fixture-suite",
    })
    assert ambiguous.status_code == 409
    assert ambiguous.json()["detail"] == "tenant_deployment_id is required for an ambiguous sso combination"
    assert client.get("/authorization/sso-combination-scopes/fixture-suite",
                      params={"tenant_deployment_id": TENANT}).status_code == 409
    with pytest.raises(Exception, match="tenant_deployment_id"):
        service.get_combination("fixture-suite", tenant_deployment_id=TENANT)


def test_sso_preserves_sorted_grant_tie_order(backend_plane) -> None:
    """Equal-geometry legacy rows retain grant-key order, not insertion order."""
    store, _, client = backend_plane
    store.delete(SOFTWARE_UNIT_GRANT_NAMESPACE, TENANT + "::naruon-web")
    for key, capability in (("z-later", "software.later"), ("a-earlier", "software.earlier")):
        value = grant("naruon-web", "allow").model_copy(update={
            "grant_key": key, "capability_codes": [capability],
        })
        store.put(SOFTWARE_UNIT_GRANT_NAMESPACE, TENANT + "::" + key, value.model_dump_json())
    body = decide(client, "legacy-sorted-positive")
    assert body["effect"] == "allow"
    assert body["member_decisions"][0]["capability_codes"] == ["software.earlier"]


def test_invalid_name_is_rejected_before_store_read(backend_plane, monkeypatch) -> None:
    """Keep original slug validation precedence without weakening the store contract."""
    store, _, client = backend_plane
    calls = []
    original = store.get_all_namespaces

    def observe_read(namespaces):
        """Observe a real read if validation mistakenly permits it."""
        calls.append(True)
        return original(namespaces)

    monkeypatch.setattr(store, "get_all_namespaces", observe_read)
    response = client.post("/authorization/sso-combinations:decide", json={
        "snapshot": SNAPSHOT, "combination_name": "invalid suite",
    })
    assert response.status_code == 400
    assert not calls


def test_captured_allow_is_not_admitted_work_revocation(sqlite_plane, monkeypatch) -> None:
    """An already captured coherent allow may return after commit; a fresh read denies."""
    reader, writer, _, client = sqlite_plane
    replace_version(writer, "naruon-web", "allow", "deny")
    before = decide(client, "before-revocation")
    original = reader.get_all_namespaces
    commits = []

    def capture_then_revoke(namespaces):
        """Commit after untouched persisted raw rows are copied, once only."""
        values = original(namespaces)
        if not commits:
            replace_version(writer, "clearfolio-web", "allow", "deny")
            commits.append(True)
        return values

    monkeypatch.setattr(reader, "get_all_namespaces", capture_then_revoke)
    raced = decide(client, "captured-allow-after-revocation")
    after = decide(client, "next-fresh-decision")
    assert commits == [True]
    assert raced == before and raced["effect"] == "allow"
    assert after["effect"] == "deny"
