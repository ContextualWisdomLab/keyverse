"""Real SQLite menu decisions must not combine two committed grant generations."""
from __future__ import annotations

import threading
from collections.abc import Callable

import pytest

from app.authorization_plane import (
    MENU_GRANT_NAMESPACE,
    SOFTWARE_UNIT_GRANT_NAMESPACE,
    AuthorizationPlaneService,
    MenuDecisionRequest,
)
from app.kv_store import InMemoryKvStore, SqliteKvStore
from app.org_authorization import AssignmentSnapshot, AuthorizationGrant

NAMESPACES = (SOFTWARE_UNIT_GRANT_NAMESPACE, MENU_GRANT_NAMESPACE)
ROOT_PATH = "/group_company/fixture-company"
PERSON_PATH = ROOT_PATH + "/legal_entity/fixture-entity/business_unit/finance/team/review/person/p1"


def request() -> MenuDecisionRequest:
    """Build synthetic caller input, not verified issuer or membership evidence."""
    return MenuDecisionRequest(
        snapshot=AssignmentSnapshot(
            keyverse_subject="fixture-subject",
            tenant_deployment_id="fixture-deployment",
            org_path=PERSON_PATH,
            assignment_record_id="fixture-assignment",
            request_attributes={"purpose": "invoice-review"},
        ),
        software_unit_id="fixture-rp",
        menu_path="/invoices/approve",
    )


def grant(scope: str, effect: str) -> AuthorizationGrant:
    """Build a valid persisted ancestor grant with closed menu ABAC/RBAC."""
    return AuthorizationGrant(
        grant_key="fixture-" + scope.replace("_", "-"),
        tenant_deployment_id="fixture-deployment",
        grant_scope_code=scope,
        org_path=ROOT_PATH,
        software_unit_id="fixture-rp",
        menu_path="/invoices" if scope == "menu" else None,
        effect_code=effect,
        capability_codes=["menu.read", "menu.approve"] if scope == "menu" and effect == "allow" else [],
        attribute_constraints={"purpose": "invoice-review"} if scope == "menu" and effect == "allow" else {},
        actor_identity_id="fixture-operator",
    )


def seed(service: AuthorizationPlaneService, software_effect: str, menu_effect: str) -> None:
    """Persist both grants through the actual validated administration service."""
    software = grant("software_unit", software_effect)
    menu = grant("menu", menu_effect)
    service.put_software_unit_grant(software.grant_key, software)
    service.put_menu_grant(menu.grant_key, menu)


def replace_generation(writer: SqliteKvStore, software_effect: str, menu_effect: str) -> None:
    """Commit both synthetic namespaces in one actual second-connection transaction."""
    with writer._lock, writer._connection:
        for namespace, scope, effect in zip(NAMESPACES, ("software_unit", "menu"), (software_effect, menu_effect)):
            value = grant(scope, effect)
            writer._connection.execute(
                "UPDATE idp_config_entries SET entry_value = ? "
                "WHERE config_namespace = ? AND entry_key = ?",
                (value.model_dump_json(), namespace, "fixture-deployment::" + value.grant_key),
            )


class ReadBoundaryStore(SqliteKvStore):
    """Pause only after a real read; no row, SQL, or PDP result is substituted."""

    def __init__(self, database_path: str) -> None:
        """Open the canonical store with a one-shot deterministic boundary hook."""
        super().__init__(database_path)
        self.after_read: Callable[[], None] | None = None

    def _release_writer(self) -> None:
        """Release the writer once and wait for its actual committed transaction."""
        if self.after_read is not None:
            callback, self.after_read = self.after_read, None
            callback()

    def get_all(self, namespace: str) -> dict[str, str]:
        """Read unchanged SQL before pausing at the legacy read boundary."""
        values = super().get_all(namespace)
        self._release_writer()
        return values

    def get_all_namespaces(self, namespaces: tuple[str, ...]) -> dict[str, dict[str, str]]:
        """Read the proposed canonical seam before pausing at its read boundary."""
        values = super().get_all_namespaces(namespaces)
        self._release_writer()
        return values


def test_menu_never_allows_torn_denied_generations(tmp_path) -> None:
    """Before and after deny; a legacy software-before/menu-after pair falsely allows."""
    path = str(tmp_path / "authorization_grants.sqlite3")
    reader = ReadBoundaryStore(path)
    writer = SqliteKvStore(path)
    release, committed = threading.Event(), threading.Event()
    errors: list[BaseException] = []
    service = AuthorizationPlaneService(reader)
    assert reader._connection is not writer._connection
    assert reader._lock is not writer._lock

    def cutover() -> None:
        """Execute an independently connected real transaction after read release."""
        try:
            assert release.wait(5), "reader never reached the read boundary"
            replace_generation(writer, "deny", "allow")
        except BaseException as exc:
            errors.append(exc)
        finally:
            committed.set()

    def wait_for_commit() -> None:
        """Hold the reader until the competing connection has actually committed."""
        release.set()
        assert committed.wait(5), "writer transaction did not settle"
        assert not errors, errors

    worker = threading.Thread(target=cutover, name="fixture-grant-cutover")
    try:
        seed(service, "allow", "deny")
        before = service.decide_menu(request())
        assert before.effect == "deny"
        assert before.decision_code == "inherited_deny"
        reader.after_read = wait_for_commit
        worker.start()
        raced = service.decide_menu(request())
        after = service.decide_menu(request())
        worker.join(5)
        assert not worker.is_alive()
        assert not errors, errors
        assert after.effect == "deny"
        assert after.decision_code == "software_unit_denied"
        print({"before": before.model_dump(mode="json"), "raced": raced.model_dump(mode="json"), "after": after.model_dump(mode="json"), "actual_second_connection_commit": committed.is_set()})
        assert raced.effect == "deny", "torn software-before/menu-after grants falsely authorized"
        assert raced.capability_codes == []
    finally:
        release.set()
        if worker.ident is not None:
            worker.join(5)
        reader.close()
        writer.close()


def test_memory_menu_keeps_valid_allow_and_closed_namespaces() -> None:
    """The other canonical backend supports the same coherent composition contract."""
    store = InMemoryKvStore()
    service = AuthorizationPlaneService(store)
    seed(service, "allow", "allow")
    store.put("fixture_unrequested_namespace", "broken", "{")
    decision = service.decide_menu(request())
    assert decision.effect == "allow"
    assert decision.capability_codes == ["menu.read", "menu.approve"]
    values = store.get_all_namespaces((*NAMESPACES, NAMESPACES[0], "fixture_absent_namespace"))
    assert set(values) == {*NAMESPACES, "fixture_absent_namespace"}
    assert values["fixture_absent_namespace"] == {}
    assert values[NAMESPACES[0]] == store.get_all(NAMESPACES[0])
    values[NAMESPACES[0]].clear()
    assert store.get_all(NAMESPACES[0])
    assert store.get_all_namespaces(()) == {}


def test_menu_preserves_legacy_grant_key_order() -> None:
    """Equal-geometry raw rows retain the existing sorted-list tie order."""
    store = InMemoryKvStore()
    service = AuthorizationPlaneService(store)
    seed(service, "allow", "allow")
    original = grant("menu", "allow")
    later = original.model_copy(update={"grant_key": "z-fixture-menu", "capability_codes": ["menu.later"]})
    earlier = original.model_copy(update={"grant_key": "a-fixture-menu", "capability_codes": ["menu.earlier"]})
    store.delete(MENU_GRANT_NAMESPACE, "fixture-deployment::" + original.grant_key)
    for value in (later, earlier):
        store.put(MENU_GRANT_NAMESPACE, "fixture-deployment::" + value.grant_key, value.model_dump_json())
    assert service.list_menu_grants() == [earlier, later]
    assert service.decide_menu(request()).capability_codes == ["menu.earlier"]


def test_memory_snapshot_copies_seed_entries() -> None:
    """The existing seed-copy behavior also remains detached from input mutation."""
    source = {"fixture_seed_namespace": {"fixture-entry": "original"}}
    store = InMemoryKvStore(source)
    source["fixture_seed_namespace"]["fixture-entry"] = "changed"
    assert store.get_all_namespaces(("fixture_seed_namespace",)) == {
        "fixture_seed_namespace": {"fixture-entry": "original"},
    }


@pytest.fixture(params=["sqlite", "memory"])
def backend(request, tmp_path):
    """Provide actual canonical stores with owned resource cleanup."""
    store = SqliteKvStore(str(tmp_path / "fixture_store.sqlite3")) if request.param == "sqlite" else InMemoryKvStore()
    try:
        yield store
    finally:
        store.close()


def test_otherwise_valid_menu_allow_survives_coherent_read(backend) -> None:
    """A nonempty positive guards against repairing the race by denying everyone."""
    service = AuthorizationPlaneService(backend)
    seed(service, "allow", "allow")
    allowed = service.decide_menu(request())
    assert allowed.effect == "allow"
    assert allowed.decision_code == "inherited_allow"
    assert allowed.capability_codes == ["menu.read", "menu.approve"]
    assert allowed.winning_org_path == ROOT_PATH
    assert allowed.winning_menu_path == "/invoices"
    assert allowed.pep_enforcement_required is True
    mismatch = request()
    mismatch.snapshot.request_attributes = {"purpose": "other-purpose"}
    assert service.decide_menu(mismatch).decision_code == "attribute_mismatch"
    wrong_tenant = request()
    wrong_tenant.snapshot.tenant_deployment_id = "other-deployment"
    assert service.decide_menu(wrong_tenant).effect == "deny"


@pytest.mark.parametrize("namespace", NAMESPACES)
def test_captured_corrupt_row_fails_closed_before_pdp(backend, namespace) -> None:
    """A corrupt row must never disappear behind an otherwise valid allowed pair."""
    from app.errors import AuthorizationPolicyError

    service = AuthorizationPlaneService(backend)
    seed(service, "allow", "allow")
    backend.put(namespace, "fixture-broken-row", "{")
    with pytest.raises(AuthorizationPolicyError, match="authorization grant store is corrupt") as caught:
        service.decide_menu(request())
    assert caught.value.status_code == 500


@pytest.mark.parametrize("namespace", NAMESPACES)
def test_semantically_invalid_row_still_fails_closed(backend, namespace) -> None:
    """Syntactically valid but closed-policy-invalid rows remain errors."""
    from app.errors import AuthorizationPolicyError

    service = AuthorizationPlaneService(backend)
    seed(service, "allow", "allow")
    invalid = grant("menu", "allow").model_copy(update={"effect_code": "unknown"})
    backend.put(namespace, "fixture-invalid-row", invalid.model_dump_json())
    with pytest.raises(AuthorizationPolicyError, match="effect_code must be allow or deny"):
        service.decide_menu(request())


def test_unchanged_single_namespace_store_operations(backend) -> None:
    """Legacy single-namespace reads/writes retain their exact raw-string contract."""
    namespace = "fixture_config_namespace"
    backend.put(namespace, "fixture-entry", "unchanged\x00값")
    backend.put_many(namespace, {"fixture-second": "two", "fixture-third": "three"})
    backend.replace_many(namespace, {"fixture-second": "updated"}, ["fixture-third", "absent"])
    assert backend.get(namespace, "fixture-entry") == "unchanged\x00값"
    assert backend.get(namespace, "absent") is None
    assert backend.get_all(namespace) == {"fixture-entry": "unchanged\x00값", "fixture-second": "updated"}
    values = backend.get_all(namespace)
    values.clear()
    assert backend.get_all(namespace)
    backend.delete(namespace, "fixture-entry")
    backend.delete(namespace, "absent")
    assert backend.get_all(namespace) == {"fixture-second": "updated"}
    assert backend.get_all("fixture_absent_namespace") == {}


def test_sqlite_closed_snapshot_query_preserves_literal_names_and_values(tmp_path) -> None:
    """One bound SELECT excludes unrequested rows; duplicates and empty are defined."""
    store = SqliteKvStore(str(tmp_path / "fixture_literal_store.sqlite3"))
    namespace = "fixture_namespace') OR 1=1 --"
    statements: list[str] = []
    try:
        store.put(namespace, "fixture-key", "literal\x00값")
        store.put("fixture_unrequested_namespace", "fixture-key", "unrequested")
        store._connection.set_trace_callback(statements.append)
        values = store.get_all_namespaces((namespace, namespace, "fixture_absent_namespace"))
        assert values == {namespace: {"fixture-key": "literal\x00값"}, "fixture_absent_namespace": {}}
        assert len(statements) == 1
        assert statements[0].startswith("SELECT config_namespace, entry_key, entry_value")
        assert " IN (" in statements[0]
        values[namespace].clear()
        assert store.get(namespace, "fixture-key") == "literal\x00값"
        statements.clear()
        assert store.get_all_namespaces(()) == {}
        assert statements == []
    finally:
        store.close()


def test_sqlite_snapshot_is_coherent_when_other_connection_commits_during_fetch(tmp_path) -> None:
    """WAL allows a real independent commit while the SELECT continues fetching."""
    path = str(tmp_path / "fixture_scan_store.sqlite3")
    reader, writer = SqliteKvStore(path), SqliteKvStore(path)
    service = AuthorizationPlaneService(reader)
    seen: list[str] = []
    commits: list[bool] = []

    def row_boundary(cursor, row):
        """Return each untouched native row, committing once after the first is read."""
        seen.append(row[0])
        if len(seen) == 1:
            replace_generation(writer, "deny", "allow")
            assert not writer._connection.in_transaction
            commits.append(True)
        return row

    try:
        seed(service, "allow", "deny")
        reader._connection.row_factory = row_boundary
        captured = reader.get_all_namespaces(NAMESPACES)
        reader._connection.row_factory = None
        assert commits == [True]
        assert set(seen) == set(NAMESPACES)
        assert AuthorizationGrant.model_validate_json(next(iter(captured[NAMESPACES[0]].values()))).effect_code == "allow"
        assert AuthorizationGrant.model_validate_json(next(iter(captured[NAMESPACES[1]].values()))).effect_code == "deny"
        assert service.decide_menu(request()).decision_code == "software_unit_denied"
    finally:
        reader._connection.row_factory = None
        reader.close()
        writer.close()


def test_coherent_revocation_applies_to_next_decision_not_already_captured_one(tmp_path) -> None:
    """An old coherent allow is not an operation-revocation guarantee."""
    path = str(tmp_path / "fixture_revocation_store.sqlite3")
    reader, writer = ReadBoundaryStore(path), SqliteKvStore(path)
    service = AuthorizationPlaneService(reader)
    try:
        seed(service, "allow", "allow")
        reader.after_read = lambda: replace_generation(writer, "deny", "deny")
        captured = service.decide_menu(request())
        assert captured.effect == "allow"
        assert captured.capability_codes == ["menu.read", "menu.approve"]
        current = service.decide_menu(request())
        assert current.effect == "deny"
        assert current.decision_code == "software_unit_denied"
        assert current.capability_codes == []
    finally:
        reader.close()
        writer.close()


def test_single_namespace_service_paths_remain_independent(backend) -> None:
    """A software decision still reads only software grants, with sorted list/get behavior."""
    from app.authorization_plane import SoftwareUnitDecisionRequest

    service = AuthorizationPlaneService(backend)
    seed(service, "allow", "allow")
    backend.put(MENU_GRANT_NAMESPACE, "fixture-broken-menu", "{")
    software = service.decide_software_unit(SoftwareUnitDecisionRequest(
        snapshot=request().snapshot, software_unit_id="fixture-rp",
    ))
    assert software.effect == "allow"
    assert service.list_software_unit_grants() == [grant("software_unit", "allow")]
    assert service.get_software_unit_grant("fixture-software-unit") == grant("software_unit", "allow")
    service.delete_software_unit_grant("fixture-software-unit")
    assert service.list_software_unit_grants() == []
    assert service.decide_software_unit(SoftwareUnitDecisionRequest(
        snapshot=request().snapshot, software_unit_id="fixture-rp",
    )).effect == "deny"


def test_corrupt_menu_cannot_be_skipped_even_when_software_denies(backend) -> None:
    """All captured rows are parsed, rather than bypassed by an early PDP deny."""
    from app.errors import AuthorizationPolicyError

    service = AuthorizationPlaneService(backend)
    seed(service, "deny", "allow")
    backend.put(MENU_GRANT_NAMESPACE, "fixture-broken-menu", "{")
    with pytest.raises(AuthorizationPolicyError, match="authorization grant store is corrupt"):
        service.decide_menu(request())
