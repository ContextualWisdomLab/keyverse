"""Independent PAT lifecycle races with real storage and transparent barriers."""
import threading

import pytest

from app.application_tokens import (
    APPLICATION_TOKEN_NAMESPACE,
    ApplicationTokenIssueRequest,
    ApplicationTokenService,
    ApplicationTokenVerifyRequest,
)
from app.audit import AuditLogger, InMemoryAuditSink
from app.errors import AuthorizationPolicyError
from app.kv_store import InMemoryKvStore, SqliteKvStore


@pytest.fixture(params=["memory", "sqlite"])
def pair(request, tmp_path):
    """Use shared memory or two actual SQLite connections, never two databases."""
    if request.param == "memory":
        store = InMemoryKvStore()
        stores = [store, store]
    else:
        stores = [SqliteKvStore(str(tmp_path / "pat.sqlite3")) for _ in range(2)]
        assert stores[0]._connection is not stores[1]._connection
    services = [ApplicationTokenService(s, AuditLogger(InMemoryAuditSink()),
                                        clock=lambda: 1_700_000_000.0) for s in stores]
    yield stores, services
    for store in set(stores):
        store.close()


def issue_request():
    """Return a realistic tenant-bound machine credential request."""
    return ApplicationTokenIssueRequest(
        tenant_deployment_id="fixture-deployment", software_unit_id="fixture-rp",
        purpose_code="machine_api", capability_codes=["api.read"],
        lifetime_seconds=3600, actor_identity_id="fixture-operator",
    )


def active(service, issued):
    """Verify the actual synthetic secret without including it in diagnostics."""
    return service.verify(ApplicationTokenVerifyRequest(
        presented_token=issued.plaintext_token,
        tenant_deployment_id="fixture-deployment", software_unit_id="fixture-rp",
    )).active


def test_two_rotations_have_one_active_successor(pair, monkeypatch):
    """Both mint barriers fire; one conditional pair write loses with HTTP409."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    assert active(services[1], issued)
    barrier = threading.Barrier(2, timeout=5)
    results, errors, reached = [], [], []
    for service in services:
        original = service._mint

        def mint(request, *, replaced_token_id, original=original):
            record, plaintext = original(request, replaced_token_id=replaced_token_id)
            reached.append(record.application_token_id)
            barrier.wait()
            return record, plaintext

        monkeypatch.setattr(service, "_mint", mint)

    def rotate(service):
        try:
            results.append(service.rotate(issued.application_token_id, issue_request()))
        except Exception as error:
            errors.append(error)

    workers = [threading.Thread(target=rotate, args=(service,)) for service in services]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(7)
        assert not any(worker.is_alive() for worker in workers)
        assert len(reached) == 2, "the original after-mint schedule must remain enabled"
        assert len(results) == 1, "one predecessor produced multiple successful successors"
        assert len(errors) == 1 and isinstance(errors[0], AuthorizationPolicyError)
        assert errors[0].status_code == 409
        assert sum(active(services[0], result) for result in results) == 1
        assert not active(services[0], issued)
        assert len(stores[0].get_all(APPLICATION_TOKEN_NAMESPACE)) == 2
    finally:
        barrier.abort()
        for worker in workers:
            worker.join(7)


def test_rotation_audit_failure_preserves_completed_successor_revoke(pair, monkeypatch):
    """Audit runs after commit; another connection can revoke without deadlock."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    failure = RuntimeError("fixture audit unavailable")
    completed = []

    def audit_failure(_event, _actor, record, *, predecessor=None):
        completed.append(services[1].revoke(
            record.application_token_id, actor_identity_id="independent-operator",
        ))
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].rotate(issued.application_token_id, issue_request())
    assert error.value is failure
    assert len(completed) == 1
    assert not active(services[1], issued), "compensation revived the predecessor"
    assert services[1].get_token(completed[0].application_token_id).lifecycle_status_code == "revoked"
    assert all(view.lifecycle_status_code != "active" for view in services[1].list_tokens())


def test_rotation_audit_failure_preserves_completed_successor_rotation(pair, monkeypatch):
    """An independently completed second rotation remains valid after old audit fails."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    failure = RuntimeError("fixture audit unavailable")
    next_tokens = []

    def audit_failure(_event, _actor, record, *, predecessor=None):
        next_tokens.append(services[1].rotate(record.application_token_id, issue_request()))
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].rotate(issued.application_token_id, issue_request())
    assert error.value is failure
    assert not active(services[1], issued)
    assert active(services[1], next_tokens[0])
    assert len([view for view in services[1].list_tokens() if view.lifecycle_status_code == "active"]) == 1


def test_compensation_conflict_removes_still_owned_successor_without_restore(pair, monkeypatch):
    """Changed predecessor rejects pair rollback, but never strands an owned active successor."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    failure = RuntimeError("fixture audit unavailable")
    completed = []

    def audit_failure(_event, _actor, successor, *, predecessor=None):
        # A separate recovery writes a new conservative revoked generation.
        from app.application_tokens import ApplicationTokenRecord
        raw = stores[1].get(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id)
        retired = ApplicationTokenRecord.model_validate_json(raw)
        changed = retired.model_copy(update={
            "lifecycle_status_code": "revoked", "lifecycle_generation_id": "independent-recovery",
        })
        assert stores[1].compare_and_replace(
            APPLICATION_TOKEN_NAMESPACE, {issued.application_token_id: raw},
            {issued.application_token_id: changed.model_dump_json()},
        )
        completed.append(changed.model_dump_json())
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].rotate(issued.application_token_id, issue_request())
    assert error.value is failure
    assert stores[1].get(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id) == completed[0]
    assert len(stores[1].get_all(APPLICATION_TOKEN_NAMESPACE)) == 1
    assert not active(services[1], issued)


def test_revoke_stale_snapshot_cannot_overwrite_completed_rotation(pair, monkeypatch):
    """A revoke captured before another rotation must conflict before auditing."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    original = services[0]._require_record
    replacement = []

    def captured(token_id):
        record = original(token_id)
        replacement.append(services[1].rotate(token_id, issue_request()))
        return record

    monkeypatch.setattr(services[0], "_require_record", captured)
    with pytest.raises(AuthorizationPolicyError) as error:
        services[0].revoke(issued.application_token_id, actor_identity_id="fixture-operator")
    assert error.value.status_code == 409
    assert services[1].get_token(issued.application_token_id).lifecycle_status_code == "rotated"
    assert active(services[1], replacement[0])


def test_issue_failure_does_not_delete_completed_independent_revoke(pair, monkeypatch):
    """The completed security retirement survives failed issue compensation."""
    stores, services = pair
    completed = []
    failure = RuntimeError("fixture audit unavailable")

    def audit_failure(_event, _actor, record, *, predecessor=None):
        completed.append(services[1].revoke(
            record.application_token_id, actor_identity_id="independent-operator",
        ))
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].issue(issue_request())
    assert error.value is failure
    assert services[1].get_token(completed[0].application_token_id).lifecycle_status_code == "revoked"


def test_revoke_before_rotation_commit_is_conflict_without_audit(pair, monkeypatch):
    """The after-mint hook remains live; completed revoke wins before pair CAS."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    original = services[0]._mint
    completed, audit_calls = [], []

    def mint(request, *, replaced_token_id):
        result = original(request, replaced_token_id=replaced_token_id)
        completed.append(services[1].revoke(
            replaced_token_id, actor_identity_id="independent-operator",
        ))
        return result

    monkeypatch.setattr(services[0], "_mint", mint)
    monkeypatch.setattr(services[0], "_audit_event", lambda *args: audit_calls.append(args[0]))
    with pytest.raises(AuthorizationPolicyError) as error:
        services[0].rotate(issued.application_token_id, issue_request())
    assert error.value.status_code == 409
    assert len(completed) == 1 and audit_calls == []
    assert not active(services[1], issued)
    assert len(stores[0].get_all(APPLICATION_TOKEN_NAMESPACE)) == 1


def test_revoke_compensation_cannot_confuse_identical_clock_generations(pair, monkeypatch):
    """Restore/revoke ABA at the same timestamp must not revive a completed revoke."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    initial = stores[0].get(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id)
    failure = RuntimeError("fixture audit unavailable")
    completed = []

    def audit_failure(_event, _actor, record, *, predecessor=None):
        # Another compensation restores the original active bytes, then an
        # independent service completes a new revoke at the identical clock.
        assert stores[1].compare_and_replace(
            APPLICATION_TOKEN_NAMESPACE,
            {record.application_token_id: record.model_dump_json()},
            {record.application_token_id: initial},
        )
        completed.append(services[1].revoke(
            record.application_token_id, actor_identity_id="independent-operator",
        ))
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].revoke(issued.application_token_id, actor_identity_id="fixture-operator")
    assert error.value is failure and len(completed) == 1
    assert not active(services[1], issued), "same-clock ABA matched a different revoke generation"


@pytest.mark.parametrize("operation", ["issue", "rotate"])
def test_compensation_storage_error_preserves_original_and_removes_owned_new_token(
    pair, monkeypatch, operation,
):
    """A failed restoring batch still attempts exact-owned successor removal."""
    stores, services = pair
    issued = services[0].issue(issue_request()) if operation == "rotate" else None
    failure = RuntimeError("fixture audit unavailable")
    original = stores[0].compare_and_replace
    cleanup_calls = []

    def audit_failure(*args, **kwargs):
        raise failure

    def conditional(namespace, expected, entries, delete_keys=()):
        if delete_keys:
            cleanup_calls.append(tuple(delete_keys))
            if len(cleanup_calls) == 1:
                raise OSError("fixture compensation write unavailable")
        return original(namespace, expected, entries, delete_keys)

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    monkeypatch.setattr(stores[0], "compare_and_replace", conditional)
    with pytest.raises(RuntimeError) as error:
        if operation == "issue":
            services[0].issue(issue_request())
        else:
            services[0].rotate(issued.application_token_id, issue_request())
    assert error.value is failure
    assert len(cleanup_calls) == 2, "conditional cleanup was abandoned after the first storage error"
    assert all(view.lifecycle_status_code != "active" for view in services[1].list_tokens())


@pytest.mark.parametrize("operation", ["issue", "rotate"])
def test_new_identifier_collision_never_overwrites_existing_token(pair, monkeypatch, operation):
    """A minted successor ID must be absent, even if its secret is otherwise valid."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    other = services[1].issue(issue_request())
    baseline = stores[0].get_all(APPLICATION_TOKEN_NAMESPACE)
    original = services[0]._mint
    audit_calls = []

    def mint(request, *, replaced_token_id):
        record, plaintext = original(request, replaced_token_id=replaced_token_id)
        return record.model_copy(update={"application_token_id": other.application_token_id}), plaintext

    monkeypatch.setattr(services[0], "_mint", mint)
    monkeypatch.setattr(services[0], "_audit_event", lambda *args: audit_calls.append(args[0]))
    with pytest.raises(AuthorizationPolicyError) as error:
        if operation == "issue":
            services[0].issue(issue_request())
        else:
            services[0].rotate(issued.application_token_id, issue_request())
    assert error.value.status_code == 409 and audit_calls == []
    assert stores[0].get_all(APPLICATION_TOKEN_NAMESPACE) == baseline
    assert active(services[1], issued) and active(services[1], other)


@pytest.mark.parametrize("operation", ["revoke", "rotate"])
def test_legacy_raw_row_and_audit_failure_restore_without_stale_compare(pair, monkeypatch, operation):
    """Noncanonical JSON and missing generation remain readable and compensatable."""
    import json

    stores, services = pair
    issued = services[0].issue(issue_request())
    value = json.loads(stores[0].get(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id))
    value.pop("lifecycle_generation_id", None)
    raw = json.dumps(value, indent=2, sort_keys=True)
    stores[0].put(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id, raw)
    failure = RuntimeError("fixture audit unavailable")

    def audit_failure(*args, **kwargs):
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        if operation == "revoke":
            services[0].revoke(issued.application_token_id, actor_identity_id="fixture-operator")
        else:
            services[0].rotate(issued.application_token_id, issue_request())
    assert error.value is failure
    assert active(services[1], issued)
    assert len(stores[0].get_all(APPLICATION_TOKEN_NAMESPACE)) == 1


def test_revoke_failed_compensation_leaves_retirement_and_original_error(pair, monkeypatch):
    """Unavailable storage cannot justify stale restoration or replace audit failure."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    failure = RuntimeError("fixture audit unavailable")
    original = stores[0].compare_and_replace
    calls = []

    def conditional(namespace, expected, entries, delete_keys=()):
        calls.append(1)
        if len(calls) > 1:
            raise OSError("fixture cleanup storage unavailable")
        return original(namespace, expected, entries, delete_keys)

    def audit_failure(*args, **kwargs):
        raise failure

    monkeypatch.setattr(stores[0], "compare_and_replace", conditional)
    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].revoke(issued.application_token_id, actor_identity_id="fixture-operator")
    assert error.value is failure
    assert not active(services[1], issued)


def test_persistent_cleanup_failure_does_not_replace_audit_error(pair, monkeypatch):
    """After failed storage retries, propagate the original error, never stale restore."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    failure = RuntimeError("fixture audit unavailable")
    original = stores[0].compare_and_replace
    calls = []

    def conditional(namespace, expected, entries, delete_keys=()):
        calls.append(1)
        if len(calls) > 1:
            raise OSError("fixture persistent cleanup outage")
        return original(namespace, expected, entries, delete_keys)

    def audit_failure(*args, **kwargs):
        raise failure

    monkeypatch.setattr(stores[0], "compare_and_replace", conditional)
    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    with pytest.raises(RuntimeError) as error:
        services[0].rotate(issued.application_token_id, issue_request())
    assert error.value is failure and len(calls) == 3
    assert not active(services[1], issued)
    # No response returns the new plaintext; total storage outage prevents
    # durable cleanup, so its stranded row is an explicit recovery limitation.
    assert len(stores[1].get_all(APPLICATION_TOKEN_NAMESPACE)) == 2


def test_audit_callback_allows_independent_threaded_lifecycle(pair, monkeypatch):
    """No store writer lock remains across audit on either backend."""
    stores, services = pair
    issued = services[0].issue(issue_request())
    failure = RuntimeError("fixture audit unavailable")
    errors, completed = [], []
    workers = []

    def audit_failure(_event, _actor, record, *, predecessor=None):
        def revoke():
            try:
                completed.append(services[1].revoke(
                    record.application_token_id, actor_identity_id="independent-operator",
                ))
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=revoke)
        workers.append(worker)
        worker.start()
        worker.join(5)
        assert not worker.is_alive(), "audit callback is holding a backend writer lock"
        raise failure

    monkeypatch.setattr(services[0], "_audit_event", audit_failure)
    try:
        with pytest.raises(RuntimeError) as error:
            services[0].rotate(issued.application_token_id, issue_request())
        assert error.value is failure and errors == [] and len(completed) == 1
        assert not active(services[1], issued)
        assert all(view.lifecycle_status_code != "active" for view in services[1].list_tokens())
    finally:
        for worker in workers:
            worker.join(7)
