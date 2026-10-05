"""Explicit tenant-scoped historical rotation reads, without generic widening."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
from threading import Event

import pytest

from app import audit as audit_module
from app.application_tokens import CLOSED_PURPOSE_CODES, ApplicationTokenVerifyRequest
from app.org_authorization import _SLUG as OWNER_SLUG

from app.application_tokens import ApplicationTokenIssueRequest, ApplicationTokenService
from app.audit import (
    AuditEvent, AuditLogger, ApplicationTokenRotationAuditEvent,
    ApplicationTokenRotationAuditRead, InMemoryAuditSink, SqliteAuditSink,
)
from app.kv_store import InMemoryKvStore, SqliteKvStore

TENANT = "default-deployment"
BODY = {
    "software_unit_id": "naruon-web",
    "purpose_code": "machine_api",
    "capability_codes": ["api.invoices.read", "api.invoices.write"],
    "lifetime_seconds": 3600,
    "actor_identity_id": "operator-ida",
    "tenant_deployment_id": TENANT,
}


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_one_rotation_two_lookups_one_append(tmp_path, backend):
    """Both arms return the same historical row; generic correlation stays exact."""
    path = str(tmp_path / "audit.db")
    sink = InMemoryAuditSink() if backend == "memory" else SqliteAuditSink(path)
    store = InMemoryKvStore() if backend == "memory" else SqliteKvStore(str(tmp_path / "kv.db"))
    audit = AuditLogger(sink)
    service = ApplicationTokenService(store, audit)
    try:
        request = ApplicationTokenIssueRequest.model_validate(BODY)
        issued = service.issue(request)
        rotated = service.rotate(issued.application_token_id, request)
        first, second = issued.application_token_id, rotated.application_token_id
        assert callable(getattr(service, "rotation_audit_for", None)), "missing explicit rotation read"
        old = service.rotation_audit_for(first, tenant_deployment_id=TENANT)
        new = service.rotation_audit_for(second, tenant_deployment_id=TENANT)
        assert old == new
        assert len(old.events) == 1
        event = old.events[0]
        assert event.application_token_id == event.audit_id == second
        assert event.replaced_token_id == first
        assert event.replaced_token_lifecycle_status_code == "rotated"
        assert event.lifecycle_status_code == "active"
        assert event.tenant_deployment_id == TENANT
        assert old.predecessor_lookup_complete is True
        assert [e.event_type for e in audit.events_for(first)] == ["application_token_issued"]
        assert [e.event_type for e in audit.events_for(second)] == ["application_token_rotated"]
        assert len(audit.events_for(first)) + len(audit.events_for(second)) == 2
        if backend == "sqlite":
            audit.close()
            audit = AuditLogger(SqliteAuditSink(path))
            store.close()
            store = SqliteKvStore(str(tmp_path / "kv.db"))
            reopened = ApplicationTokenService(store, audit)
            assert reopened.rotation_audit_for(first, tenant_deployment_id=TENANT) == old
    finally:
        audit.close()
        store.close()


class _AccessFence(InMemoryAuditSink):
    """Count optional reader acquisition without reading unrelated storage."""

    def __init__(self):
        super().__init__()
        self.reads = 0

    def application_token_rotation_events_for(self, *args, **kwargs):
        self.reads += 1
        return super().application_token_rotation_events_for(*args, **kwargs)


def _closed_error(call, code):
    """Assert fixed errors without pytest formatting injected raw values."""
    error = None
    try:
        call()
    except Exception as caught:
        error = caught
    assert error is not None, "expected closed read rejection"
    assert type(error).__name__ == "ApplicationTokenAuditReadError"
    assert error.code == code
    assert str(error) == {
        'invalid_query': 'Invalid application token audit query',
        'unsupported_reader': 'Application token audit reader unsupported',
        'corrupt_rotation_event': 'Application token rotation audit is corrupt',
        'storage_unavailable': 'Application token audit storage unavailable',
    }[code]
    assert error.__cause__ is None
    assert error.__context__ is None
    return error


@pytest.mark.parametrize('token,tenant', [
    ('bad', TENANT), (123, TENANT), ('tok-' + 'A' * 16, TENANT),
    ('tok-' + 'a' * 16, ''), ('tok-' + 'a' * 16, 'Bad Slug'),
    ('tok-' + 'a' * 16, 123), ('tok-' + 'a' * 16, 'a' * 64),
])
def test_query_rejected_before_reader_access(token, tenant):
    """Strict query validation precedes optional sink capability access."""
    sink = _AccessFence()
    audit = AuditLogger(sink)
    service = ApplicationTokenService(InMemoryKvStore(), audit)
    for reader in (service.rotation_audit_for, audit.application_token_rotation_events_for):
        _closed_error(lambda: reader(token, tenant_deployment_id=tenant), 'invalid_query')
    assert sink.reads == 0



A, B, C = ('tok-' + c * 16 for c in 'abc')


def _row(successor=B, predecessor=A, tenant=TENANT, **changes):
    """Build a realistic metadata row, with explicit legacy absence when requested."""
    payload = {
        'application_token_id': successor, 'tenant_deployment_id': tenant,
        'software_unit_id': 'naruon-web', 'token_prefix': 'deadbeefcafe',
        'purpose_code': 'machine_api', 'lifecycle_status_code': 'active',
    }
    if predecessor is not None:
        payload.update(replaced_token_id=predecessor,
                       replaced_token_lifecycle_status_code='rotated')
    return replace(AuditEvent(successor, 'application_token_rotated', 'operator-ida',
                              None, None, json.dumps(payload), 1700000000.0), **changes)


@pytest.fixture(params=['memory', 'sqlite'])
def rotation_sink(request, tmp_path):
    """Use real storage for every strict decoder and append-order control."""
    sink = InMemoryAuditSink() if request.param == 'memory' else SqliteAuditSink(
        str(tmp_path / 'rotation.db'))
    try:
        yield sink
    finally:
        sink.close()


def test_legacy_coverage_is_requested_tenant_wide(rotation_sink):
    """A same-tenant unrelated legacy row makes empty predecessor lookup incomplete."""
    audit = AuditLogger(rotation_sink)
    rotation_sink.record(_row(predecessor=None))
    legacy = audit.application_token_rotation_events_for(B, tenant_deployment_id=TENANT)
    assert len(legacy.events) == 1
    event = legacy.events[0]
    assert event.lineage_status_code == 'legacy_missing'
    assert event.replaced_token_id is event.replaced_token_lifecycle_status_code is None
    assert legacy.predecessor_lookup_complete is False
    empty = audit.application_token_rotation_events_for(A, tenant_deployment_id=TENANT)
    assert empty.events == () and empty.predecessor_lookup_complete is False
    foreign = audit.application_token_rotation_events_for(B, tenant_deployment_id='other-tenant')
    assert foreign.events == () and foreign.predecessor_lookup_complete is True


@pytest.mark.parametrize('mutation', [
    {'application_token_id': A}, {'tenant_deployment_id': 'Bad Tenant'},
    {'software_unit_id': ''}, {'purpose_code': 'password'}, {'token_prefix': 'BAD'},
    {'lifecycle_status_code': 'revoked'}, {'replaced_token_id': None},
    {'replaced_token_id': C}, {'replaced_token_id': 1},
    {'replaced_token_lifecycle_status_code': 'revoked'},
    {'replaced_token_lifecycle_status_code': None},
    {'secret_extension': 'synthetic-sensitive-value'},
])
def test_closed_payload_rejects_corruption_before_selection(rotation_sink, mutation):
    """All captured rotations are validated, including unrelated foreign rows."""
    good = _row()
    rotation_sink.record(good)
    bad = _row(successor=C, predecessor=A, tenant='other-tenant')
    payload = json.loads(bad.payload_json)
    payload.update(mutation)
    rotation_sink.record(replace(bad, payload_json=json.dumps(payload)))
    audit = AuditLogger(rotation_sink)
    _closed_error(lambda: audit.application_token_rotation_events_for(
        B, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


@pytest.mark.parametrize('raw', [
    '{', '[]', 'null', '1', '{"application_token_id":"duplicate", "application_token_id":"duplicate"}',
    '{"x": NaN}', '{"x": Infinity}', '{"x": -Infinity}', '{"x": 1e999}',
])
def test_strict_json_rejects_nonobjects_duplicates_and_nonfinite(rotation_sink, raw):
    """Opaque generic JSON remains unchanged while the explicit reader fails closed."""
    row = _row(payload_json=raw)
    rotation_sink.record(row)
    audit = AuditLogger(rotation_sink)
    assert audit.events_for(B) == [row]
    _closed_error(lambda: audit.application_token_rotation_events_for(
        B, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


@pytest.mark.parametrize('changes', [
    {'audit_id': A}, {'actor': ''}, {'actor': 'a' * 129},
    {'survivor_user_id': 'merge-user'}, {'duplicate_user_id': 'merge-user'},
    {'created_at': -1.0}, {'created_at': float('inf')},
])
def test_rotation_envelope_rejects_bad_metadata(rotation_sink, changes):
    """Rotation rows must not carry merge metadata or invalid audit facts."""
    rotation_sink.record(_row(**changes))
    _closed_error(lambda: AuditLogger(rotation_sink).application_token_rotation_events_for(
        B, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


@pytest.mark.parametrize('missing', [
    'application_token_id', 'tenant_deployment_id', 'software_unit_id',
    'token_prefix', 'purpose_code', 'lifecycle_status_code',
    'replaced_token_id', 'replaced_token_lifecycle_status_code',
])
def test_missing_key_is_not_legacy_unless_both_lineage_keys_absent(rotation_sink, missing):
    """Partial lineage and missing base keys are corruption, never inferred history."""
    row = _row()
    payload = json.loads(row.payload_json)
    del payload[missing]
    rotation_sink.record(replace(row, payload_json=json.dumps(payload)))
    _closed_error(lambda: AuditLogger(rotation_sink).application_token_rotation_events_for(
        B, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


class _ExactOnlySink:
    """Third-party generic sink remains compatible without optional reader support."""

    def __init__(self):
        self.events = []
        self.closed = False

    def record(self, event):
        self.events.append(event)

    def events_for(self, audit_id):
        return [e for e in self.events if e.audit_id == audit_id]

    def close(self):
        self.closed = True


def test_unsupported_reader_keeps_generic_emit_exact_and_close():
    """The new optional capability must not become a generic sink requirement."""
    sink = _ExactOnlySink()
    audit = AuditLogger(sink)
    row = audit.emit(audit_id=B, event_type='merge_started', actor='operator-ida')
    assert audit.events_for(B) == [row]
    assert audit.events_for(A) == []
    _closed_error(lambda: audit.application_token_rotation_events_for(
        B, tenant_deployment_id=TENANT), 'unsupported_reader')
    audit.close()
    assert sink.closed




class _CustomReader(_ExactOnlySink):
    """Supply untrusted custom capability results through the real logger facade."""

    def __init__(self, result):
        super().__init__()
        self.result = result

    def application_token_rotation_events_for(self, *args, **kwargs):
        return self.result


def _projected(**updates):
    """Return otherwise-valid custom-reader metadata."""
    return ApplicationTokenRotationAuditEvent(
        **dict(event_type='application_token_rotated', audit_id=B,
               application_token_id=B, tenant_deployment_id=TENANT,
               software_unit_id='naruon-web', purpose_code='machine_api', actor='operator-ida',
               created_at=1700000000.0, lifecycle_status_code='active',
               lineage_status_code='recorded', replaced_token_id=A,
               replaced_token_lifecycle_status_code='rotated', **updates))


@pytest.mark.parametrize('fault', ['foreign', 'unrelated', 'bool', 'list', 'raw', 'false_partial'])
def test_facade_revalidates_custom_reader_closed_result(fault):
    """Custom readers cannot expose foreign/unrelated rows or contradictory coverage."""
    event = _projected()
    result = ApplicationTokenRotationAuditRead((event,), True)
    if fault == 'foreign':
        object.__setattr__(event, 'tenant_deployment_id', 'other-tenant')
    elif fault == 'unrelated':
        object.__setattr__(event, 'application_token_id', C)
        object.__setattr__(event, 'audit_id', C)
        object.__setattr__(event, 'replaced_token_id', B)
    elif fault == 'bool':
        object.__setattr__(result, 'predecessor_lookup_complete', 1)
    elif fault == 'list':
        object.__setattr__(result, 'events', [event])
    elif fault == 'raw':
        result = {'events': [asdict(event)], 'predecessor_lookup_complete': True}
    else:
        object.__setattr__(event, 'lineage_status_code', 'legacy_missing')
        object.__setattr__(event, 'replaced_token_id', None)
        object.__setattr__(event, 'replaced_token_lifecycle_status_code', None)
    audit = AuditLogger(_CustomReader(result))
    _closed_error(lambda: audit.application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


def test_dto_constructor_validates_runtime_not_only_annotations():
    """Closed immutable DTO constructors must reject invalid exact types."""
    _closed_error(lambda: ApplicationTokenRotationAuditRead((), 1), 'corrupt_rotation_event')
    fields = asdict(_projected())
    fields['created_at'] = True
    _closed_error(lambda: ApplicationTokenRotationAuditEvent(**fields), 'corrupt_rotation_event')


class _FailingReader(_ExactOnlySink):
    """Force driver errors without real network or inaccessible shared state."""

    def application_token_rotation_events_for(self, *args, **kwargs):
        raise RuntimeError('synthetic-driver-sensitive-detail')


def test_storage_failure_is_fixed_not_empty_or_raw():
    """Optional storage failures must not become empty success or echo driver text."""
    _closed_error(lambda: AuditLogger(_FailingReader()).application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT), 'storage_unavailable')


def test_closed_sqlite_read_is_fixed_storage_failure(tmp_path):
    """Exercise the real SQLite unavailable boundary, including direct sink access."""
    sink = SqliteAuditSink(str(tmp_path / 'closed.db'))
    sink.close()
    _closed_error(lambda: sink.application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT), 'storage_unavailable')




def test_adjacent_chain_append_order_and_physical_duplicates(rotation_sink):
    """Middle B has two adjacent rotations; no transitive walk or audit-ID dedup."""
    first, second = _row(), _row(successor=C, predecessor=B, created_at=1.0)
    rotation_sink.record(first)
    rotation_sink.record(second)
    rotation_sink.record(second)
    audit = AuditLogger(rotation_sink)
    def read(token):
        """Read adjacent rotations through the real logger."""
        return audit.application_token_rotation_events_for(token, tenant_deployment_id=TENANT)
    assert [e.audit_id for e in read(A).events] == [B]
    assert [e.audit_id for e in read(B).events] == [B, C, C]
    assert [e.created_at for e in read(B).events] == [1700000000.0, 1.0, 1.0]
    assert len(read(C).events) == 2
    rotation_sink.record(_row(successor=A, predecessor=C, tenant='other-tenant'))
    assert [e.audit_id for e in read(B).events] == [B, C, C]
    assert read('tok-' + 'd' * 16).events == ()


@pytest.mark.parametrize('arm', ['successor', 'predecessor'])
def test_cross_tenant_same_id_references_are_never_returned(rotation_sink, arm):
    """Both match arms are tenant scoped, not global token existence or membership."""
    rotation_sink.record(_row())
    rotation_sink.record(_row(successor=A, predecessor=C, tenant='other-tenant'))
    audit = AuditLogger(rotation_sink)
    token = B if arm == 'successor' else A
    result = audit.application_token_rotation_events_for(token, tenant_deployment_id=TENANT)
    assert len(result.events) == 1 and result.events[0].audit_id == B
    foreign = audit.application_token_rotation_events_for(B, tenant_deployment_id='other-tenant')
    assert foreign.events == () and foreign.predecessor_lookup_complete is True


def test_nonrotation_opaque_json_is_outside_reader(rotation_sink):
    """Generic byte semantics stay exact even for malformed nonrotation JSON."""
    opaque = _row(event_type='merge_started', payload_json='{not JSON')
    rotation_sink.record(opaque)
    rotation_sink.record(_row())
    audit = AuditLogger(rotation_sink)
    assert audit.events_for(B)[0] == opaque
    assert len(audit.application_token_rotation_events_for(A, tenant_deployment_id=TENANT).events) == 1


@pytest.mark.parametrize('backend', ['memory', 'sqlite'])
def test_snapshot_capture_has_independent_settled_append_barrier(tmp_path, monkeypatch, backend):
    """A real independent writer commits after actual capture; next read alone sees it."""
    path = str(tmp_path / 'snapshot.db')
    sink = InMemoryAuditSink() if backend == 'memory' else SqliteAuditSink(path)
    writer = sink if backend == 'memory' else SqliteAuditSink(path)
    captured, committed = Event(), Event()
    actual = audit_module._rotation_read
    trace = []
    sink.record(_row())
    def after_capture(rows, token, tenant):
        captured.set()
        assert committed.wait(5), 'independent writer did not settle'
        return actual(rows, token, tenant)
    def append():
        assert captured.wait(5), 'capture barrier not reached'
        writer.record(_row(successor=C, predecessor=B))
        committed.set()
    try:
        if backend == 'sqlite':
            sink._connection.set_trace_callback(trace.append)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(append)
            with monkeypatch.context() as patcher:
                patcher.setattr(audit_module, '_rotation_read', after_capture)
                result = AuditLogger(sink).application_token_rotation_events_for(B, tenant_deployment_id=TENANT)
            future.result(timeout=5)
        assert len(result.events) == 1
        assert len(AuditLogger(sink).application_token_rotation_events_for(B, tenant_deployment_id=TENANT).events) == 2
        if backend == 'sqlite':
            reads = [statement for statement in trace if statement.startswith('SELECT')]
            assert len(reads) == 2
            assert all('WHERE event_type =' in s and 'ORDER BY event_sequence' in s for s in reads)
            assert not any(s.startswith(('INSERT', 'UPDATE', 'DELETE', 'BEGIN')) for s in trace)
    finally:
        if writer is not sink:
            writer.close()
        sink.close()


def test_history_survives_retirement_expiry_and_no_kv_access(monkeypatch):
    """Historical states remain stable after real revoke/expiry and KV removal."""
    store = InMemoryKvStore()
    audit = AuditLogger(InMemoryAuditSink())
    now = [1700000000.0]
    service = ApplicationTokenService(store, audit, clock=lambda: now[0])
    request = ApplicationTokenIssueRequest.model_validate(BODY)
    issued = service.issue(request)
    successor = service.rotate(issued.application_token_id, request)
    historical = service.rotation_audit_for(issued.application_token_id, tenant_deployment_id=TENANT)
    service.revoke(successor.application_token_id, actor_identity_id='operator-ida')
    now[0] += 3601
    assert service.get_token(successor.application_token_id).lifecycle_status_code == 'revoked'
    assert service.verify(ApplicationTokenVerifyRequest(
        presented_token=successor.plaintext_token, tenant_deployment_id=TENANT,
        software_unit_id='naruon-web')).active is False
    def no_kv(*args, **kwargs):
        raise AssertionError('audit read consulted KV')
    for name in ('get', 'get_all', 'get_all_namespaces', 'put', 'put_many', 'compare_and_replace', 'delete'):
        monkeypatch.setattr(store, name, no_kv)
    assert service.rotation_audit_for(issued.application_token_id, tenant_deployment_id=TENANT) == historical
    text = json.dumps(asdict(historical))
    assert not any(s in text for s in (issued.plaintext_token, successor.plaintext_token,
                                      'token_hash', 'token_prefix', 'capability_codes', 'payload_json'))
    with pytest.raises(FrozenInstanceError):
        historical.events = ()
    with pytest.raises(FrozenInstanceError):
        historical.events[0].actor = 'changed'


def test_closed_profiles_match_owners_and_protocol_enumeration():
    """Copied audit grammars are pinned to actual issuing profiles, not broadened."""
    assert audit_module.ROTATION_PURPOSE_CODES == CLOSED_PURPOSE_CODES
    for value in ('a', 'a-b', '0', 'a' * 63, '', '-a', 'a-', 'Bad', 'a_b', 'a' * 64, 'a\n'):
        assert (audit_module._SLUG.fullmatch(value) is not None) == (OWNER_SLUG.fullmatch(value) is not None)
    assert {name for name, member in vars(audit_module.AuditSink).items()
            if not name.startswith('_') and callable(member)} == {'record', 'events_for', 'close'}
    assert {name for name, member in vars(audit_module.ApplicationTokenRotationAuditReader).items()
            if not name.startswith('_') and callable(member)} == {'application_token_rotation_events_for'}


@pytest.mark.parametrize('timestamp', [True, '1700000000', float('nan'), 10 ** 400])
def test_memory_timestamp_exact_types_and_overflow(timestamp):
    """SQLite affinity cannot certify original Boolean types; memory rejects them."""
    sink = InMemoryAuditSink()
    sink.record(_row(created_at=timestamp))
    _closed_error(lambda: sink.application_token_rotation_events_for(A, tenant_deployment_id=TENANT),
                  'corrupt_rotation_event')


def test_duplicate_equal_keys_valid_base_and_scalar_overflow(rotation_sink):
    """Otherwise-valid JSON duplicate keys and overflow never disappear on decode."""
    row = _row()
    raw = row.payload_json[:-1] + ', "purpose_code": "machine_api"}'
    rotation_sink.record(replace(row, payload_json=raw))
    _closed_error(lambda: rotation_sink.application_token_rotation_events_for(A, tenant_deployment_id=TENANT),
                  'corrupt_rotation_event')


def test_baseexception_identity_not_normalized():
    """Interruption must propagate unchanged, not become storage failure or empty."""
    interruption = KeyboardInterrupt()
    class Interrupted(_ExactOnlySink):
        def application_token_rotation_events_for(self, *args, **kwargs):
            raise interruption
    caught = None
    try:
        AuditLogger(Interrupted()).application_token_rotation_events_for(A, tenant_deployment_id=TENANT)
    except KeyboardInterrupt as error:
        caught = error
    assert caught is interruption


def test_service_revalidates_injected_logger_result():
    """The management service rechecks scope even when its logger is injected."""
    class Logger:
        def application_token_rotation_events_for(self, *args, **kwargs):
            return ApplicationTokenRotationAuditRead((_projected(),), True)
    service = ApplicationTokenService(InMemoryKvStore(), Logger())
    _closed_error(lambda: service.rotation_audit_for(C, tenant_deployment_id=TENANT),
                  'corrupt_rotation_event')


def test_direct_memory_capture_failure_is_sanitized():
    """A failed memory capture is storage failure rather than a raw exception."""
    class BrokenList(list):
        def __iter__(self):
            raise RuntimeError('synthetic-sensitive-capture-detail')
    sink = InMemoryAuditSink(events=BrokenList())
    _closed_error(lambda: sink.application_token_rotation_events_for(A, tenant_deployment_id=TENANT),
                  'storage_unavailable')


@pytest.mark.parametrize('fault', ['raw_event', 'bad_predecessor', 'legacy_pair', 'field_type'])
def test_custom_reader_defensive_projection_checks(fault):
    """Revalidate bypassed constructors as untrusted capability output."""
    event = _projected()
    result = ApplicationTokenRotationAuditRead((event,), True)
    if fault == 'raw_event':
        object.__setattr__(result, 'events', (asdict(event),))
    elif fault == 'bad_predecessor':
        object.__setattr__(event, 'replaced_token_id', B)
    elif fault == 'legacy_pair':
        object.__setattr__(event, 'lineage_status_code', 'legacy_missing')
    else:
        object.__setattr__(event, 'created_at', '123')
    _closed_error(lambda: AuditLogger(_CustomReader(result)).application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


def test_timestamp_finite_json_float_positive_and_raw_payload_type():
    """Fractional finite JSON numbers remain valid; wrong raw payload types do not."""
    assert audit_module._finite_json_float('1.25') == 1.25
    sink = InMemoryAuditSink()
    sink.record(_row(payload_json=123))
    _closed_error(lambda: sink.application_token_rotation_events_for(A, tenant_deployment_id=TENANT),
                  'corrupt_rotation_event')


def test_legacy_custom_reader_partial_envelope_positive():
    """A valid partial custom result is accepted without claiming unseen-row capture."""
    event = replace(_projected(), lineage_status_code='legacy_missing',
                    replaced_token_id=None, replaced_token_lifecycle_status_code=None)
    result = ApplicationTokenRotationAuditRead((event,), False)
    assert AuditLogger(_CustomReader(result)).application_token_rotation_events_for(
        B, tenant_deployment_id=TENANT) == result
    empty = ApplicationTokenRotationAuditRead((), False)
    assert AuditLogger(_CustomReader(empty)).application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT) == empty


def test_overflow_in_otherwise_valid_closed_payload(rotation_sink):
    """Scalar overflow must reject rather than coerce to inf before semantic checks."""
    row = _row()
    raw = row.payload_json.replace('"machine_api"', '1e999')
    rotation_sink.record(replace(row, payload_json=raw))
    _closed_error(lambda: rotation_sink.application_token_rotation_events_for(A, tenant_deployment_id=TENANT),
                  'corrupt_rotation_event')


def test_forged_exact_dto_missing_field_fails_closed():
    """Bypassing a frozen constructor cannot turn missing fields into raw failures."""
    malformed = object.__new__(ApplicationTokenRotationAuditEvent)
    result = ApplicationTokenRotationAuditRead((), True)
    object.__setattr__(result, 'events', (malformed,))
    _closed_error(lambda: AuditLogger(_CustomReader(result)).application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT), 'corrupt_rotation_event')


def test_event_type_str_subclass_is_not_exact_closed_metadata():
    """Memory retains original Python types; event labels must be exact strings."""
    class Label(str):
        pass
    sink = InMemoryAuditSink()
    sink.record(_row(event_type=Label('application_token_rotated')))
    _closed_error(lambda: sink.application_token_rotation_events_for(A, tenant_deployment_id=TENANT),
                  'corrupt_rotation_event')


def test_forged_exact_result_missing_fields_fails_closed():
    """Defensive envelope validation rejects uninitialized exact-class objects."""
    malformed = object.__new__(ApplicationTokenRotationAuditRead)
    _closed_error(lambda: AuditLogger(_CustomReader(malformed)).application_token_rotation_events_for(
        A, tenant_deployment_id=TENANT), 'corrupt_rotation_event')
