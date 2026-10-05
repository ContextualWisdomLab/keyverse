"""Permanent regressions for malformed custom rotation-read failures."""
import traceback

import pytest

from app.audit import (
    AuditLogger, ApplicationTokenAuditReadError as ReadError,
    ApplicationTokenRotationAuditRead as Read,
)
from app.application_tokens import ApplicationTokenService
from app.kv_store import InMemoryKvStore

A = "tok-" + "a" * 16
TENANT = "fixture-deployment"
SENTINEL = "CONTAINMENT_SYNTHETIC_DETAIL_ONLY"
MESSAGES = {
    "invalid_query": "Invalid application token audit query",
    "unsupported_reader": "Application token audit reader unsupported",
    "corrupt_rotation_event": "Application token rotation audit is corrupt",
    "storage_unavailable": "Application token audit storage unavailable",
}


class Reader:
    """Expose the same injected reader at direct logger and service boundaries."""

    def __init__(self, failure=None):
        self.failure = failure

    def application_token_rotation_events_for(self, token, *, tenant_deployment_id):
        if self.failure is not None:
            raise self.failure
        return Read((), True)


def facade(reader, boundary):
    """Avoid the double logger wrapper that masks the injected service defect."""
    if boundary == "logger":
        return AuditLogger(reader).application_token_rotation_events_for
    return ApplicationTokenService(InMemoryKvStore(), reader).rotation_audit_for


def closed(call, code):
    """Assert exact public error identity and formatted traceback containment."""
    caught = None
    try:
        call()
    except Exception as error:
        caught = error
    assert type(caught) is ReadError, "malformed failure escaped closed typed boundary"
    assert caught.code == code
    assert str(caught) == MESSAGES[code]
    assert caught.__cause__ is None
    assert caught.__context__ is None
    assert SENTINEL not in "".join(traceback.format_exception(caught))
    return caught


@pytest.mark.parametrize("boundary", ["logger", "service"])
@pytest.mark.parametrize("fault", ["list", "dict", "missing", "property"])
def test_malformed_typed_failure_is_closed(boundary, fault):
    """Valid input and reader precede each minimal malformed typed failure."""
    assert facade(Reader(), boundary)(A, tenant_deployment_id=TENANT) == Read((), True)
    failure = ReadError("storage_unavailable")
    if fault == "list":
        failure.code = [SENTINEL]
    elif fault == "dict":
        failure.code = {"detail": SENTINEL}
    elif fault == "missing":
        del failure.code
    else:
        class PropertyError(ReadError):
            @property
            def code(self):
                raise RuntimeError(SENTINEL)

            @code.setter
            def code(self, value):
                pass
        failure = PropertyError("storage_unavailable")
    failure.args = (SENTINEL,)
    read = facade(Reader(failure), boundary)
    closed(lambda: read(A, tenant_deployment_id=TENANT), "storage_unavailable")

@pytest.mark.parametrize("field", ["payload_json", "actor", "survivor_user_id", "created_at"])
def test_stored_memory_missing_rotation_field_is_closed(field):
    """Read a valid stored row before deleting exactly one envelope field."""
    from app.audit import InMemoryAuditSink
    from tests.test_pat_rotation_audit_read import _row

    row = _row()
    sink = InMemoryAuditSink(events=[row])
    assert len(sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment").events) == 1
    object.__delattr__(row, field)
    closed(lambda: sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment"), "corrupt_rotation_event")

@pytest.mark.parametrize("fault", ["missing", "property", "unsafe_string", "wrong_class"])
def test_stored_memory_event_type_shape_is_corruption(fault, monkeypatch):
    """Contain envelope faults before event-type filtering can drop a bad row."""
    from app.audit import AuditEvent, InMemoryAuditSink
    from tests.test_pat_rotation_audit_read import _row

    row = _row()
    sink = InMemoryAuditSink(events=[row])
    assert len(sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment").events) == 1
    if fault == "missing":
        object.__delattr__(row, "event_type")
    elif fault == "property":
        def explode(self):
            raise RuntimeError(SENTINEL)
        monkeypatch.setattr(AuditEvent, "event_type", property(explode), raising=False)
    elif fault == "unsafe_string":
        class UnsafeString(str):
            def __eq__(self, other):
                raise RuntimeError(SENTINEL)
        object.__setattr__(row, "event_type", UnsafeString("application_token_rotated"))
    else:
        class ForeignEvent:
            event_type = "application_token_rotated"
        sink.events[0] = ForeignEvent()
    closed(lambda: sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment"), "corrupt_rotation_event")

@pytest.mark.parametrize("boundary", ["logger", "service"])
@pytest.mark.parametrize("code", list(MESSAGES))
def test_known_typed_codes_are_reconstructed_without_formatting(boundary, code):
    """Keep genuine known codes without inspecting attacker formatting or args."""
    observed = []
    class Unformattable(ReadError):
        def __getattribute__(self, name):
            if name == "args":
                observed.append(name)
                raise RuntimeError(SENTINEL)
            return super().__getattribute__(name)

        def __str__(self):
            observed.append("str")
            raise RuntimeError(SENTINEL)

        def __repr__(self):
            observed.append("repr")
            raise RuntimeError(SENTINEL)
    failure = Unformattable(code)
    read = facade(Reader(failure), boundary)
    assert closed(lambda: read(A, tenant_deployment_id=TENANT), code) is not failure
    assert observed == []


@pytest.mark.parametrize("boundary", ["logger", "service"])
@pytest.mark.parametrize("fault", ["unknown", "str_subclass", "ordinary"])
def test_unsafe_error_metadata_is_not_evaluated(boundary, fault):
    """Do not hash a str subclass or reflect an unknown code/raw ordinary message."""
    observed = []
    class UnsafeString(str):
        def __hash__(self):
            observed.append("hash")
            raise RuntimeError(SENTINEL)
    failure = ReadError("storage_unavailable")
    if fault == "unknown":
        failure.code = SENTINEL
    elif fault == "str_subclass":
        failure.code = UnsafeString("storage_unavailable")
    else:
        failure = RuntimeError(SENTINEL)
    read = facade(Reader(failure), boundary)
    closed(lambda: read(A, tenant_deployment_id=TENANT), "storage_unavailable")
    assert observed == []


@pytest.mark.parametrize("field", ["audit_id", "duplicate_user_id"])
def test_other_missing_rotation_envelope_fields_are_closed(field):
    """Sibling missing fields use the same complete stored-row shape guard."""
    from app.audit import InMemoryAuditSink
    from tests.test_pat_rotation_audit_read import _row

    row = _row()
    sink = InMemoryAuditSink(events=[row])
    assert len(sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment").events) == 1
    object.__delattr__(row, field)
    closed(lambda: sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment"), "corrupt_rotation_event")


@pytest.mark.parametrize("field", ["payload_json", "actor", "audit_id", "survivor_user_id",
                                   "duplicate_user_id", "created_at"])
def test_exact_stored_class_property_failure_is_closed(field, monkeypatch):
    """Ordinary descriptor failures on the exact stored class never escape."""
    from app.audit import AuditEvent, InMemoryAuditSink
    from tests.test_pat_rotation_audit_read import _row

    row = _row()
    sink = InMemoryAuditSink(events=[row])
    assert len(sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment").events) == 1
    def explode(self):
        raise RuntimeError(SENTINEL)
    monkeypatch.setattr(AuditEvent, field, property(explode), raising=False)
    closed(lambda: sink.application_token_rotation_events_for(
        A, tenant_deployment_id="default-deployment"), "corrupt_rotation_event")


@pytest.mark.parametrize("boundary", ["logger", "service"])
@pytest.mark.parametrize("stage", ["operation", "code"])
def test_interruptions_are_not_swallowed(boundary, stage):
    """BaseException identity survives both callback and typed-code acquisition."""
    interruption = KeyboardInterrupt()
    if stage == "operation":
        failure = interruption
    else:
        class InterruptingError(ReadError):
            @property
            def code(self):
                raise interruption

            @code.setter
            def code(self, value):
                pass
        failure = InterruptingError("storage_unavailable")
    with pytest.raises(KeyboardInterrupt) as info:
        facade(Reader(failure), boundary)(A, tenant_deployment_id=TENANT)
    assert info.value is interruption


def test_decoder_exact_class_shape_control():
    """The shared decoder refuses a foreign envelope without evaluating properties."""
    from app.audit import _decode_rotation
    from tests.test_pat_rotation_audit_read import _row

    assert _decode_rotation(_row()).application_token_id == "tok-" + "b" * 16
    class Foreign:
        @property
        def payload_json(self):
            raise RuntimeError(SENTINEL)
    closed(lambda: _decode_rotation(Foreign()), "corrupt_rotation_event")
