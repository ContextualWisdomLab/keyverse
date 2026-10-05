"""Append-only, thread-safe audit logging for identity merge operations.

Every mutating merge action is recorded. The standalone sink writes to the
two-word snake_case table ``account_merge_audit``. SQLite access is serialized
inside the process and configured for bounded cross-process contention.
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class AuditEvent:
    """Immutable record for one merge or identity-link action."""

    audit_id: str
    event_type: str
    actor: str
    survivor_user_id: str | None
    duplicate_user_id: str | None
    payload_json: str
    created_at: float


_TOKEN_ID = re.compile(r"tok-[0-9a-f]{16}")
_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ApplicationTokenAuditReadError(Exception):
    """Closed, non-echoing failure for explicit rotation reads."""

    _MESSAGES = {
        "invalid_query": "Invalid application token audit query",
        "unsupported_reader": "Application token audit reader unsupported",
        "corrupt_rotation_event": "Application token rotation audit is corrupt",
        "storage_unavailable": "Application token audit storage unavailable",
    }

    def __init__(self, code: str) -> None:
        """Build an error using only the fixed closed code vocabulary."""
        self.code = code
        super().__init__(self._MESSAGES[code])


def _matches(value: object, pattern: re.Pattern) -> bool:
    """Reject coercion and str subclasses before matching a closed grammar."""
    return type(value) is str and pattern.fullmatch(value) is not None


def _rotation_storage_call(operation: Callable[[], object]) -> object:
    """Normalize ordinary storage errors outside their handler, without raw context.

    Acquire a custom typed code once under an ordinary-Exception guard and
    preserve only exact strings from the fixed vocabulary. Never format args,
    str or repr. Raise after all handlers exit: from-None alone keeps context.
    This bounds cause/context, not temporary interpreter memory or traceback
    locals. Interruptions and other BaseExceptions are never caught.
    """
    result = None
    code = None
    try:
        result = operation()
    except ApplicationTokenAuditReadError as error:
        code = "storage_unavailable"
        try:
            candidate = error.code
            if type(candidate) is str and candidate in ApplicationTokenAuditReadError._MESSAGES:
                code = candidate
        except Exception:
            pass
    except Exception:
        code = "storage_unavailable"
    if code is not None:
        raise ApplicationTokenAuditReadError(code)
    return result


def _validate_rotation_query(application_token_id: str, tenant_deployment_id: str) -> None:
    """Reject malformed query values before acquiring any storage capability."""
    if not _matches(application_token_id, _TOKEN_ID) or not _matches(tenant_deployment_id, _SLUG):
        raise ApplicationTokenAuditReadError("invalid_query")


@dataclass(frozen=True, slots=True)
class ApplicationTokenRotationAuditEvent:
    """Closed historical rotation metadata; never contains a token secret."""

    event_type: str
    audit_id: str
    application_token_id: str
    tenant_deployment_id: str
    software_unit_id: str
    purpose_code: str
    actor: str
    created_at: float
    lifecycle_status_code: str
    lineage_status_code: str
    replaced_token_id: str | None
    replaced_token_lifecycle_status_code: str | None

    def __post_init__(self) -> None:
        """Validate the closed runtime projection, not just its type annotations."""
        _validate_rotation_projection(self)


@dataclass(frozen=True, slots=True)
class ApplicationTokenRotationAuditRead:
    """Ordered captured rows and explicit predecessor coverage for that snapshot."""

    events: tuple[ApplicationTokenRotationAuditEvent, ...]
    predecessor_lookup_complete: bool

    def __post_init__(self) -> None:
        """Validate exact tuple, Boolean coverage and every immutable event."""
        _validate_rotation_result(self)


ROTATION_PURPOSE_CODES = frozenset({"machine_api", "integration_sync", "operator_export"})
_PREFIX = re.compile(r"[0-9a-f]{12}")
_BASE_KEYS = frozenset({
    "application_token_id", "tenant_deployment_id", "software_unit_id",
    "token_prefix", "purpose_code", "lifecycle_status_code",
})
_LINEAGE_KEYS = frozenset({"replaced_token_id", "replaced_token_lifecycle_status_code"})


def _finite_timestamp(value: object) -> bool:
    """Accept only nonnegative finite builtin timestamp numbers, never Boolean."""
    if type(value) not in (int, float):
        return False
    try:
        return value >= 0 and math.isfinite(value)
    except OverflowError:
        return False


def _validate_rotation_projection(event: ApplicationTokenRotationAuditEvent) -> None:
    """Reject malformed custom projections without reconstructing raw storage."""
    if type(event) is not ApplicationTokenRotationAuditEvent or any(
        not hasattr(event, name) for name in ApplicationTokenRotationAuditEvent.__slots__
    ):
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    if (
        type(event.event_type) is not str or event.event_type != "application_token_rotated"
        or not _matches(event.audit_id, _TOKEN_ID)
        or not _matches(event.application_token_id, _TOKEN_ID)
        or event.audit_id != event.application_token_id
        or not _matches(event.tenant_deployment_id, _SLUG)
        or not _matches(event.software_unit_id, _SLUG)
        or type(event.purpose_code) is not str or event.purpose_code not in ROTATION_PURPOSE_CODES
        or type(event.actor) is not str or not 1 <= len(event.actor) <= 128
        or not _finite_timestamp(event.created_at)
        or type(event.lifecycle_status_code) is not str or event.lifecycle_status_code != "active"
        or type(event.lineage_status_code) is not str
        or event.lineage_status_code not in ("recorded", "legacy_missing")
    ):
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    if event.lineage_status_code == "recorded":
        if (
            not _matches(event.replaced_token_id, _TOKEN_ID)
            or event.replaced_token_id == event.application_token_id
            or type(event.replaced_token_lifecycle_status_code) is not str
            or event.replaced_token_lifecycle_status_code != "rotated"
        ):
            raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    elif event.replaced_token_id is not None or event.replaced_token_lifecycle_status_code is not None:
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")


def _validate_rotation_result(result: ApplicationTokenRotationAuditRead) -> None:
    """Check exact closed shape and reject falsely complete returned legacy rows."""
    if (
        type(result) is not ApplicationTokenRotationAuditRead
        or any(not hasattr(result, name) for name in ApplicationTokenRotationAuditRead.__slots__)
        or type(result.events) is not tuple
        or type(result.predecessor_lookup_complete) is not bool
    ):
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    for event in result.events:
        _validate_rotation_projection(event)
        if result.predecessor_lookup_complete and event.lineage_status_code == "legacy_missing":
            raise ApplicationTokenAuditReadError("corrupt_rotation_event")


def _validate_rotation_scope(
    result: ApplicationTokenRotationAuditRead, application_token_id: str, tenant_deployment_id: str
) -> ApplicationTokenRotationAuditRead:
    """Revalidate capability output, refusing foreign or unrelated rows, never filtering."""
    _validate_rotation_result(result)
    for event in result.events:
        if event.tenant_deployment_id != tenant_deployment_id or application_token_id not in (
            event.application_token_id, event.replaced_token_id
        ):
            raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject every duplicate JSON object key, including equal-valued duplicates."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    """Reject JSON nonfinite extensions without formatting their input."""
    raise ValueError("nonfinite constant")


def _finite_json_float(value: str) -> float:
    """Reject exponent overflow as well as named nonfinite JSON constants."""
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite number")
    return number


def _is_rotation_row(row: AuditEvent) -> bool:
    """Check the stored discriminator without coercion or silent malformed-row loss."""
    event_type = None
    if type(row) is AuditEvent:
        try:
            event_type = row.event_type
        except Exception:
            pass
    if type(event_type) is not str:
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    return event_type == "application_token_rotated"


def _decode_rotation(row: AuditEvent) -> ApplicationTokenRotationAuditEvent:
    """Guard all stored fields, then strictly decode before tenant/ID selection.

    Missing fields and ordinary descriptor failures on the exact stored class
    are corruption. Acquire a plain envelope before inspecting payload values;
    raise only after the shape handler exits, without its raw cause/context.
    """
    complete = False
    if type(row) is AuditEvent:
        try:
            row = AuditEvent(*(getattr(row, name) for name in AuditEvent.__dataclass_fields__))
            complete = True
        except Exception:
            pass
    if not complete:
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    payload = None
    if type(row.payload_json) is str:
        try:
            payload = json.loads(
                row.payload_json, object_pairs_hook=_unique_object,
                parse_constant=_reject_constant, parse_float=_finite_json_float,
            )
        except Exception:
            pass
    # Raise after leaving the decoder exception handler: no raw cause/context.
    if type(payload) is not dict or set(payload) not in (_BASE_KEYS, _BASE_KEYS | _LINEAGE_KEYS):
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    if (
        row.event_type != "application_token_rotated"
        or not _matches(row.audit_id, _TOKEN_ID)
        or row.audit_id != payload["application_token_id"]
        or not _matches(payload["application_token_id"], _TOKEN_ID)
        or not _matches(payload["tenant_deployment_id"], _SLUG)
        or not _matches(payload["software_unit_id"], _SLUG)
        or not _matches(payload["token_prefix"], _PREFIX)
        or type(payload["purpose_code"]) is not str
        or payload["purpose_code"] not in ROTATION_PURPOSE_CODES
        or type(payload["lifecycle_status_code"]) is not str
        or payload["lifecycle_status_code"] != "active"
        or type(row.actor) is not str or not 1 <= len(row.actor) <= 128
        or row.survivor_user_id is not None or row.duplicate_user_id is not None
        or not _finite_timestamp(row.created_at)
    ):
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    legacy = set(payload) == _BASE_KEYS
    predecessor = payload.get("replaced_token_id")
    status = payload.get("replaced_token_lifecycle_status_code")
    if not legacy and (
        not _matches(predecessor, _TOKEN_ID) or predecessor == row.audit_id
        or type(status) is not str or status != "rotated"
    ):
        raise ApplicationTokenAuditReadError("corrupt_rotation_event")
    return ApplicationTokenRotationAuditEvent(
        event_type=row.event_type, audit_id=row.audit_id,
        application_token_id=payload["application_token_id"],
        tenant_deployment_id=payload["tenant_deployment_id"],
        software_unit_id=payload["software_unit_id"], purpose_code=payload["purpose_code"],
        actor=row.actor, created_at=row.created_at, lifecycle_status_code="active",
        lineage_status_code="legacy_missing" if legacy else "recorded",
        replaced_token_id=predecessor, replaced_token_lifecycle_status_code=status,
    )


def _rotation_read(
    rows: tuple[AuditEvent, ...], application_token_id: str, tenant_deployment_id: str
) -> ApplicationTokenRotationAuditRead:
    """Validate the entire rotation snapshot, then select each physical row once."""
    validated = tuple(_decode_rotation(row) for row in rows)
    complete = not any(
        event.tenant_deployment_id == tenant_deployment_id
        and event.lineage_status_code == "legacy_missing" for event in validated
    )
    selected = tuple(
        event for event in validated
        if event.tenant_deployment_id == tenant_deployment_id
        and (event.application_token_id == application_token_id
             or event.replaced_token_id == application_token_id)
    )
    return ApplicationTokenRotationAuditRead(selected, complete)


class ApplicationTokenRotationAuditReader(Protocol):
    """Separate optional capability; generic AuditSink enumeration stays unchanged."""

    def application_token_rotation_events_for(
        self, application_token_id: str, *, tenant_deployment_id: str
    ) -> ApplicationTokenRotationAuditRead:
        """Return a coherent validated rotation-only snapshot for the tenant."""
        ...


class AuditSink(Protocol):
    """Persistence contract for append-only audit events."""

    def record(self, event: AuditEvent) -> None:
        """Append one immutable audit event."""
        ...

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Return events for one correlation id in write order."""
        ...

    def close(self) -> None:
        """Release resources held by the sink."""
        ...


@dataclass
class InMemoryAuditSink:
    """Thread-safe test/dev sink keeping events in a list."""

    events: list[AuditEvent] = field(default_factory=list)
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False
    )

    def record(self, event: AuditEvent) -> None:
        """Append an event to the in-memory list."""
        with self._lock:
            self.events.append(event)

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Return recorded events for one correlation id."""
        with self._lock:
            return [event for event in self.events if event.audit_id == audit_id]

    def application_token_rotation_events_for(
        self, application_token_id: str, *, tenant_deployment_id: str
    ) -> ApplicationTokenRotationAuditRead:
        """Capture rotation rows under one lock, then project outside the lock."""
        _validate_rotation_query(application_token_id, tenant_deployment_id)
        def capture() -> tuple[AuditEvent, ...]:
            """Capture immutable event references in append order under the sink lock."""
            with self._lock:
                return tuple(e for e in self.events if _is_rotation_row(e))

        rows = _rotation_storage_call(capture)
        return _rotation_read(rows, application_token_id, tenant_deployment_id)

    def close(self) -> None:
        """Release no-op in-memory resources."""


class SqliteAuditSink:
    """Durable append-only sink backed by ``account_merge_audit``."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS account_merge_audit (
        audit_id          TEXT NOT NULL,
        event_sequence    INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type        TEXT NOT NULL,
        actor_name        TEXT NOT NULL,
        survivor_user_id  TEXT,
        duplicate_user_id TEXT,
        payload_json      TEXT NOT NULL,
        created_at        REAL NOT NULL
    );
    """

    def __init__(self, database_path: str) -> None:
        """Open the audit database and ensure the audit table exists."""
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            database_path,
            timeout=10.0,
            check_same_thread=False,
        )
        with self._lock:
            self._connection.execute("PRAGMA busy_timeout = 10000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = NORMAL")
            self._connection.execute(self._SCHEMA)
            self._connection.commit()

    def record(self, event: AuditEvent) -> None:
        """Persist one event row and commit immediately."""
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO account_merge_audit "
                "(audit_id, event_type, actor_name, survivor_user_id, "
                " duplicate_user_id, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.audit_id,
                    event.event_type,
                    event.actor,
                    event.survivor_user_id,
                    event.duplicate_user_id,
                    event.payload_json,
                    event.created_at,
                ),
            )

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Load events for one correlation id in event sequence order."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT audit_id, event_type, actor_name, survivor_user_id, "
                "duplicate_user_id, payload_json, created_at "
                "FROM account_merge_audit "
                "WHERE audit_id = ? ORDER BY event_sequence",
                (audit_id,),
            ).fetchall()
        return [
            AuditEvent(
                audit_id=row[0],
                event_type=row[1],
                actor=row[2],
                survivor_user_id=row[3],
                duplicate_user_id=row[4],
                payload_json=row[5],
                created_at=row[6],
            )
            for row in rows
        ]

    def application_token_rotation_events_for(
        self, application_token_id: str, *, tenant_deployment_id: str
    ) -> ApplicationTokenRotationAuditRead:
        """Capture all rotations with one ordered statement, without JSON SQL."""
        _validate_rotation_query(application_token_id, tenant_deployment_id)
        def capture() -> tuple[AuditEvent, ...]:
            """Materialize actual rows in one SQLite statement under the connection lock."""
            with self._lock:
                rows = self._connection.execute(
                    "SELECT audit_id, event_type, actor_name, survivor_user_id, "
                    "duplicate_user_id, payload_json, created_at FROM account_merge_audit "
                    "WHERE event_type = ? ORDER BY event_sequence",
                    ("application_token_rotated",),
                ).fetchall()
            return tuple(AuditEvent(*row) for row in rows)

        rows = _rotation_storage_call(capture)
        return _rotation_read(rows, application_token_id, tenant_deployment_id)

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()


class AuditLogger:
    """Build and persist audit events behind a stable correlation id."""

    def __init__(self, sink: AuditSink) -> None:
        """Create an audit logger around one sink implementation."""
        self._sink = sink

    def new_correlation_id(self) -> str:
        """Return a new opaque merge correlation id."""
        return uuid.uuid4().hex

    def emit(
        self,
        *,
        audit_id: str,
        event_type: str,
        actor: str,
        survivor_user_id: str | None = None,
        duplicate_user_id: str | None = None,
        payload: dict | None = None,
    ) -> AuditEvent:
        """Create, persist, and return one audit event."""
        event = AuditEvent(
            audit_id=audit_id,
            event_type=event_type,
            actor=actor,
            survivor_user_id=survivor_user_id,
            duplicate_user_id=duplicate_user_id,
            payload_json=json.dumps(payload or {}, sort_keys=True),
            created_at=time.time(),
        )
        self._sink.record(event)
        return event

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Return the audit trail for one merge correlation id."""
        return self._sink.events_for(audit_id)

    def application_token_rotation_events_for(
        self, application_token_id: str, *, tenant_deployment_id: str
    ) -> ApplicationTokenRotationAuditRead:
        """Read explicit rotation lineage without widening generic correlation."""
        _validate_rotation_query(application_token_id, tenant_deployment_id)
        reader = _rotation_storage_call(
            lambda: getattr(self._sink, "application_token_rotation_events_for", None)
        )
        if not callable(reader):
            raise ApplicationTokenAuditReadError("unsupported_reader")
        result = _rotation_storage_call(
            lambda: reader(application_token_id, tenant_deployment_id=tenant_deployment_id)
        )
        return _validate_rotation_scope(result, application_token_id, tenant_deployment_id)

    def close(self) -> None:
        """Close the underlying audit sink."""
        self._sink.close()
