"""Append-only, thread-safe audit logging for identity merge operations.

Every mutating merge action is recorded. The standalone sink writes to the
two-word snake_case table ``account_merge_audit``. SQLite access is serialized
inside the process and configured for bounded cross-process contention.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
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

    def close(self) -> None:
        """Close the underlying audit sink."""
        self._sink.close()
