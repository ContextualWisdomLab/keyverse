"""Append-only audit log for link/merge operations.

Every mutating action is recorded. The default sink writes to the KV/DB store
under the two-word snake_case object ``account_merge_audit``. An in-memory sink
is used by tests. Records are immutable once written.
"""
from __future__ import annotations

import json
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


@dataclass
class InMemoryAuditSink:
    """Test/dev sink keeping events in a list."""

    events: list[AuditEvent] = field(default_factory=list)

    def record(self, event: AuditEvent) -> None:
        """Append an event to the in-memory list."""
        self.events.append(event)

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Return recorded events for one correlation id."""
        return [event for event in self.events if event.audit_id == audit_id]


class SqliteAuditSink:
    """Durable append-only sink backed by the ``account_merge_audit`` table."""

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
        import sqlite3

        self._connection = sqlite3.connect(database_path)
        self._connection.execute(self._SCHEMA)
        self._connection.commit()

    def record(self, event: AuditEvent) -> None:
        """Persist one event row and commit immediately."""
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
        self._connection.commit()

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Load events for one correlation id in event sequence order."""
        rows = self._connection.execute(
            "SELECT audit_id, event_type, actor_name, survivor_user_id, "
            "duplicate_user_id, payload_json, created_at "
            "FROM account_merge_audit WHERE audit_id = ? ORDER BY event_sequence",
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
        self._connection.close()


class AuditLogger:
    """Builds and persists audit events; returns a stable correlation id."""

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
