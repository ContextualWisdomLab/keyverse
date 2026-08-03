"""Thread-safety tests for standalone SQLite configuration and audit stores."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from app.audit import AuditLogger, SqliteAuditSink
from app.kv_store import SqliteKvStore


def test_sqlite_kv_store_handles_concurrent_access(tmp_path):
    """One store instance safely serves concurrent readers and writers."""
    store = SqliteKvStore(
        str(tmp_path / "configuration.sqlite3")
    )

    def write_entry(index: int) -> str | None:
        entry_key = f"entry_key_{index}"
        entry_value = f"entry_value_{index}"
        store.put(
            "runtime_configuration",
            entry_key,
            entry_value,
        )
        return store.get(
            "runtime_configuration", entry_key
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(write_entry, range(100)))

    assert values == [
        f"entry_value_{index}" for index in range(100)
    ]
    assert len(
        store.get_all("runtime_configuration")
    ) == 100
    store.close()


def test_sqlite_audit_sink_handles_concurrent_events(tmp_path):
    """Concurrent audit events remain complete and ordered by sequence."""
    sink = SqliteAuditSink(
        str(tmp_path / "audit_events.sqlite3")
    )
    audit = AuditLogger(sink)
    audit_id = "concurrent_audit"

    def emit_event(index: int) -> None:
        audit.emit(
            audit_id=audit_id,
            event_type="concurrent_event",
            actor=f"worker_{index}",
            payload={"event_index": index},
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(emit_event, range(100)))

    events = audit.events_for(audit_id)
    assert len(events) == 100
    assert {
        event.actor for event in events
    } == {
        f"worker_{index}" for index in range(100)
    }
    audit.close()
