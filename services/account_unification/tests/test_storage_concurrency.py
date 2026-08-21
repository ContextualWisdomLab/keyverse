"""Thread-safety tests for standalone SQLite configuration and audit stores."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

from app.audit import AuditLogger, SqliteAuditSink
from app.kv_store import SqliteKvStore


def test_sqlite_kv_store_handles_concurrent_access(tmp_path) -> None:
    """One store instance safely serves concurrent readers and writers."""
    with closing(
        SqliteKvStore(str(tmp_path / "configuration.sqlite3"))
    ) as store:

        def write_entry(index: int) -> str | None:
            """Write and read one independently keyed configuration value."""
            entry_key = f"entry_key_{index}"
            entry_value = f"entry_value_{index}"
            store.put(
                "runtime_configuration",
                entry_key,
                entry_value,
            )
            return store.get("runtime_configuration", entry_key)

        with ThreadPoolExecutor(max_workers=8) as executor:
            values = list(executor.map(write_entry, range(100)))

        assert values == [
            f"entry_value_{index}" for index in range(100)
        ]
        assert len(store.get_all("runtime_configuration")) == 100
        store.put_many(
            "runtime_configuration",
            {"batch_entry_a": "batch_value_a", "batch_entry_b": "batch_value_b"},
        )
        assert store.get("runtime_configuration", "batch_entry_a") == "batch_value_a"
        assert store.get("runtime_configuration", "batch_entry_b") == "batch_value_b"


def test_sqlite_kv_store_replaces_entries_in_one_operation(tmp_path) -> None:
    """Durable compensation upserts and removes entries transactionally."""
    with closing(SqliteKvStore(str(tmp_path / "replacement.sqlite3"))) as store:
        store.put_many(
            "runtime_configuration",
            {"keep_entry": "old_value", "remove_entry": "stale_value"},
        )
        store.replace_many(
            "runtime_configuration",
            {"keep_entry": "new_value", "added_entry": "new_value"},
            {"remove_entry"},
        )

        assert store.get_all("runtime_configuration") == {
            "keep_entry": "new_value",
            "added_entry": "new_value",
        }


def test_sqlite_audit_sink_handles_concurrent_events(tmp_path) -> None:
    """Concurrent audit events remain complete and retrievable in DB order."""
    with closing(
        SqliteAuditSink(str(tmp_path / "audit_events.sqlite3"))
    ) as sink:
        audit = AuditLogger(sink)
        audit_id = "concurrent_audit"

        def emit_event(index: int) -> None:
            """Append one independently attributable audit event."""
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
        assert {event.actor for event in events} == {
            f"worker_{index}" for index in range(100)
        }
