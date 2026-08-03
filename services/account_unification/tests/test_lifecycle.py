"""Application lifecycle and temporary resource tests."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from app.main import (
    _remove_temporary_lock_database,
    _user_operation_lock_path,
)


def test_in_memory_audit_uses_real_temporary_lock_database() -> None:
    """An in-memory audit sink never creates a malformed pseudo-file path."""
    lock_path, is_temporary = _user_operation_lock_path(":memory:")
    try:
        assert is_temporary is True
        assert lock_path != ":memory:.user-operation-locks.sqlite3"
        assert Path(lock_path).is_file()
    finally:
        Path(lock_path).unlink(missing_ok=True)


def test_persistent_audit_uses_adjacent_lock_sidecar(tmp_path) -> None:
    """A persistent audit database keeps its lock sidecar on the same volume."""
    audit_path = str(tmp_path / "account_merge_audit.sqlite3")
    lock_path, is_temporary = _user_operation_lock_path(audit_path)
    assert lock_path == f"{audit_path}.user-operation-locks.sqlite3"
    assert is_temporary is False


def test_temporary_lock_database_is_removed_at_shutdown(tmp_path) -> None:
    """Lifecycle cleanup removes only the explicitly temporary sidecar."""
    lock_path = tmp_path / "temporary_user_locks.sqlite3"
    lock_path.write_text("placeholder", encoding="utf-8")
    app = SimpleNamespace(
        state=SimpleNamespace(
            temporary_user_operation_lock_database=True,
            user_operation_lock_database_path=str(lock_path),
        )
    )

    _remove_temporary_lock_database(app)

    assert not lock_path.exists()


def test_persistent_lock_database_is_not_removed_at_shutdown(tmp_path) -> None:
    """Lifecycle cleanup leaves deployment-owned persistent sidecars intact."""
    lock_path = tmp_path / "persistent_user_locks.sqlite3"
    lock_path.write_text("placeholder", encoding="utf-8")
    app = SimpleNamespace(
        state=SimpleNamespace(
            temporary_user_operation_lock_database=False,
            user_operation_lock_database_path=str(lock_path),
        )
    )

    _remove_temporary_lock_database(app)

    assert lock_path.exists()
