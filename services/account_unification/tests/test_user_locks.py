"""Shared user-operation serialization for merge and SCIM writes."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.user_locks import (
    InMemoryUserOperationLocks,
    SqliteUserOperationLocks,
    UserOperationLockTimeout,
)


def _assert_overlapping_operation_waits(first_manager, second_manager) -> None:
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def hold_first() -> None:
        with first_manager.hold("survivor", "dup"):
            first_entered.set()
            assert release_first.wait(timeout=5)

    def hold_second() -> None:
        assert first_entered.wait(timeout=5)
        with second_manager.hold("dup"):
            second_entered.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(hold_first)
        second_future = executor.submit(hold_second)
        assert first_entered.wait(timeout=2)
        was_serialized = not second_entered.wait(timeout=0.25)
        release_first.set()
        first_future.result(timeout=5)
        second_future.result(timeout=5)

    assert was_serialized
    assert second_entered.is_set()


def test_in_memory_locks_serialize_overlapping_user_ids():
    manager = InMemoryUserOperationLocks()
    _assert_overlapping_operation_waits(manager, manager)


def test_sqlite_locks_serialize_distinct_manager_instances(tmp_path):
    database_path = str(tmp_path / "user-operation-locks.sqlite3")
    first_manager = SqliteUserOperationLocks(database_path)
    second_manager = SqliteUserOperationLocks(database_path)
    _assert_overlapping_operation_waits(first_manager, second_manager)


def test_sqlite_lock_timeout_is_explicit_and_retryable(tmp_path):
    database_path = str(tmp_path / "user-operation-locks.sqlite3")
    first_manager = SqliteUserOperationLocks(database_path)
    impatient_manager = SqliteUserOperationLocks(database_path, timeout_seconds=0.05)

    with first_manager.hold("dup"):
        with pytest.raises(UserOperationLockTimeout):
            with impatient_manager.hold("dup"):
                pytest.fail("contending operation unexpectedly acquired the lock")


def test_lock_manager_rejects_empty_user_ids():
    manager = InMemoryUserOperationLocks()
    with pytest.raises(ValueError):
        with manager.hold(""):
            pytest.fail("empty user ID unexpectedly acquired a lock")
