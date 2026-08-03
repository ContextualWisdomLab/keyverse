"""Cross-path serialization for mutations of Keycloak user records.

SCIM replacement and account merge both write complete or partial Keycloak user
representations. They must share one lock boundary so a merge cannot tombstone a
duplicate between SCIM's tombstone check and its replacement PUT.

The standalone runtime uses :class:`SqliteUserOperationLocks`, backed by a
dedicated sidecar SQLite database. ``BEGIN IMMEDIATE`` provides a crash-safe,
cross-process mutex for every service worker sharing that database file. The
current implementation intentionally serializes all user mutations rather than
risking a multi-key deadlock; the public interface remains user-ID keyed so a
future Postgres advisory-lock implementation can safely increase concurrency.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import ContextManager, Iterator, Protocol


class UserOperationLockTimeout(RuntimeError):
    """Raised when a shared user-operation lock cannot be acquired in time."""


class UserOperationLocks(Protocol):
    """Serialize mutations that involve one or more Keycloak user IDs."""

    def hold(self, *user_ids: str) -> ContextManager[None]:
        """Return a context manager holding the requested user-operation locks."""
        ...


def _normalise_user_ids(user_ids: tuple[str, ...]) -> tuple[str, ...]:
    """Return unique, non-empty user IDs in deterministic acquisition order."""
    ordered = tuple(sorted(set(user_ids)))
    if not ordered or any(not user_id for user_id in ordered):
        raise ValueError("at least one non-empty user ID is required")
    return ordered


class InMemoryUserOperationLocks:
    """Process-local keyed lock manager for tests and explicit single-worker use."""

    def __init__(self) -> None:
        """Create an empty keyed re-entrant lock registry."""
        self._registry_guard = threading.Lock()
        self._locks: dict[str, threading.RLock] = {}

    @contextmanager
    def hold(self, *user_ids: str) -> Iterator[None]:
        """Hold all requested user locks in stable order to avoid deadlocks."""
        ordered_ids = _normalise_user_ids(user_ids)
        with self._registry_guard:
            locks = [
                self._locks.setdefault(user_id, threading.RLock())
                for user_id in ordered_ids
            ]
        for lock in locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()


class SqliteUserOperationLocks:
    """Cross-process mutex backed by a dedicated SQLite sidecar database.

    SQLite permits only one writer holding a ``BEGIN IMMEDIATE`` transaction.
    Every manager instance pointed at the same database file therefore shares a
    crash-safe mutex: process termination closes the connection and releases the
    lock automatically. This is deliberately coarser than the user-ID-keyed
    protocol, but it fully serializes the SCIM and merge critical sections for
    the supported SQLite deployment without introducing a lease-expiry race.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS user_operation_lock_state (
        lock_name TEXT PRIMARY KEY,
        requested_user_ids TEXT NOT NULL
    );
    """

    def __init__(self, database_path: str, *, timeout_seconds: float = 10.0) -> None:
        """Create a manager using ``database_path`` and an acquisition timeout."""
        if not database_path:
            raise ValueError("database_path is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._database_path = database_path
        self._timeout_seconds = timeout_seconds
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        """Open one autocommit connection configured with the lock timeout."""
        return sqlite3.connect(
            self._database_path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )

    def _initialize(self) -> None:
        """Create the sidecar schema before requests begin competing for it."""
        connection = self._connect()
        try:
            connection.execute(self._SCHEMA)
        finally:
            connection.close()

    @contextmanager
    def hold(self, *user_ids: str) -> Iterator[None]:
        """Hold the shared SQLite mutex for the complete user mutation."""
        ordered_ids = _normalise_user_ids(user_ids)
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower():
                    raise UserOperationLockTimeout(
                        "timed out waiting for another user mutation to finish"
                    ) from exc
                raise
            connection.execute(
                "INSERT INTO user_operation_lock_state "
                "(lock_name, requested_user_ids) VALUES ('global', ?) "
                "ON CONFLICT(lock_name) DO UPDATE SET "
                "requested_user_ids = excluded.requested_user_ids",
                (",".join(ordered_ids),),
            )
            yield
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
