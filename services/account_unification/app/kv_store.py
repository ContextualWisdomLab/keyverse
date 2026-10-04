"""Thread-safe config/secret store abstraction, the runtime source of truth.

The service never reads scattered environment variables for real configuration
or secrets. Database objects use two-word snake_case names, including
``idp_config_entries`` and its ``entry_key`` / ``entry_value`` columns.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Collection, Mapping
from typing import Protocol


class KvStore(Protocol):
    """Read/write interface for the configuration and secret store."""

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        """Store one value in one namespace."""
        ...

    def put_many(self, namespace: str, entries: Mapping[str, str]) -> None:
        """Store multiple values in one namespace atomically."""
        ...

    def replace_many(
        self,
        namespace: str,
        entries: Mapping[str, str],
        delete_keys: Collection[str],
    ) -> None:
        """Upsert values and delete keys in one atomic operation."""
        ...

    def compare_and_replace(
        self,
        namespace: str,
        expected: Mapping[str, str | None],
        entries: Mapping[str, str],
        delete_keys: Collection[str] = (),
    ) -> bool:
        """Atomically check exact values (None means absent), then replace them.

        Every changed key must have an expectation. A mismatch returns False
        without any write; storage errors propagate after atomic rollback.
        """
        ...

    def get(self, namespace: str, entry_key: str) -> str | None:
        """Return a value or ``None`` when it is absent."""
        ...

    def get_all(self, namespace: str) -> dict[str, str]:
        """Return every entry in one namespace."""
        ...

    def get_all_namespaces(self, namespaces: Collection[str]) -> dict[str, dict[str, str]]:
        """Return detached entries for requested namespaces at one read instant.

        Include absent namespaces as empty dicts, collapse duplicates, and return
        an empty dict for no namespaces. Unrequested namespaces are excluded.
        """
        ...

    def delete(self, namespace: str, entry_key: str) -> None:
        """Remove one entry if present."""
        ...

    def close(self) -> None:
        """Release resources held by the store."""
        ...


class InMemoryKvStore:
    """Thread-safe dict-backed store for tests and ephemeral bootstrap shims."""

    def __init__(self, seed: dict[str, dict[str, str]] | None = None) -> None:
        """Create a store seeded by namespace and entry key."""
        self._lock = threading.RLock()
        self._data: dict[str, dict[str, str]] = {}
        if seed:
            for namespace, entries in seed.items():
                self._data[namespace] = dict(entries)

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        """Store one value in one namespace."""
        with self._lock:
            self._data.setdefault(namespace, {})[entry_key] = entry_value

    def put_many(self, namespace: str, entries: Mapping[str, str]) -> None:
        """Store multiple values in one namespace under one lock."""
        with self._lock:
            self._data.setdefault(namespace, {}).update(entries)

    def replace_many(
        self,
        namespace: str,
        entries: Mapping[str, str],
        delete_keys: Collection[str],
    ) -> None:
        """Upsert and delete values under one lock."""
        with self._lock:
            values = self._data.setdefault(namespace, {})
            values.update(entries)
            for entry_key in delete_keys:
                values.pop(entry_key, None)

    def compare_and_replace(
        self,
        namespace: str,
        expected: Mapping[str, str | None],
        entries: Mapping[str, str],
        delete_keys: Collection[str] = (),
    ) -> bool:
        """Check and replace a namespace generation under one memory-store lock."""
        if not (set(entries) | set(delete_keys)) <= set(expected):
            raise ValueError("every changed key requires an expected value")
        with self._lock:
            values = self._data.get(namespace, {})
            if any(values.get(key) != value for key, value in expected.items()):
                return False
            before = dict(values)
            try:
                if delete_keys:
                    self.replace_many(namespace, entries, delete_keys)
                elif len(entries) == 1:
                    key, value = next(iter(entries.items()))
                    self.put(namespace, key, value)
                else:
                    self.put_many(namespace, entries)
            except BaseException:
                self._data[namespace] = before
                raise
            return True

    def get(self, namespace: str, entry_key: str) -> str | None:
        """Return one value from one namespace, if present."""
        with self._lock:
            return self._data.get(namespace, {}).get(entry_key)

    def get_all(self, namespace: str) -> dict[str, str]:
        """Return a copy of every value in one namespace."""
        with self._lock:
            return dict(self._data.get(namespace, {}))

    def get_all_namespaces(self, namespaces: Collection[str]) -> dict[str, dict[str, str]]:
        """Copy all requested namespace entries while holding one store lock."""
        with self._lock:
            return {namespace: dict(self._data.get(namespace, {})) for namespace in namespaces}

    def delete(self, namespace: str, entry_key: str) -> None:
        """Remove one value from one namespace if present."""
        with self._lock:
            self._data.get(namespace, {}).pop(entry_key, None)

    def close(self) -> None:
        """Release no-op in-memory resources."""


class SqliteKvStore:
    """SQLite-backed store for standalone and development deployments."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS idp_config_entries (
        config_namespace TEXT NOT NULL,
        entry_key        TEXT NOT NULL,
        entry_value      TEXT NOT NULL,
        PRIMARY KEY (config_namespace, entry_key)
    );
    """

    def __init__(self, database_path: str) -> None:
        """Open the SQLite store and ensure the config table exists."""
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

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        """Upsert one config value."""
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO idp_config_entries "
                "(config_namespace, entry_key, entry_value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(config_namespace, entry_key) "
                "DO UPDATE SET entry_value = excluded.entry_value",
                (namespace, entry_key, entry_value),
            )

    def put_many(self, namespace: str, entries: Mapping[str, str]) -> None:
        """Upsert multiple config values in one SQLite transaction."""
        with self._lock, self._connection:
            self._connection.executemany(
                "INSERT INTO idp_config_entries "
                "(config_namespace, entry_key, entry_value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(config_namespace, entry_key) "
                "DO UPDATE SET entry_value = excluded.entry_value",
                ((namespace, entry_key, entry_value) for entry_key, entry_value in entries.items()),
            )

    def replace_many(
        self,
        namespace: str,
        entries: Mapping[str, str],
        delete_keys: Collection[str],
    ) -> None:
        """Upsert and delete config values in one SQLite transaction."""
        with self._lock, self._connection:
            self._connection.executemany(
                "INSERT INTO idp_config_entries "
                "(config_namespace, entry_key, entry_value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(config_namespace, entry_key) "
                "DO UPDATE SET entry_value = excluded.entry_value",
                ((namespace, entry_key, entry_value) for entry_key, entry_value in entries.items()),
            )
            for entry_key in delete_keys:
                self._connection.execute(
                    "DELETE FROM idp_config_entries "
                    "WHERE config_namespace = ? AND entry_key = ?",
                    (namespace, entry_key),
                )

    def compare_and_replace(
        self,
        namespace: str,
        expected: Mapping[str, str | None],
        entries: Mapping[str, str],
        delete_keys: Collection[str] = (),
    ) -> bool:
        """Compare and mutate after BEGIN IMMEDIATE, without external callbacks.

        SQLite serializes independent writers before the expected-state reads.
        The existing busy timeout bounds lock waiting. The connection context
        rolls back read/write errors; no writer transaction spans audit I/O.
        """
        if not (set(entries) | set(delete_keys)) <= set(expected):
            raise ValueError("every changed key requires an expected value")
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            for key, value in expected.items():
                row = self._connection.execute(
                    "SELECT entry_value FROM idp_config_entries "
                    "WHERE config_namespace = ? AND entry_key = ?",
                    (namespace, key),
                ).fetchone()
                if (row[0] if row else None) != value:
                    return False
            self._connection.executemany(
                "INSERT INTO idp_config_entries "
                "(config_namespace, entry_key, entry_value) VALUES (?, ?, ?) "
                "ON CONFLICT(config_namespace, entry_key) "
                "DO UPDATE SET entry_value = excluded.entry_value",
                ((namespace, key, value) for key, value in entries.items()),
            )
            self._connection.executemany(
                "DELETE FROM idp_config_entries "
                "WHERE config_namespace = ? AND entry_key = ?",
                ((namespace, key) for key in delete_keys),
            )
            return True

    def get(self, namespace: str, entry_key: str) -> str | None:
        """Return one config value, if present."""
        with self._lock:
            row = self._connection.execute(
                "SELECT entry_value FROM idp_config_entries "
                "WHERE config_namespace = ? AND entry_key = ?",
                (namespace, entry_key),
            ).fetchone()
        return row[0] if row else None

    def get_all(self, namespace: str) -> dict[str, str]:
        """Return every config value in one namespace."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT entry_key, entry_value FROM idp_config_entries "
                "WHERE config_namespace = ?",
                (namespace,),
            ).fetchall()
        return {entry_key: entry_value for entry_key, entry_value in rows}

    def get_all_namespaces(self, namespaces: Collection[str]) -> dict[str, dict[str, str]]:
        """Copy requested namespaces from one SQLite SELECT snapshot.

        The instance lock protects this connection, not other connections or
        processes. SQLite supplies read coherence through the single statement.
        """
        values: dict[str, dict[str, str]] = {namespace: {} for namespace in namespaces}
        if not values:
            return values
        placeholders = ", ".join("?" for _ in values)
        with self._lock:
            rows = self._connection.execute(
                "SELECT config_namespace, entry_key, entry_value FROM idp_config_entries "
                f"WHERE config_namespace IN ({placeholders})",
                tuple(values),
            ).fetchall()
        for namespace, entry_key, entry_value in rows:
            values[namespace][entry_key] = entry_value
        return values

    def delete(self, namespace: str, entry_key: str) -> None:
        """Remove one config value from one namespace if present."""
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM idp_config_entries "
                "WHERE config_namespace = ? AND entry_key = ?",
                (namespace, entry_key),
            )

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()
