"""Config/secret store abstraction (KV/DB), the ONLY source of runtime config.

The service never calls ``os.getenv`` for real configuration or secrets. It
reads a single bootstrap pointer (see :mod:`app.bootstrap`) that names one of
these backends, then loads everything else from here. DB objects use two-word
snake_case names (``idp_config_entries`` with columns ``entry_key`` /
``entry_value``).
"""
from __future__ import annotations

import sqlite3
from typing import Protocol


class KvStore(Protocol):
    """Read interface for the config/secret store."""

    def get(self, namespace: str, entry_key: str) -> str | None:
        """Return the value for ``entry_key`` in ``namespace`` or ``None``."""
        ...

    def get_all(self, namespace: str) -> dict[str, str]:
        """Return every entry in ``namespace`` as a dict."""
        ...


class InMemoryKvStore:
    """Dict-backed store for tests and ephemeral bootstrap shims."""

    def __init__(self, seed: dict[str, dict[str, str]] | None = None) -> None:
        self._data: dict[str, dict[str, str]] = {}
        if seed:
            for namespace, entries in seed.items():
                self._data[namespace] = dict(entries)

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        self._data.setdefault(namespace, {})[entry_key] = entry_value

    def get(self, namespace: str, entry_key: str) -> str | None:
        return self._data.get(namespace, {}).get(entry_key)

    def get_all(self, namespace: str) -> dict[str, str]:
        return dict(self._data.get(namespace, {}))


class SqliteKvStore:
    """SQLite-backed store for standalone / dev deployments.

    Table ``idp_config_entries`` is keyed by (``config_namespace``,
    ``entry_key``). Values are stored as text; secret handling (encryption at
    rest, rotation) is delegated to the platform for the postgres backend.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS idp_config_entries (
        config_namespace TEXT NOT NULL,
        entry_key        TEXT NOT NULL,
        entry_value      TEXT NOT NULL,
        PRIMARY KEY (config_namespace, entry_key)
    );
    """

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        self._connection = sqlite3.connect(database_path)
        self._connection.execute(self._SCHEMA)
        self._connection.commit()

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        self._connection.execute(
            "INSERT INTO idp_config_entries (config_namespace, entry_key, entry_value) "
            "VALUES (?, ?, ?) ON CONFLICT(config_namespace, entry_key) "
            "DO UPDATE SET entry_value = excluded.entry_value",
            (namespace, entry_key, entry_value),
        )
        self._connection.commit()

    def get(self, namespace: str, entry_key: str) -> str | None:
        row = self._connection.execute(
            "SELECT entry_value FROM idp_config_entries "
            "WHERE config_namespace = ? AND entry_key = ?",
            (namespace, entry_key),
        ).fetchone()
        return row[0] if row else None

    def get_all(self, namespace: str) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT entry_key, entry_value FROM idp_config_entries "
            "WHERE config_namespace = ?",
            (namespace,),
        ).fetchall()
        return {entry_key: entry_value for entry_key, entry_value in rows}

    def close(self) -> None:
        self._connection.close()
