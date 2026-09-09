"""Keyvault: namespaced encrypted-at-rest secret storage and KDF recovery.

The storage boundary is intentionally separate from identity and authorization.
Each durable vault persists its own KDF parameters so equal passphrases do not
produce one organization-wide encryption key. The legacy fixed salt exists only
for an explicit one-shot migration of ciphertext produced by the unreleased
feature branch; normal startup never falls back to it.
"""
from __future__ import annotations

import base64
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretNotFoundError(KeyError):
    """Raised when a Keyvault read or delete targets an absent secret."""


class LegacyKeyvaultMigrationRequiredError(RuntimeError):
    """Raised when legacy ciphertext exists without durable KDF parameters."""


_KEYVAULT_KDF_VERSION = 1
_KEYVAULT_KDF_ITERATIONS = 600_000
_KEYVAULT_KDF_SALT_BYTES = 32
_LEGACY_KEYVAULT_KDF_SALT = (
    b"keyverse.account_unification.keyvault.fernet-key-derivation.v1"
)


@dataclass(frozen=True)
class KeyvaultKdfParameters:
    """Durable parameters required to reconstruct one vault encryption key."""

    version: int
    iterations: int
    salt: bytes


def _validate_kdf_parameters(parameters: KeyvaultKdfParameters) -> None:
    """Reject unsupported or weakened persisted KDF configuration."""
    if parameters.version != _KEYVAULT_KDF_VERSION:
        raise RuntimeError("unsupported Keyvault KDF version")
    if parameters.iterations < _KEYVAULT_KDF_ITERATIONS:
        raise RuntimeError("Keyvault KDF iteration count is below the supported minimum")
    if len(parameters.salt) < _KEYVAULT_KDF_SALT_BYTES:
        raise RuntimeError("Keyvault KDF salt is shorter than the supported minimum")


def derive_fernet_key(
    passphrase: str,
    parameters: KeyvaultKdfParameters,
) -> bytes:
    """Derive the Fernet key using one vault's persisted PBKDF2 parameters."""
    _validate_kdf_parameters(parameters)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=parameters.salt,
        iterations=parameters.iterations,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def legacy_fernet_key_for_migration(passphrase: str) -> bytes:
    """Derive the old feature-branch key only for explicit controlled rewrap."""
    parameters = KeyvaultKdfParameters(
        version=_KEYVAULT_KDF_VERSION,
        iterations=_KEYVAULT_KDF_ITERATIONS,
        salt=_LEGACY_KEYVAULT_KDF_SALT,
    )
    return derive_fernet_key(passphrase, parameters)


@dataclass(frozen=True)
class SecretMetadata:
    """Non-secret listing information: never carries the decrypted value."""

    namespace: str
    secret_key: str
    updated_at: float


class KeyvaultStore(Protocol):
    """Atomic persistence contract for encrypted secrets and their audit trail."""

    def put(
        self, namespace: str, secret_key: str, encrypted_value: bytes, *, actor: str
    ) -> None:
        """Atomically upsert one encrypted secret and its audit event."""
        ...

    def get(self, namespace: str, secret_key: str) -> bytes | None:
        """Return one encrypted secret's ciphertext, or ``None`` if absent."""
        ...

    def list_keys(self, namespace: str) -> list[SecretMetadata]:
        """Return metadata (never ciphertext or plaintext) for one namespace."""
        ...

    def list_namespaces(self) -> list[str]:
        """Return namespaces that currently contain at least one secret."""
        ...

    def delete(self, namespace: str, secret_key: str, *, actor: str) -> bool:
        """Atomically remove one secret and append its audit event."""
        ...

    def record_read(self, namespace: str, secret_key: str, *, actor: str) -> None:
        """Append a successful-read audit event."""
        ...

    def events_for(self, namespace: str, secret_key: str) -> list[dict]:
        """Return recorded events for one secret in write order."""
        ...

    def close(self) -> None:
        """Release resources held by the store."""
        ...


class InMemoryKeyvaultStore:
    """Thread-safe dict-backed store for tests and the dev/mock path."""

    def __init__(self) -> None:
        """Create an empty in-memory encrypted-secret table."""
        self._lock = threading.RLock()
        self._data: dict[tuple[str, str], tuple[bytes, float]] = {}
        self._events: list[dict] = []

    def put(
        self, namespace: str, secret_key: str, encrypted_value: bytes, *, actor: str
    ) -> None:
        """Atomically upsert one encrypted secret and its audit event."""
        with self._lock:
            self._data[(namespace, secret_key)] = (encrypted_value, time.time())
            self._record(namespace, secret_key, "secret_set", actor)

    def get(self, namespace: str, secret_key: str) -> bytes | None:
        """Return one secret's ciphertext, or ``None`` if absent."""
        with self._lock:
            entry = self._data.get((namespace, secret_key))
            return None if entry is None else entry[0]

    def list_keys(self, namespace: str) -> list[SecretMetadata]:
        """Return metadata for every secret in ``namespace``."""
        with self._lock:
            return [
                SecretMetadata(namespace=ns, secret_key=key, updated_at=updated_at)
                for (ns, key), (_value, updated_at) in self._data.items()
                if ns == namespace
            ]

    def list_namespaces(self) -> list[str]:
        """Return non-empty namespaces in stable order."""
        with self._lock:
            return sorted({namespace for namespace, _secret_key in self._data})

    def delete(self, namespace: str, secret_key: str, *, actor: str) -> bool:
        """Atomically remove one secret and append its audit event."""
        with self._lock:
            deleted = self._data.pop((namespace, secret_key), None) is not None
            if deleted:
                self._record(namespace, secret_key, "secret_deleted", actor)
            return deleted

    def record_read(self, namespace: str, secret_key: str, *, actor: str) -> None:
        """Append one successful-read event."""
        with self._lock:
            self._record(namespace, secret_key, "secret_read", actor)

    def events_for(self, namespace: str, secret_key: str) -> list[dict]:
        """Return recorded events for one secret in write order."""
        with self._lock:
            return [
                dict(event)
                for event in self._events
                if event["namespace"] == namespace and event["secret_key"] == secret_key
            ]

    def _record(self, namespace: str, secret_key: str, action: str, actor: str) -> None:
        """Append one event while the caller holds ``_lock``."""
        self._events.append(
            {
                "namespace": namespace,
                "secret_key": secret_key,
                "action": action,
                "actor": actor,
                "created_at": time.time(),
            }
        )

    def close(self) -> None:
        """Release no-op in-memory resources."""


class SqliteKeyvaultStore:
    """Durable encrypted-secret store with per-vault KDF recovery metadata."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS keyvault_secrets (
        secret_namespace TEXT NOT NULL,
        secret_key       TEXT NOT NULL,
        encrypted_value  BLOB NOT NULL,
        updated_at       REAL NOT NULL,
        PRIMARY KEY (secret_namespace, secret_key)
    );
    CREATE TABLE IF NOT EXISTS keyvault_audit_log (
        event_sequence   INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_namespace TEXT NOT NULL,
        secret_key       TEXT NOT NULL,
        action           TEXT NOT NULL,
        actor            TEXT NOT NULL,
        created_at       REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS keyvault_kdf_config (
        config_slot      INTEGER PRIMARY KEY CHECK (config_slot = 1),
        kdf_version      INTEGER NOT NULL,
        iteration_count  INTEGER NOT NULL,
        salt             BLOB NOT NULL,
        created_at       REAL NOT NULL
    );
    """

    def __init__(self, database_path: str) -> None:
        """Open the Keyvault database and ensure its tables exist."""
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
            self._connection.executescript(self._SCHEMA)
            self._connection.commit()

    def _load_kdf_parameters(self) -> KeyvaultKdfParameters | None:
        """Load the persisted singleton KDF configuration."""
        row = self._connection.execute(
            "SELECT kdf_version, iteration_count, salt "
            "FROM keyvault_kdf_config WHERE config_slot = 1"
        ).fetchone()
        if row is None:
            return None
        parameters = KeyvaultKdfParameters(
            version=int(row[0]),
            iterations=int(row[1]),
            salt=bytes(row[2]),
        )
        _validate_kdf_parameters(parameters)
        return parameters

    def load_or_create_kdf_parameters(self) -> KeyvaultKdfParameters:
        """Load durable KDF parameters or initialize a provably empty vault."""
        with self._lock, self._connection:
            existing = self._load_kdf_parameters()
            if existing is not None:
                return existing
            secret_count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM keyvault_secrets"
                ).fetchone()[0]
            )
            if secret_count:
                raise LegacyKeyvaultMigrationRequiredError(
                    "legacy Keyvault ciphertext requires explicit rewrap"
                )
            parameters = KeyvaultKdfParameters(
                version=_KEYVAULT_KDF_VERSION,
                iterations=_KEYVAULT_KDF_ITERATIONS,
                salt=secrets.token_bytes(_KEYVAULT_KDF_SALT_BYTES),
            )
            self._connection.execute(
                "INSERT INTO keyvault_kdf_config "
                "(config_slot, kdf_version, iteration_count, salt, created_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (
                    parameters.version,
                    parameters.iterations,
                    parameters.salt,
                    time.time(),
                ),
            )
            return parameters

    def migrate_legacy_kdf(
        self,
        passphrase: str,
        *,
        actor: str,
    ) -> KeyvaultKdfParameters:
        """Explicitly rewrap unreleased fixed-salt ciphertext into a fresh vault KDF."""
        with self._lock, self._connection:
            existing = self._load_kdf_parameters()
            if existing is not None:
                raise RuntimeError("Keyvault KDF parameters are already initialized")
            rows = self._connection.execute(
                "SELECT secret_namespace, secret_key, encrypted_value "
                "FROM keyvault_secrets ORDER BY secret_namespace, secret_key"
            ).fetchall()
            if not rows:
                return self.load_or_create_kdf_parameters()

            legacy_fernet = Fernet(legacy_fernet_key_for_migration(passphrase))
            plaintext_rows = [
                (str(namespace), str(secret_key), legacy_fernet.decrypt(bytes(ciphertext)))
                for namespace, secret_key, ciphertext in rows
            ]
            parameters = KeyvaultKdfParameters(
                version=_KEYVAULT_KDF_VERSION,
                iterations=_KEYVAULT_KDF_ITERATIONS,
                salt=secrets.token_bytes(_KEYVAULT_KDF_SALT_BYTES),
            )
            replacement_fernet = Fernet(derive_fernet_key(passphrase, parameters))
            migrated_at = time.time()
            for namespace, secret_key, plaintext in plaintext_rows:
                self._connection.execute(
                    "UPDATE keyvault_secrets SET encrypted_value = ?, updated_at = ? "
                    "WHERE secret_namespace = ? AND secret_key = ?",
                    (
                        replacement_fernet.encrypt(plaintext),
                        migrated_at,
                        namespace,
                        secret_key,
                    ),
                )
                self._insert_event(
                    namespace,
                    secret_key,
                    "secret_rewrapped",
                    actor,
                    migrated_at,
                )
            self._connection.execute(
                "INSERT INTO keyvault_kdf_config "
                "(config_slot, kdf_version, iteration_count, salt, created_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (
                    parameters.version,
                    parameters.iterations,
                    parameters.salt,
                    migrated_at,
                ),
            )
            return parameters

    def put(
        self, namespace: str, secret_key: str, encrypted_value: bytes, *, actor: str
    ) -> None:
        """Atomically upsert one encrypted secret and its audit event."""
        with self._lock, self._connection:
            updated_at = time.time()
            self._connection.execute(
                "INSERT INTO keyvault_secrets "
                "(secret_namespace, secret_key, encrypted_value, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(secret_namespace, secret_key) DO UPDATE SET "
                "encrypted_value = excluded.encrypted_value, "
                "updated_at = excluded.updated_at",
                (namespace, secret_key, encrypted_value, updated_at),
            )
            self._insert_event(namespace, secret_key, "secret_set", actor, updated_at)

    def get(self, namespace: str, secret_key: str) -> bytes | None:
        """Return one secret's ciphertext, or ``None`` if absent."""
        with self._lock:
            row = self._connection.execute(
                "SELECT encrypted_value FROM keyvault_secrets "
                "WHERE secret_namespace = ? AND secret_key = ?",
                (namespace, secret_key),
            ).fetchone()
        return None if row is None else bytes(row[0])

    def list_keys(self, namespace: str) -> list[SecretMetadata]:
        """Return metadata for every secret in ``namespace``, key-ordered."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT secret_key, updated_at FROM keyvault_secrets "
                "WHERE secret_namespace = ? ORDER BY secret_key",
                (namespace,),
            ).fetchall()
        return [
            SecretMetadata(namespace=namespace, secret_key=row[0], updated_at=row[1])
            for row in rows
        ]

    def list_namespaces(self) -> list[str]:
        """Return non-empty namespaces in stable order."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT DISTINCT secret_namespace FROM keyvault_secrets "
                "ORDER BY secret_namespace"
            ).fetchall()
        return [row[0] for row in rows]

    def delete(self, namespace: str, secret_key: str, *, actor: str) -> bool:
        """Atomically remove one secret and append its audit event."""
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM keyvault_secrets "
                "WHERE secret_namespace = ? AND secret_key = ?",
                (namespace, secret_key),
            )
            deleted = cursor.rowcount > 0
            if deleted:
                self._insert_event(namespace, secret_key, "secret_deleted", actor)
            return deleted

    def record_read(self, namespace: str, secret_key: str, *, actor: str) -> None:
        """Append one successful-read event."""
        with self._lock, self._connection:
            self._insert_event(namespace, secret_key, "secret_read", actor)

    def events_for(self, namespace: str, secret_key: str) -> list[dict]:
        """Load events for one secret in write order."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT secret_namespace, secret_key, action, actor, created_at "
                "FROM keyvault_audit_log WHERE secret_namespace = ? AND secret_key = ? "
                "ORDER BY event_sequence",
                (namespace, secret_key),
            ).fetchall()
        return [
            {
                "namespace": row[0],
                "secret_key": row[1],
                "action": row[2],
                "actor": row[3],
                "created_at": row[4],
            }
            for row in rows
        ]

    def _insert_event(
        self,
        namespace: str,
        secret_key: str,
        action: str,
        actor: str,
        created_at: float | None = None,
    ) -> None:
        """Insert one event on the caller's active transaction."""
        self._connection.execute(
            "INSERT INTO keyvault_audit_log "
            "(secret_namespace, secret_key, action, actor, created_at) VALUES (?, ?, ?, ?, ?)",
            (namespace, secret_key, action, actor, created_at or time.time()),
        )

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()


class KeyvaultService:
    """Encrypt/decrypt at the service boundary; audit each successful access."""

    def __init__(self, store: KeyvaultStore, fernet_key: bytes) -> None:
        """Wire one atomic storage backend and the encryption key."""
        self._store = store
        self._fernet = Fernet(fernet_key)

    def put_secret(
        self, namespace: str, secret_key: str, value: str, *, actor: str
    ) -> SecretMetadata:
        """Encrypt and store one secret; record a ``secret_set`` audit event."""
        encrypted = self._fernet.encrypt(value.encode("utf-8"))
        self._store.put(namespace, secret_key, encrypted, actor=actor)
        return self._require_metadata(namespace, secret_key)

    def get_secret(self, namespace: str, secret_key: str, *, actor: str) -> str:
        """Decrypt and return one secret; record a successful-read audit event."""
        encrypted = self._store.get(namespace, secret_key)
        if encrypted is None:
            raise SecretNotFoundError(f"{namespace}/{secret_key}")
        value = self._fernet.decrypt(encrypted).decode("utf-8")
        self._store.record_read(namespace, secret_key, actor=actor)
        return value

    def list_secrets(self, namespace: str) -> list[SecretMetadata]:
        """Return metadata (never values) for every secret in ``namespace``."""
        return self._store.list_keys(namespace)

    def list_namespaces(self) -> list[str]:
        """Return non-empty consumer namespaces without secret material."""
        return self._store.list_namespaces()

    def delete_secret(self, namespace: str, secret_key: str, *, actor: str) -> None:
        """Delete one secret; record a ``secret_deleted`` audit event."""
        deleted = self._store.delete(namespace, secret_key, actor=actor)
        if not deleted:
            raise SecretNotFoundError(f"{namespace}/{secret_key}")

    def audit_history(self, namespace: str, secret_key: str) -> list[dict]:
        """Return the recorded access history for one secret."""
        return self._store.events_for(namespace, secret_key)

    def _require_metadata(self, namespace: str, secret_key: str) -> SecretMetadata:
        """Return the just-written secret's metadata row."""
        for metadata in self._store.list_keys(namespace):
            if metadata.secret_key == secret_key:
                return metadata
        raise SecretNotFoundError(f"{namespace}/{secret_key}")  # pragma: no cover

    def close(self) -> None:
        """Release the wrapped store."""
        self._store.close()
