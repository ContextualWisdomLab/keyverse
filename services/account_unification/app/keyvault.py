"""Keyvault: a namespaced, encrypted-at-rest secrets store.

Bounded-context note (see ``docs/adr/0014-keyverse-keyvault-bounded-context.md``):
identity/authentication (Keycloak plus this service's other IdP-facing
modules -- ``relying_party_admin.py``, ``authorization_plane.py`` on the
``feat/authorization`` line) and secrets storage are historically separate
concerns even inside mature IdP platforms (Keycloak != HashiCorp Vault).
Rather than growing ``kv_store.py``'s ``idp_config_entries`` table -- which is
this service's own internal configuration, read at startup, never a
generic secret-storage product surface -- this module owns a dedicated table
and reuses only the *pattern* already proven by ``kv_store.py`` and
``audit.py`` (a small ``Protocol`` + in-memory/SQLite backends, WAL mode,
``busy_timeout``). That pattern, not any shared table, is the deliberately
minimal Shared Kernel between the two bounded contexts.

A namespace here identifies the *consumer* of a secret (typically one CWL
service or one deployment-scoped concern), never an end user or a Keycloak
realm object. Values are Fernet-encrypted before they reach SQLite; the
passphrase used to derive the encryption key is bootstrap transport only
(``config.py``'s ``keyvault_passphrase``, itself read from the KV/DB config
store, never a raw environment variable read at request time -- the same "KV,
not env" discipline contextual-orchestrator's ``credentials.py`` documents
for its own provider-credential registry).
"""
from __future__ import annotations

import base64
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


# Fixed, context-specific salt: not a secret (PBKDF2 salts need only be
# unique per use-context, not hidden -- OWASP Password Storage Cheat
# Sheet), but domain-separates this KDF use from any other passphrase-derived
# key in the org so a precomputed table built against one cannot be reused
# against the other. Fixed (not per-installation) so derive_fernet_key stays
# deterministic for a given passphrase with the existing single-argument
# signature -- this module has exactly one caller (``main.py`` at bootstrap)
# and no salt-storage location to thread a per-install value through.
_KEYVAULT_KDF_SALT = b"keyverse.account_unification.keyvault.fernet-key-derivation.v1"
# OWASP's 2023 minimum recommendation for PBKDF2-HMAC-SHA256.
_KEYVAULT_KDF_ITERATIONS = 600_000


def derive_fernet_key(passphrase: str) -> bytes:
    """Derive a urlsafe-base64 Fernet key from an operator passphrase.

    Uses PBKDF2-HMAC-SHA256 (not a bare SHA-256 digest -- CodeQL correctly
    flags that as too fast/computationally cheap to resist brute-force
    against a human-chosen passphrase) to give Fernet (which requires a
    32-byte urlsafe-base64 key) a fixed-length key from an arbitrary-length
    passphrase. The passphrase itself is read once at process bootstrap and
    is never logged, returned, or persisted anywhere by this module.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KEYVAULT_KDF_SALT,
        iterations=_KEYVAULT_KDF_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


@dataclass(frozen=True)
class SecretMetadata:
    """Non-secret listing information: never carries the decrypted value."""

    namespace: str
    secret_key: str
    updated_at: float


class KeyvaultStore(Protocol):
    """Persistence contract for the encrypted secrets table."""

    def put(self, namespace: str, secret_key: str, encrypted_value: bytes) -> None:
        """Upsert one already-encrypted secret."""
        ...

    def get(self, namespace: str, secret_key: str) -> bytes | None:
        """Return one encrypted secret's ciphertext, or ``None`` if absent."""
        ...

    def list_keys(self, namespace: str) -> list[SecretMetadata]:
        """Return metadata (never ciphertext or plaintext) for one namespace."""
        ...

    def delete(self, namespace: str, secret_key: str) -> bool:
        """Remove one secret; return whether a row was actually deleted."""
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

    def put(self, namespace: str, secret_key: str, encrypted_value: bytes) -> None:
        """Upsert one already-encrypted secret with a fresh timestamp."""
        with self._lock:
            self._data[(namespace, secret_key)] = (encrypted_value, time.time())

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

    def delete(self, namespace: str, secret_key: str) -> bool:
        """Remove one secret; return whether it was present."""
        with self._lock:
            return self._data.pop((namespace, secret_key), None) is not None

    def close(self) -> None:
        """Release no-op in-memory resources."""


class SqliteKeyvaultStore:
    """Durable encrypted-secret table, independent of ``idp_config_entries``."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS keyvault_secrets (
        secret_namespace TEXT NOT NULL,
        secret_key       TEXT NOT NULL,
        encrypted_value  BLOB NOT NULL,
        updated_at       REAL NOT NULL,
        PRIMARY KEY (secret_namespace, secret_key)
    );
    """

    def __init__(self, database_path: str) -> None:
        """Open the Keyvault database and ensure its table exists."""
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

    def put(self, namespace: str, secret_key: str, encrypted_value: bytes) -> None:
        """Upsert one already-encrypted secret and refresh its timestamp."""
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO keyvault_secrets "
                "(secret_namespace, secret_key, encrypted_value, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(secret_namespace, secret_key) DO UPDATE SET "
                "encrypted_value = excluded.encrypted_value, "
                "updated_at = excluded.updated_at",
                (namespace, secret_key, encrypted_value, time.time()),
            )

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

    def delete(self, namespace: str, secret_key: str) -> bool:
        """Remove one secret; return whether a row actually existed."""
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM keyvault_secrets "
                "WHERE secret_namespace = ? AND secret_key = ?",
                (namespace, secret_key),
            )
            return cursor.rowcount > 0

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()


class KeyvaultAuditSink(Protocol):
    """Persistence contract for append-only Keyvault access events.

    Deliberately its own event shape (namespace/secret_key/action/actor),
    separate from ``audit.AuditEvent``'s merge-correlation shape
    (survivor/duplicate user ids) -- a Keyvault write has no survivor and
    forcing one schema onto the other would blur two different Aggregates.
    The value itself is never part of an audit event.
    """

    def record(
        self, *, namespace: str, secret_key: str, action: str, actor: str
    ) -> None:
        """Append one Keyvault access event."""
        ...

    def events_for(self, namespace: str, secret_key: str) -> list[dict]:
        """Return recorded events for one secret, in write order."""
        ...

    def close(self) -> None:
        """Release resources held by the sink."""
        ...


class InMemoryKeyvaultAuditSink:
    """Thread-safe in-memory Keyvault audit sink for tests and dev."""

    def __init__(self) -> None:
        """Create an empty in-memory event list."""
        self._lock = threading.RLock()
        self._events: list[dict] = []

    def record(
        self, *, namespace: str, secret_key: str, action: str, actor: str
    ) -> None:
        """Append one event with a fresh timestamp."""
        with self._lock:
            self._events.append(
                {
                    "namespace": namespace,
                    "secret_key": secret_key,
                    "action": action,
                    "actor": actor,
                    "created_at": time.time(),
                }
            )

    def events_for(self, namespace: str, secret_key: str) -> list[dict]:
        """Return recorded events for one secret, in write order."""
        with self._lock:
            return [
                dict(event)
                for event in self._events
                if event["namespace"] == namespace and event["secret_key"] == secret_key
            ]

    def close(self) -> None:
        """Release no-op in-memory resources."""


class SqliteKeyvaultAuditSink:
    """Durable append-only Keyvault audit sink."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS keyvault_audit_log (
        event_sequence   INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_namespace TEXT NOT NULL,
        secret_key       TEXT NOT NULL,
        action           TEXT NOT NULL,
        actor            TEXT NOT NULL,
        created_at       REAL NOT NULL
    );
    """

    def __init__(self, database_path: str) -> None:
        """Open the audit database and ensure its table exists."""
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

    def record(
        self, *, namespace: str, secret_key: str, action: str, actor: str
    ) -> None:
        """Persist one event row and commit immediately."""
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO keyvault_audit_log "
                "(secret_namespace, secret_key, action, actor, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (namespace, secret_key, action, actor, time.time()),
            )

    def events_for(self, namespace: str, secret_key: str) -> list[dict]:
        """Load events for one secret in write order."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT secret_namespace, secret_key, action, actor, created_at "
                "FROM keyvault_audit_log "
                "WHERE secret_namespace = ? AND secret_key = ? "
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

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()


class KeyvaultService:
    """Encrypt/decrypt at the service boundary; audit every write and delete.

    The store never sees plaintext (encryption happens here, before
    ``store.put``) and the audit sink never sees ciphertext or plaintext
    (only namespace/key/action/actor) -- each collaborator holds the minimum
    it needs, matching this repo's least-privilege convention for the
    Keycloak Admin client and the merge audit trail.
    """

    def __init__(
        self, store: KeyvaultStore, audit: KeyvaultAuditSink, fernet_key: bytes
    ) -> None:
        """Wire a storage backend, an audit sink, and the encryption key."""
        self._store = store
        self._audit = audit
        self._fernet = Fernet(fernet_key)

    def put_secret(
        self, namespace: str, secret_key: str, value: str, *, actor: str
    ) -> SecretMetadata:
        """Encrypt and store one secret; record a ``secret_set`` audit event."""
        encrypted = self._fernet.encrypt(value.encode("utf-8"))
        self._store.put(namespace, secret_key, encrypted)
        self._audit.record(
            namespace=namespace, secret_key=secret_key, action="secret_set", actor=actor
        )
        return self._require_metadata(namespace, secret_key)

    def get_secret(self, namespace: str, secret_key: str, *, actor: str) -> str:
        """Decrypt and return one secret; record a ``secret_read`` audit event.

        Raises :class:`SecretNotFoundError` when no such secret is stored.
        """
        encrypted = self._store.get(namespace, secret_key)
        if encrypted is None:
            raise SecretNotFoundError(f"{namespace}/{secret_key}")
        self._audit.record(
            namespace=namespace, secret_key=secret_key, action="secret_read", actor=actor
        )
        return self._fernet.decrypt(encrypted).decode("utf-8")

    def list_secrets(self, namespace: str) -> list[SecretMetadata]:
        """Return metadata (never values) for every secret in ``namespace``."""
        return self._store.list_keys(namespace)

    def delete_secret(self, namespace: str, secret_key: str, *, actor: str) -> None:
        """Delete one secret; record a ``secret_deleted`` audit event.

        Raises :class:`SecretNotFoundError` when no such secret was stored.
        """
        deleted = self._store.delete(namespace, secret_key)
        if not deleted:
            raise SecretNotFoundError(f"{namespace}/{secret_key}")
        self._audit.record(
            namespace=namespace,
            secret_key=secret_key,
            action="secret_deleted",
            actor=actor,
        )

    def audit_history(self, namespace: str, secret_key: str) -> list[dict]:
        """Return the recorded access history for one secret."""
        return self._audit.events_for(namespace, secret_key)

    def _require_metadata(self, namespace: str, secret_key: str) -> SecretMetadata:
        """Return the just-written secret's metadata row."""
        for metadata in self._store.list_keys(namespace):
            if metadata.secret_key == secret_key:
                return metadata
        raise SecretNotFoundError(f"{namespace}/{secret_key}")  # pragma: no cover

    def close(self) -> None:
        """Release the wrapped store and audit sink."""
        self._store.close()
        self._audit.close()
