# Keyvault operations

## Current delivery boundary

PR #129 is the canonical encrypted-store foundation, not a released workload
credential service. The administrator API exposes metadata and mutation
outcomes, never plaintext. Consumers must not use an operator token as workload
identity, query the Keyverse database, or import this branch as a dependency.

## Root bootstrap without a plaintext config-store key

The account-unification compatibility service now accepts the non-secret
`keyvault_passphrase_file` locator in its private config namespace. It rejects
any `keyvault_passphrase` entry, including an empty entry, instead of silently
falling back. The process environment and `.env` are not alternative credential
sources. With no locator the vault remains disabled; an invalid locator aborts
startup rather than making an encrypted vault look empty.

The supervisor must supply a regular POSIX file with mode `0400` or `0600`,
owned by root or the service's effective UID, and with one hard link. Every
path component must be absolute and free of symlinks, dot segments, and empty
segments. The reader uses descriptor-relative opens, no-follow and nonblocking
flags, rejects FIFOs/directories, bounds content to 4096 bytes, validates UTF-8,
and detects in-place changes while reading. One final LF or CRLF is removed;
other whitespace remains part of the credential. Errors do not echo the path,
raw content, or an underlying decoder/OS diagnostic. All opened descriptors
are closed on both success and failure.

Use a supervisor-managed, read-only private tmpfs credential mount outside the
repository, image, config DB, application secret DB, logs, and backup of those
DBs. Standard Kubernetes projected Secret symlinks are deliberately NOT accepted
by this compatibility reader: a trusted deployment controller must materialize
a private regular-file snapshot, or use a separately reviewed native adapter.
Do not weaken the reader to follow an arbitrary symlink. A filesystem file is
not an HSM: host/root compromise, crash dumps and Python string retention remain
risks. This change does not claim hardware custody or complete zeroization.

This root-only exception breaks the self-bootstrap cycle: a vault cannot fetch
the key needed to open itself from its own unavailable API. Production Rust
vault work must replace it with managed workload identity and an external
KMS/HSM envelope-key provider. Ordinary product credentials do not qualify for
this exception.

## Controlled migration

Before adopting this unreleased change, stop the affected vault service and
have an authorized operator transfer the existing root credential through a
private administrative channel to the supervisor. Keep its exact value: merely
changing the root key makes existing ciphertext unreadable. Configure only the
new locator, remove the plaintext entry, rehearse decryption and restart against
a private restored copy, then cut over. SQL DELETE alone is not secure erasure:
old SQLite pages, WALs and backups may retain the former value. Retire those
copies under the recovery/retention policy after a tested rewrap/rotation. This
session does not transfer, delete, rotate, or deploy real credentials.

Rollback must retain the protected bootstrap path; it must not recreate `.env`
or put the root credential back into the ordinary config DB. Actual key
rotation, durable rewrap/rollback and KMS integration remain release gates.

## Administration and consumer adoption

Administrators can list metadata, set or rotate a stored value, inspect audit
history and delete it. Never echo submitted values into UI state, logs,
screenshots, notifications, exceptions or exports. Configuration repr excludes
client, operator, registration and vault bootstrap credentials; this is not
permission to serialize configuration with `dataclasses.asdict`.

Each secret mutation and its audit event commits in one transaction. Back up
and restore that database as one unit. Wrong-key decryption is an error, not an
empty namespace. Root-key storage protection does not fix the parent's
installation-wide KDF salt, ciphertext context binding, or missing immutable
secret-version/lease model; those findings remain explicit in the gap register.

Noema, contextual-orchestrator and other consumers require signed workload
identity, namespace/key/version-scoped authorization, cross-tenant denial,
rotation/revocation, bounded lease behavior, outage and rollback tests, plus an
immutable Keyverse release before production adoption. A cache may be used only
within its issued lease and revocation policy; no expired-cache or dotenv
fallback is permitted. Application settings which are not secrets stay in typed
configuration, not in the secret-value store.
