# Keyvault operations

## Delivery boundary

Keyverse is the canonical CWL secret-lifecycle owner, but this PR is still a
foundation. Its administrator surface manages encrypted values and metadata; it
is not yet the released signed-workload read API required for consumer cutover.
Do not give application workloads the operator token, query the Keyverse SQLite
database from another service, or import an open PR as a runtime dependency.

The root passphrase remains a bootstrap concern. Production migration must use
the separately hardened root-bootstrap path and ultimately external KMS/HSM
custody; ordinary product credentials never qualify for a dotenv or plaintext
file fallback.

## Per-vault KDF recovery

Each durable vault stores one `keyvault_kdf_config` row with KDF version,
iteration count, a random 32-byte salt, and creation time. These values are not
secret, but they are required recovery metadata. Back up and restore them with
`keyvault_secrets` and `keyvault_audit_log` as one coherent database state.
The root credential is restored from its independent trust boundary.

A fresh empty vault creates KDF parameters once. A restart reloads the existing
parameters before deriving the Fernet key. Unsupported/weakened parameters fail
startup. If secret rows exist but no KDF metadata exists, startup raises
`LegacyKeyvaultMigrationRequiredError`; it must not invent a new salt or try the
old fixed salt silently.

## Legacy feature-branch rewrap

The former fixed-salt derivation is available only through the explicit
`SqliteKeyvaultStore.migrate_legacy_kdf` maintenance primitive. It exists to
recover ciphertext created by the unreleased feature branch if private
deployment evidence shows that such data exists.

Use a maintenance window and a tested copy first:

1. Stop writes to the affected Keyverse vault and take a consistent encrypted
   backup of its database plus recovery evidence.
2. Resolve the existing root credential through the protected bootstrap
   boundary. Do not copy it into a command line, issue, PR, shell history, log,
   `.env`, screenshot, or migration fixture.
3. Invoke the migration inside the trusted maintenance process with an audited
   opaque operator identity. The helper authenticates every legacy ciphertext
   before changing durable state.
4. The transaction generates a fresh vault salt, re-encrypts every row, records
   `secret_rewrapped`, and persists the new KDF record together. Any decryption
   failure rolls the transaction back without creating authoritative KDF
   metadata.
5. Reopen the vault normally and prove expected secret reads through the
   authorized service boundary. Keep the old backup until restore rehearsal and
   rollback acceptance complete.
6. Retire historical SQLite pages/WAL/backups under the retention policy after
   the migration has been accepted. SQL row changes alone are not proof of
   secure erasure.

Do not expose the legacy derivation as an HTTP endpoint or automatic fallback.
Once `keyvault_kdf_config` exists, repeated legacy migration is rejected.
Future KDF/envelope-key changes require their own versioned rewrap contract.

## Administration

Administrators can list namespaces and secret metadata, set/replace values,
inspect audit history, and delete values. The API never returns plaintext.
Privileged GET responses use `Cache-Control: no-store` so browser/proxy caches
do not retain namespace, key, refresh-time, or audit-actor metadata.

Do not echo submitted values into UI state, logs, traces, metrics, screenshots,
notifications, exceptions, export files, model prompts, or generated artifacts.
Secret change and its audit event remain one transaction; retry only after
checking metadata and audit evidence.

## Consumer migration gate

Contextual Orchestrator, Naruon, Noema and other CWL products keep their current
credential authority until Keyverse publishes an immutable workload-resolution
release. Each consumer migration must prove, at one exact revision:

- cryptographically verified workload identity;
- tenant/environment plus namespace/key/version/operation authorization;
- denied cross-namespace and cross-tenant access;
- bounded lease, expiry and revocation behavior;
- rotation and rollback without credential loss;
- Keyverse outage behavior with no expired-cache, `.env`, plaintext-config, or
  local second-vault fallback;
- logs/artifacts/model context free of resolved secret values;
- clean startup and required operations with no dotenv dependency.

An administrator session is never a substitute for workload identity. A valid
lease may be used only for the lifetime and revocation semantics declared by the
released contract.
