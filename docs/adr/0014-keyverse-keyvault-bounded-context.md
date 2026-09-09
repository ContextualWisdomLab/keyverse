# ADR-0014: Keyverse Key Vault as a separate secret-lifecycle bounded context

**Status:** Proposed; implementation is still an open PR and is not a released workload credential service.
**Date:** 2026-09-02
**Updated:** 2026-09-10

## Context

Keyverse must become the canonical CWL Key Vault rather than merely a Keycloak-fronting identity service. That responsibility is distinct from both identity/authentication and ordinary application configuration: secret custody has different invariants for encryption, key separation, versions, rotation, revocation, authorization, recovery and audit.

`idp_config_entries` remains the account-unification service's configuration store. It must not become a general credential database. The Key Vault therefore owns dedicated persistence and APIs, while consumers retain the domain meaning of their credentials behind Anti-Corruption Layers.

The initial feature branch used PBKDF2-HMAC-SHA256 with one fixed organization-wide salt. Although a PBKDF2 salt need not be secret, reusing the same salt means equal passphrases derive the same vault key and prevents the vault instance from carrying its own recoverable KDF configuration. A durable vault instead needs installation-specific random parameters. Randomizing the salt only at process startup would be worse: the service could not derive the same key after restart. The parameters therefore have to be persisted with the ciphertext database and validated before use.

The feature branch may also have been exercised outside protected `main`. Silently falling back to its former fixed salt during normal startup would turn an obsolete derivation into a permanent compatibility path. Conversely, blindly generating a fresh salt when ciphertext already exists would make that ciphertext unreadable. Migration must therefore be explicit, authenticated, atomic and one-shot.

## Decision

Key Vault is a separate Keyverse bounded context. Identity establishes a principal, the Authorization Plane grants scoped operations, and the Key Vault performs secret-lifecycle operations. Consumers do not query Keyverse tables or receive a shared administrator token.

The current storage foundation consists of:

- `keyvault_secrets`, keyed by namespace and secret key, containing ciphertext and update time;
- `keyvault_audit_log`, an append-only access/mutation trail that never contains plaintext or ciphertext values;
- `keyvault_kdf_config`, a singleton durable KDF record containing `kdf_version`, `iteration_count`, a random per-vault salt and creation time.

For a fresh, empty vault, `SqliteKeyvaultStore.load_or_create_kdf_parameters()` generates a cryptographically random 32-byte salt, persists it transactionally, and returns the exact parameters used by `derive_fernet_key`. On restart, the stored version, iteration count and salt are loaded and validated before key derivation. Unsupported versions, an iteration count below the supported floor, or an undersized salt fail closed.

If ciphertext exists but `keyvault_kdf_config` does not, normal startup raises `LegacyKeyvaultMigrationRequiredError`; it never generates a new salt and never tries the former fixed salt automatically. The former salt is reachable only through `legacy_fernet_key_for_migration` and `migrate_legacy_kdf`. That migration first authenticates and decrypts every legacy row in memory before any durable mutation. Only after all rows authenticate does one transaction generate fresh per-vault parameters, re-encrypt every value, append `secret_rewrapped` audit events, and persist the new KDF record. A wrong passphrase therefore cannot leave a partially migrated vault.

The migration helper is a recovery primitive, not an ordinary read fallback. Operations must invoke it during a controlled maintenance window using the protected root bootstrap and must retain a tested backup until the rewrapped vault has been reopened and verified. Future KDF or envelope-key changes require versioned migration rather than editing the active KDF row in place.

Administrative GET responses that expose namespace names, key names, update times or audit actors set `Cache-Control: no-store`. The administrator API still never returns plaintext. A future workload API requires signed workload identity and namespace/key/version-scoped authorization before any consumer migration.

## Root bootstrap

A vault cannot obtain the credential required to unlock itself from its own unavailable API. The root bootstrap is therefore an explicit exception to ordinary application-secret resolution. It must be supplied from an independently protected supervisor/KMS/HSM boundary, not `.env` or the plaintext configuration database. The follow-up protected-bootstrap PR tightens this boundary further; ordinary CWL product credentials do not inherit this exception.

Production evolution should replace the compatibility passphrase model with external KMS/HSM-backed envelope-key custody and managed workload identity. Persisted KDF parameters are necessary recovery metadata for this foundation, not a claim that SQLite plus Fernet is the final enterprise key-management architecture.

## Consequences

Equal passphrases in two fresh vault databases now derive different encryption keys. A vault can still restart because its non-secret KDF parameters are durable. Existing feature-branch ciphertext cannot be accidentally orphaned by a random new salt, and legacy compatibility is not left enabled in the request path.

The KDF metadata belongs with the encrypted vault backup: losing it loses the ability to reproduce the derived key, while disclosing it does not disclose the passphrase. The root credential belongs in a different trust boundary. Backup/restore acceptance must therefore restore ciphertext, audit data and KDF metadata as one coherent vault state while independently restoring access to the root credential.

This PR remains a foundation. It does not yet provide immutable secret versions, leases, revocation, context-bound multi-tenant envelope encryption, an external KMS/HSM adapter, or a released signed-workload read API. Those remain release gates before CWL-wide `.env` retirement can be called complete.

## References

Barker, E. (2020). *Recommendation for key management: Part 1 – General* (NIST SP 800-57 Part 1, Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Evans, E. (2003). *Domain-driven design: Tackling complexity in the heart of software*. Addison-Wesley.

OWASP Foundation. (2021). *OWASP application security verification standard 4.0.3*. https://owasp.org/www-project-application-security-verification-standard/

Vernon, V. (2013). *Implementing domain-driven design*. Addison-Wesley.
