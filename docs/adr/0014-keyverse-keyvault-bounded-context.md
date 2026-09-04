# ADR-0014: Keyvault as a separate bounded context from IdP identity/config

**Status:** Accepted (first slice implemented)
**Date:** 2026-09-02

## Context

The owner asked that Keyverse stop being only a Keycloak-fronting Identity
Provider and also become usable as a Keyvault: a namespaced,
encrypted-at-rest secrets store analogous to Azure Key Vault or HashiCorp
Vault's KV secrets engine, with write/read/delete APIs and audit logging.

Keyverse already runs one seam that looks superficially similar:
`services/account_unification/app/kv_store.py`'s `idp_config_entries` table
(`KvStore` protocol; `InMemoryKvStore`/`SqliteKvStore`), which
`config.py` reads at startup for this service's *own* operational
configuration (Keycloak URLs, operator tokens, timeouts). Values there are
stored as plain SQLite text, never encrypted — appropriate for
`config.py`'s stated invariant ("nothing here reads process environment";
everything is this service's own internal, operator-set configuration), but
not a safe foundation for a general-purpose secrets product surface other
CWL services would write arbitrary customer/provider secrets into.

Identity/authentication and secrets storage are historically separate
concerns even inside mature platforms — Keycloak (an OpenID Connect
Provider) is architecturally distinct from HashiCorp Vault (a secrets
manager), and the two are typically deployed and operated independently.
Domain-Driven Design treats this as a Bounded Context question: two models
that use similar words ("store a value under a key") but serve different
Aggregates, different invariants, and different consumers should not be
collapsed into one undifferentiated model merely because they could share a
table (Evans, 2003, ch. 14; Vernon, 2013, ch. 2–3).

A genuine motivating first consumer already exists in this ecosystem:
`contextual-orchestrator`'s `credentials.py` documents the exact same "KV,
not env" principle for its own provider API keys (`CredentialBackend`
Protocol; `InMemoryCredentialBackend` default; pgcrypto-encrypted
`PostgresCredentialBackend`). That module's docstring explicitly names
Keyverse-style KV-backed secret resolution as the org reference pattern.
A Keyverse Keyvault is not a feature built for its own sake — it is the
natural next step for that pattern to be centrally operated rather than
reimplemented per repository, and `contextual-orchestrator` could later
swap in a `KeyverseCredentialBackend` implementing its existing
`CredentialBackend` Protocol with no call-site change, exactly as its
pluggable-backend design already anticipates.

NIST SP 800-57 Part 1 Rev. 5 sets general key-management expectations
(key separation, controlled key lifetime, protecting keys distinct from the
data they protect) that a from-scratch secrets store should satisfy rather
than inventing ad hoc practice (Barker, 2020). OWASP's Application Security
Verification Standard requires application-layer secrets to be encrypted
at rest with keys that are not co-located with the ciphertext under the
same trust boundary (OWASP Foundation, 2021, V6 Cryptography at rest).

## Decision

Keyvault is a **separate bounded context** from Keyverse's IdP-facing
modules (Keycloak realm/client management, `relying_party_admin.py`, the
in-flight `authorization_plane.py`/`org_authorization.py` line — see
ADR-0015). It does **not** extend `idp_config_entries` or `kv_store.py`.

What is shared (deliberately minimal Shared Kernel, per this org's
DDD convention of keeping Shared Kernels small):

- The **pattern** already proven twice in this service (`kv_store.py`,
  `audit.py`): a small `Protocol` plus in-memory and SQLite backends, WAL
  journal mode, a 10-second `busy_timeout`, and an append-only trail.
  Keyvault keeps each mutation and its audit event in one transaction.
- The `operator_auth_dependency` / `admin_path_security_dependency`
  router-level authentication and opaque-path-segment validation already
  required for every privileged router in `main.py`.
- The "KV, not env" bootstrap discipline: `keyvault_passphrase` is read
  from the *existing* `idp_config_entries` config store (never a raw
  environment variable at request time), exactly like every other
  `ServiceConfig` field.

What is genuinely new (Capability #1 of the owner's three-capability
request; #2 service ABAC/RBAC and #3 login credential store are ADR-0015
and ADR-0016):

- `app/keyvault.py` — `SqliteKeyvaultStore`/`InMemoryKeyvaultStore` over a
  dedicated `keyvault_secrets` table (`secret_namespace`, `secret_key`,
  `encrypted_value`, `updated_at`) and a dedicated `keyvault_audit_log` table
  (namespace/key/action/actor/`created_at` — deliberately not
  `AuditEvent`'s survivor/duplicate-user shape, since a Keyvault write has
  no survivor and forcing one schema onto the other would blur two
  different Aggregates); `KeyvaultService`, which is the only collaborator
  that ever holds plaintext (encryption/decryption happens at this service
  boundary with `cryptography.fernet.Fernet`, keyed by PBKDF2-HMAC-SHA256 of
  the configured passphrase — the store never sees plaintext and audit events
  never contain ciphertext or plaintext).
- `app/keyvault_admin.py` — `PUT`/`DELETE /keyvault/{namespace}/{key}`,
  `GET /keyvault/{namespace}` (metadata only: namespace, key, `updated_at`
  — **never** a value, so an admin UI can render an inventory without ever
  holding plaintext it does not need), and
  `GET /keyvault/{namespace}/{key}/audit`.
- Opt-in by construction: `config.py`'s `keyvault_passphrase` defaults to
  `None`. `main.py`'s `_build_keyvault_service` returns `None` when unset,
  and `keyvault_admin.get_keyvault` then fails closed with **503** ("not
  configured"), never a misleading 404 that would suggest the feature
  exists but is empty. A namespace here identifies the *consumer* of a
  secret (one CWL service or deployment-scoped concern), never an end user
  or a Keycloak realm object.

A dedicated admin *page* for Keyvault (distinct from any general "3
admin webs" work — see the sibling multi-repo research this ADR's PR
accompanies) is designed but not built in this slice; the API above is the
complete, tested surface it will consume.

The branch briefly used a bare SHA-256 derivation before this feature reached
protected main. No released database used that pre-release format, so there is
no ciphertext to migrate and no legacy weak-key fallback is admitted. If live
deployment evidence later contradicts that premise, migration must be a
separate recovery change that identifies legacy rows explicitly and rewrites
them once; new rows must never try the legacy derivation.

## Consequences

- `idp_config_entries` stays exactly what its own docstring says it is:
  this service's internal configuration, never a place other services'
  secrets land.
- A wrong `keyvault_passphrase` cannot silently produce garbage: Fernet
  authenticates ciphertext (`cryptography.fernet.InvalidToken` on
  mismatch), so a passphrase rotation without re-encrypting existing rows
  fails loudly rather than returning corrupted plaintext.
- `contextual-orchestrator`'s `CredentialBackend`/`kv_config.ConfigStore`
  Protocols are the natural adapter target for a future
  `KeyverseCredentialBackend` — noted here as the motivating consumer, not
  implemented in this PR (see the "what's left" note in the accompanying
  PR description).
- Plaintext retrieval is intentionally absent from the administrator surface.
  A consumer adapter cannot ship until Keyverse can verify a signed workload
  identity and bind its read scope to exactly one namespace.
- 100% branch coverage and 100% docstring coverage on `app/keyvault.py`
  and `app/keyvault_admin.py` (verified: `uv run coverage run --branch
  --source=app -m pytest -q && uv run coverage report --fail-under=100`;
  `uv run interrogate -v app`), and `uv run ruff check app tests` passes
  clean, matching this service's existing gates.

## References

Barker, E. (2020). *Recommendation for key management: Part 1 – General*
(NIST SP 800-57 Part 1, Rev. 5). National Institute of Standards and
Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Evans, E. (2003). *Domain-driven design: Tackling complexity in the heart
of software*. Addison-Wesley.

OWASP Foundation. (2021). *OWASP application security verification
standard 4.0.3*. https://owasp.org/www-project-application-security-verification-standard/

Vernon, V. (2013). *Implementing domain-driven design*. Addison-Wesley.
