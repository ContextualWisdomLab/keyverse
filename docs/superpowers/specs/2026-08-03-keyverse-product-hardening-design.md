# Keyverse Product Hardening Design

## Objective

Integrate Keycloak 26 compatibility, passwordless registration, runtime
federation, SCIM serialization, and account merge into one releasable identity
service without weakening authentication, auditability, deployment durability,
or supply-chain controls.

## Product gaps addressed

1. **Overlapping pull requests could not merge safely.** SCIM replacement,
   account merge, registration, and federation modified the same service
   boundaries independently. The integrated design keeps the merge/SCIM core
   interface small and adds a separate product-facing Keycloak adapter.
2. **Registration contradicted the passkey-only claim.** The previous bootstrap
   password was reachable from the bound browser flow. Registration now creates
   no password and uses a bounded Keycloak action-email link for address
   verification and passkey enrollment.
3. **Registration could leave orphaned accounts.** Failure to send the action
   email deletes the new account; cleanup failure has its own stable error.
4. **Federation APIs could disclose provider credentials or stall concurrent
   configuration reads.** Unknown values are redacted by default, storage locks
   are released before network calls, and convergence status is explicit.
5. **SQLite objects were unsafe under threaded ASGI execution.** Configuration
   and audit connections use re-entrant process locks, WAL mode, bounded busy
   timeouts, and cross-thread connections. Cross-process user mutations remain
   serialized by a dedicated SQLite lock sidecar.
6. **Decoded route values could reach path builders.** Privileged and SCIM
   routers validate every decoded path parameter before endpoint dependencies.
7. **Runtime state disappeared on container replacement.** Compose and Helm now
   mount deployment-owned storage for audit and lock databases.
8. **Mutable production images were easy to deploy accidentally.** The chart can
   require an immutable account-unification digest and fail template rendering
   when it is absent.

## Architecture

### Core identity engine

`AdminApi`, `UnificationService`, SCIM translation, matching, audit events, and
`UserOperationLocks` remain the reusable MSA module. They do not depend on
product signup or federation configuration.

### Product extension adapter

`ProductAdminApi` extends the core contract only for product capabilities:
rollback deletion, one-time action-email enrollment, and identity-provider
CRUD. `ProductHttpAdminApi` subclasses the core HTTP adapter so both modules
share service-account authentication and model translation while keeping
product concerns separable.

The adapter allows only known Keycloak Admin REST route shapes. Every dynamic
realm, user, client, credential, group, or provider value is validated as one
opaque segment before interpolation. An expired bearer token is refreshed and
retried exactly once for every transport method.

### Password-free registration lifecycle

A bearer token distinct from operator authority gates `/registration`.
Registration:

1. verifies complete action-email configuration;
2. applies caller-keyed abuse throttling;
3. normalizes and validates identity/profile input;
4. checks for an existing email;
5. creates a password-free Keycloak account;
6. requests `VERIFY_EMAIL` and `webauthn-register-passwordless` through
   `execute-actions-email` with an HTTPS redirect and bounded lifespan;
7. deletes the account if step 6 fails.

The bound `browserFlow` contains no password authenticator. The public
`naruon-web` access token lasts 300 seconds; the SSO session can remain longer
because products obtain new access tokens through normal refresh/reissue.

### Runtime federation

The KV/DB store is the desired-state source of truth. `FederationService`
validates and persists the complete provider representation under the two-word
namespace `federation_identity_providers`. It snapshots state while holding the
storage lock, releases that lock before Keycloak network calls, and serializes
convergence separately.

Operator views expose only explicitly allowlisted non-secret configuration
keys. Unknown keys are `<redacted>`, so future Keycloak credential fields cannot
silently leak. A failed apply retains desired state and returns
`applied_to_keycloak=false`, allowing an operator or automation to retry
`identity-providers:apply` after recovery.

### Mutation serialization

Account merge, SCIM full replacement, and supported `PATCH active=false`
deprovisioning all acquire `UserOperationLocks`.
Standalone deployments use the two-word table `user_operation_lock_state` in a
dedicated SQLite sidecar and `BEGIN IMMEDIATE`. Persistent audit deployments
place that sidecar next to the audit database; in-memory tests receive a secure
temporary file that lifecycle cleanup removes.

### Persistence and packaging

The standalone Compose service mounts `account_unification_data` at
`/var/lib/account-unification`. The Helm chart creates a PVC by default and
mounts the same path. Production values set
`accountUnification.image.requireDigest=true`; chart rendering then fails unless
an immutable digest is supplied.

### Error and security behavior

- Operator and registration tokens are separate and compared in constant time.
- `/healthz` remains unauthenticated.
- The restricted stdlib health opener supports only HTTP(S), rejects redirects
  to other schemes, and raises on non-success responses.
- Unsafe admin values return HTTP 400; unsafe SCIM values return a root-level
  RFC 7644 body with `application/scim+json`.
- Provider secrets and unknown provider values never enter API representations.
- Registration failures return stable, non-internal identifiers.
- No database object uses a single-word or numeric-only name.

## Verification

The acceptance gate is:

- locked dependency installation;
- Ruff linting;
- 100% application docstring coverage;
- 100% production statement and branch coverage;
- complete pytest suite, including race, lifecycle, and threaded SQLite tests;
- realm, Docker Compose, and Helm validation;
- CodeQL, Semgrep, container security, and central coverage checks on the exact
  reviewed head.

## Release boundary

This integration remains in the Unreleased changelog until all protected checks
and independent review gates pass on the exact current head. The release step
then bumps service and lock metadata together, verifies artifacts and
provenance, publishes the matching tag, and rechecks the open-PR queue.
