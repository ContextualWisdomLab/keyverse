# Keyverse Product Hardening Design

## Objective

Integrate the Keycloak 26, runtime federation, self-registration, SCIM
serialization, and account-merge work into one releasable identity service
without weakening authentication, auditability, or supply-chain controls.

## Product gaps addressed

1. **Overlapping pull requests could not merge safely.** SCIM replacement,
   account merge, registration, and federation modified the same service
   boundaries independently. The integrated design keeps the merge/SCIM core
   interface small and adds a separate product-facing Keycloak adapter.
2. **Registration could leave orphaned accounts.** User creation is followed by
   credential and required-action setup. Failed initialization now deletes the
   newly created account and returns a stable gateway error.
3. **Federation APIs could disclose provider credentials.** Desired state and
   Keycloak still receive the complete configuration, while every operator
   response is projected through a redacted view.
4. **SQLite objects were unsafe under threaded ASGI execution.** Configuration
   and audit connections now use re-entrant process locks, WAL mode, bounded
   busy timeouts, and cross-thread connections. Cross-process user mutations
   remain serialized by the dedicated SQLite lock sidecar.
5. **Decoded route values could reach path builders.** Privileged and SCIM
   routers validate every decoded path parameter before endpoint dependencies.
6. **Expired Keycloak tokens could break non-GET operations.** The product
   adapter retries exactly once after HTTP 401 for every transport method,
   including account creation.
7. **Background resources were not closed deterministically.** Lifespan
   shutdown cancels and awaits the credential janitor, then closes Keycloak,
   audit, and configuration resources.

## Architecture

### Core identity engine

`AdminApi`, `UnificationService`, SCIM translation, matching, audit events, and
`UserOperationLocks` remain the reusable MSA module. They do not depend on
product signup or federation configuration.

### Product extension adapter

`ProductAdminApi` extends the core contract only for product capabilities:
credential lifecycle, user pagination and rollback deletion, and identity
provider CRUD. `ProductHttpAdminApi` subclasses the core HTTP adapter so both
modules share authentication and model translation while keeping concerns
separable.

### Runtime federation

The KV/DB store is the source of truth. `FederationService` validates and stores
the full desired representation, converges Keycloak under one process lock,
and returns `IdentityProviderView`, whose sensitive configuration values are
redacted. The store namespace is `federation_identity_providers`.

### Registration lifecycle

A dedicated bearer token gates `/registration`. Registration validates and
normalizes input, rejects duplicates, creates the account, installs the
bootstrap credential, and requires passwordless WebAuthn enrollment. Any
failure after creation triggers account deletion. The bounded janitor removes
password credentials only after a passwordless WebAuthn credential exists.

### Mutation serialization

Account merge and SCIM full replacement both acquire `UserOperationLocks`.
Standalone deployments use `user_operation_lock_state` in a dedicated SQLite
sidecar and `BEGIN IMMEDIATE`; future clustered deployments can provide a
PostgreSQL advisory-lock implementation behind the same protocol.

### Error and security behavior

- Operator and registration tokens are separate and compared in constant time.
- `/healthz` remains unauthenticated.
- Unsafe path values return HTTP 400; SCIM uses an RFC 7644 error envelope.
- Provider secrets are never returned in API representations.
- Registration failures return stable, non-internal error identifiers.
- No database object uses a single-word or numeric-only name.

## Verification

The acceptance gate is:

- locked dependency installation;
- Ruff linting;
- 100% application docstring coverage;
- complete pytest suite, including race and threaded SQLite tests;
- realm and Docker Compose validation;
- CodeQL, Semgrep, container security, and central coverage checks.

## Release boundary

This integration remains in the Unreleased changelog until all protected checks
and review gates pass on the final merged main branch. The release step then
bumps the service and lock metadata together and publishes the matching tag.
