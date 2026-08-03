# Keyverse Product Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one protected, release-ready Keyverse identity-service change
that integrates passwordless registration, federation, SCIM serialization,
merge hardening, and durable deployment packaging.

**Architecture:** Preserve the minimal merge/SCIM `AdminApi` contract and add a
separate product adapter for one-time passkey action email and federation. Apply
authentication and path validation at router boundaries, redact unknown
federation values by default, and separate storage locks from network
convergence.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic 2, httpx, SQLite, pytest, Ruff,
Interrogate, Keycloak Admin REST API, Docker Compose, Helm.

## Global Constraints

- Application docstring coverage must remain 100%.
- Production statement and branch coverage must remain 100%.
- Every database object name must contain at least two words and use snake_case.
- Runtime dependencies and GitHub Actions remain locked and pinned.
- The service must work standalone and as an importable MSA module.
- No federation or registration secret may appear in an HTTP response, log, or
  process argument.
- The bound browser flow contains no password authenticator.

---

### Task 1: Separate the product Keycloak contract

**Files:**
- Create: `services/account_unification/app/product_keycloak_client.py`
- Test: `services/account_unification/tests/test_keycloak_client.py`

**Interfaces:**
- Consumes: `AdminApi`, `HttpAdminApi`, `UserAccount`
- Produces: `ProductAdminApi`, `ProductHttpAdminApi`

- [x] Add a protocol test that enumerates every declared public method.
- [x] Implement action-email enrollment, rollback deletion, and federation CRUD.
- [x] Add one-shot HTTP 401 retry coverage for GET and user creation.
- [x] Add unsafe-path tests that prove transport calls are not emitted.
- [x] Validate HTTPS redirect, client ID, action aliases, and link lifespan before
  sending action email.

### Task 2: Make registration password-free and failure-atomic

**Files:**
- Modify: `services/account_unification/app/registration.py`
- Modify: `services/account_unification/app/config.py`
- Modify: `services/account_unification/tests/test_registration.py`
- Modify: `services/account_unification/tests/test_config.py`

**Interfaces:**
- Consumes: `ProductAdminApi`
- Produces: `_initialize_account`, `RegistrationResult`

- [x] Reject legacy password fields at the API boundary.
- [x] Create a Keycloak account without a password.
- [x] Send `VERIFY_EMAIL` and `webauthn-register-passwordless` in one bounded
  action email.
- [x] Delete the new account when Keycloak rejects enrollment.
- [x] Preserve a distinct error when rollback itself fails.
- [x] Map exact Keycloak duplicate-user 409 responses to the product conflict.
- [x] Isolate abuse throttling by direct caller address.
- [x] Remove the credential janitor, background loop, and realm-wide endpoint.

### Task 3: Redact and reconcile runtime federation safely

**Files:**
- Modify: `services/account_unification/app/federation.py`
- Modify: `services/account_unification/tests/test_federation.py`

**Interfaces:**
- Consumes: `KvStore`, `ProductAdminApi`
- Produces: `IdentityProviderView`, `IdentityProviderStatus`

- [x] Prove storage and Keycloak receive complete desired state.
- [x] Redact every unknown provider configuration key by default.
- [x] Bound aliases, provider IDs, config entry counts, keys, and values.
- [x] Restrict aliases to an explicit ASCII slug alphabet.
- [x] Snapshot desired state under the storage lock and release it before network
  calls.
- [x] Retain desired state and return `applied_to_keycloak=false` when
  convergence fails.

### Task 4: Harden protocol boundaries

**Files:**
- Modify: `services/account_unification/app/path_security.py`
- Modify: `services/account_unification/app/healthcheck.py`
- Modify: `services/account_unification/app/main.py`
- Test: `services/account_unification/tests/test_path_security.py`
- Test: `services/account_unification/tests/test_healthcheck.py`

- [x] Validate all decoded route parameters at router entry.
- [x] Return a root-level RFC 7644 body with `application/scim+json`.
- [x] Keep `/healthz` outside privileged dependencies.
- [x] Restrict health probes to HTTP(S) and HTTP(S) redirects.
- [x] Register the default urllib HTTP error handler so non-success responses
  raise instead of returning a null response.

### Task 5: Make standalone persistence thread-safe and durable

**Files:**
- Modify: `services/account_unification/app/kv_store.py`
- Modify: `services/account_unification/app/audit.py`
- Modify: `docker-compose.yml`
- Modify: `helm/cwl-idp/values.yaml`
- Modify: `helm/cwl-idp/templates/account-unification.yaml`
- Test: `services/account_unification/tests/test_storage_concurrency.py`
- Test: `services/account_unification/tests/test_deployment_contracts.py`

- [x] Add concurrent writer/reader tests using eight worker threads.
- [x] Add process-local re-entrant locks and cross-thread connections.
- [x] Configure WAL, normal synchronous mode, and a ten-second busy timeout.
- [x] Close connections under the same lock.
- [x] Mount persistent standalone and Kubernetes account-unification data.
- [x] Allow production Helm values to require an immutable image digest.

### Task 6: Integrate lifecycle and mutation serialization

**Files:**
- Modify: `services/account_unification/app/main.py`
- Modify: `services/account_unification/tests/test_lifecycle.py`
- Modify: `services/account_unification/tests/test_scim.py`
- Modify: `services/account_unification/tests/test_user_locks.py`

- [x] Wire merge and SCIM replacement to the same production lock dependency.
- [x] Add the deterministic SCIM/merge race test using the production in-memory
  manager.
- [x] Use a secure temporary sidecar for in-memory audit tests.
- [x] Remove test-only sidecars at shutdown without deleting persistent data.
- [x] Close API, audit, and config resources.

### Task 7: Enforce Keycloak realm policy

**Files:**
- Modify: `deploy/keycloak/realm-cwl.json`
- Modify: `scripts/validate_realm.py`
- Test: `services/account_unification/tests/test_realm_policy.py`

- [x] Remove all password authenticators reachable from the bound browser flow.
- [x] Require the passwordless WebAuthn authenticator and enrollment action.
- [x] Set the public Naruon access-token lifetime to 300 seconds.
- [x] Reject public-client lifetimes above 900 seconds.
- [x] Keep the reusable RP template independent of the Naruon hostname.

### Task 8: Protected verification and release preparation

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/specs/2026-08-03-keyverse-product-hardening-design.md`
- Modify: `docs/superpowers/plans/2026-08-03-keyverse-product-hardening.md`

- [x] Record product gaps and architectural decisions.
- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run `uv run pytest -q` with 100% production statement/branch coverage.
- [ ] Require realm, Compose, Helm, CodeQL, Semgrep, security, and central
  coverage checks on the exact current head.
- [ ] Resolve review threads only after the corresponding finding is addressed.
- [ ] Merge only after protected policy is satisfied.
- [ ] Bump service and lock versions together and publish the release tag.
