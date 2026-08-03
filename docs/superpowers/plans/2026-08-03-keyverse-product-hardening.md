# Keyverse Product Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one protected, release-ready Keyverse identity-service change
that integrates registration, federation, SCIM serialization, and merge
hardening.

**Architecture:** Preserve the minimal merge/SCIM `AdminApi` contract and add a
separate product adapter for registration and federation. Apply authentication
and path validation at router boundaries, use redacted federation response
models, and serialize standalone persistence and user mutations.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic 2, httpx, SQLite, pytest, Ruff,
Interrogate, Keycloak Admin REST API.

## Global Constraints

- Application docstring coverage must remain 100%.
- Every database object name must contain at least two words and use snake_case.
- Runtime dependencies and GitHub Actions remain locked and pinned.
- The service must work standalone and as an importable MSA module.
- No federation or registration secret may appear in an HTTP response or log.

---

### Task 1: Separate the product Keycloak contract

**Files:**
- Create: `services/account_unification/app/product_keycloak_client.py`
- Test: `services/account_unification/tests/test_keycloak_client.py`

**Interfaces:**
- Consumes: `AdminApi`, `HttpAdminApi`, `UserAccount`
- Produces: `ProductAdminApi`, `ProductHttpAdminApi`

- [x] Add a protocol test that enumerates every declared public method.
- [x] Verify the test fails before the product adapter exists.
- [x] Implement credential, user-pagination, rollback deletion, and federation
  CRUD methods.
- [x] Add one-shot HTTP 401 retry coverage for GET and user creation.
- [x] Add unsafe-path tests that prove transport calls are not emitted.

### Task 2: Make registration failure-atomic

**Files:**
- Modify: `services/account_unification/app/registration.py`
- Modify: `services/account_unification/tests/test_registration.py`

**Interfaces:**
- Consumes: `ProductAdminApi`
- Produces: `_initialize_account`, `RegistrationResult`, `JanitorResult`

- [x] Add a test in which required-action setup fails after user creation.
- [x] Verify the test observes an orphan before rollback is implemented.
- [x] Delete the new account on initialization failure.
- [x] Preserve a distinct error when rollback itself fails.
- [x] Re-run duplicate, validation, token-isolation, and janitor tests.

### Task 3: Redact runtime federation secrets

**Files:**
- Modify: `services/account_unification/app/federation.py`
- Modify: `services/account_unification/tests/test_federation.py`

**Interfaces:**
- Consumes: `KvStore`, `ProductAdminApi`
- Produces: `IdentityProviderView`, `IdentityProviderStatus`

- [x] Add tests showing that storage and Keycloak receive `clientSecret`.
- [x] Add tests requiring PUT, list, and get responses to contain `<redacted>`.
- [x] Implement deterministic secret-key detection and redacted response views.
- [x] Bound aliases, provider IDs, config entry counts, keys, and values.
- [x] Serialize desired-state convergence under one process lock.

### Task 4: Harden router path handling

**Files:**
- Create: `services/account_unification/app/path_security.py`
- Modify: `services/account_unification/app/main.py`
- Test: `services/account_unification/tests/test_path_security.py`

**Interfaces:**
- Consumes: `validate_path_segment`
- Produces: `admin_path_security_dependency`,
  `scim_path_security_dependency`

- [x] Add HTTP tests using double-encoded separators and traversal values.
- [x] Verify privileged paths reach service dependencies before hardening.
- [x] Validate all decoded route parameters at router entry.
- [x] Return an RFC 7644-shaped error for SCIM paths.
- [x] Keep `/healthz` outside privileged dependencies.

### Task 5: Make standalone persistence thread-safe

**Files:**
- Modify: `services/account_unification/app/kv_store.py`
- Modify: `services/account_unification/app/audit.py`
- Test: `services/account_unification/tests/test_storage_concurrency.py`

**Interfaces:**
- Produces: thread-safe `SqliteKvStore`, `SqliteAuditSink`

- [x] Add concurrent writer/reader tests using eight worker threads.
- [x] Verify default SQLite thread affinity fails the tests.
- [x] Add process-local re-entrant locks and cross-thread connections.
- [x] Configure WAL, normal synchronous mode, and a ten-second busy timeout.
- [x] Close connections under the same lock.

### Task 6: Integrate lifecycle and mutation serialization

**Files:**
- Modify: `services/account_unification/app/main.py`
- Modify: `services/account_unification/tests/conftest.py`
- Modify: `services/account_unification/tests/test_api.py`
- Modify: `services/account_unification/tests/test_scim.py`

**Interfaces:**
- Consumes: `SqliteUserOperationLocks`, `FederationService`,
  `ProductHttpAdminApi`
- Produces: fully wired FastAPI lifespan

- [x] Wire merge and SCIM replacement to the same lock dependency.
- [x] Add the deterministic SCIM/merge race test.
- [x] Cancel and await the janitor during shutdown.
- [x] Close API, audit, and config resources.
- [x] Authenticate all privileged test clients.

### Task 7: Protected verification and release preparation

**Files:**
- Modify: `CHANGELOG.md`
- Create: `docs/superpowers/specs/2026-08-03-keyverse-product-hardening-design.md`
- Create: `docs/superpowers/plans/2026-08-03-keyverse-product-hardening.md`

**Interfaces:**
- Produces: reviewable design, implementation record, and release notes

- [x] Record product gaps and architectural decisions.
- [x] Run syntax validation for every created or replaced Python file.
- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run `uv run pytest -q`.
- [ ] Require realm, Compose, CodeQL, Semgrep, security, and coverage checks.
- [ ] Merge only after the protected current-head checks pass.
- [ ] Bump service and lock versions together and publish the release tag.
