# Keyverse Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every valid current-head review blocker without weakening
Keyverse's passwordless, audit, security, or modularity contracts.

**Architecture:** Replace the bound-flow bootstrap password with Keycloak's
action-email passkey enrollment path; keep registration and operator privileges
separate; move network calls outside storage locks; return protocol-native
errors; and fail closed on unknown secrets, aliases, paths, and deployment
configuration.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic 2, httpx, SQLite, Keycloak Admin
REST API, pytest, Ruff, Interrogate, Helm, Docker Compose.

## Global Constraints

- The bound `browserFlow` must contain no password authenticator.
- Application and test function docstring coverage must remain 100%.
- Production statement and branch coverage must remain 100%.
- Every database object name must contain at least two words and use snake_case.
- No secret may appear in HTTP responses, logs, or process arguments.
- Required reviews and GitHub Checks must not be bypassed.

---

### Task 1: Passwordless registration enrollment

**Files:**
- Modify: `deploy/keycloak/realm-cwl.json`
- Modify: `scripts/validate_realm.py`
- Modify: `services/account_unification/app/registration.py`
- Modify: `services/account_unification/app/product_keycloak_client.py`
- Modify: `services/account_unification/app/config.py`
- Modify: `services/account_unification/app/main.py`
- Modify: `services/account_unification/tests/test_registration.py`
- Modify: `services/account_unification/tests/test_keycloak_client.py`
- Modify: `services/account_unification/tests/mock_product_keycloak.py`

**Interfaces:**
- Produces: `ProductAdminApi.send_execute_actions_email(user_id, action_aliases,
  client_id, redirect_uri, lifespan_seconds) -> None`
- Produces: registration configuration for client ID, redirect URI, and finite
  positive action-link lifespan.

- [x] Write regression tests proving the bound browser flow rejects
  `auth-password-form`, public-client access tokens are capped, registration
  creates no password, and passkey action-email failure rolls the account back.
- [x] Remove the password execution and validator exception; set `naruon-web`
  access-token lifespan to 300 seconds and validate a 900-second maximum.
- [x] Replace `initial_password` with action-email enrollment and add the
  Keycloak Admin REST adapter method.
- [x] Remove the credential janitor, its configuration, background task, and
  privileged endpoint.
- [ ] Run focused registration, adapter, config, realm, and lifecycle tests.

### Task 2: Registration abuse and race boundaries

**Files:**
- Modify: `services/account_unification/app/registration.py`
- Modify: `services/account_unification/tests/test_registration.py`

**Interfaces:**
- Produces: `reset_rate_limit_state() -> None`
- Produces: caller-keyed fixed-window registration limiting.

- [x] Write regression tests proving one client cannot exhaust another client's
  quota and Keycloak 409 maps to `email_already_registered`.
- [x] Store rate-limit windows per client address under one lock and expose a
  test reset helper.
- [x] Catch only `httpx.HTTPStatusError` with status 409; re-raise every other
  transport error.
- [ ] Run the focused registration suite.

### Task 3: Federation reconciliation and secret safety

**Files:**
- Modify: `services/account_unification/app/federation.py`
- Modify: `services/account_unification/tests/test_federation.py`

**Interfaces:**
- Preserves: `IdentityProviderStatus`
- Produces: safe-key allowlist redaction in which unknown config keys are
  redacted.

- [x] Write regressions for non-ASCII aliases, unknown-key redaction,
  persisted-but-unapplied status, and storage-lock-free network calls.
- [x] Snapshot stored registrations under the storage lock, then perform
  Keycloak calls after releasing it.
- [x] Return `applied_to_keycloak=False` when desired state was stored but
  convergence failed.
- [x] Validate aliases against explicit ASCII alphabets and redact every config
  key not explicitly classified safe.
- [ ] Run the federation suite.

### Task 4: Protocol and runtime correctness

**Files:**
- Modify: `services/account_unification/app/healthcheck.py`
- Modify: `services/account_unification/app/path_security.py`
- Modify: `services/account_unification/app/main.py`
- Modify: `services/account_unification/tests/test_healthcheck.py`
- Modify: `services/account_unification/tests/test_path_security.py`
- Modify: `services/account_unification/tests/test_user_locks.py`
- Create: `services/account_unification/tests/test_lifecycle.py`

**Interfaces:**
- Produces: `ScimPathValidationError` and
  `scim_path_validation_exception_handler`.

- [x] Write regressions for HTTP error handling, root-level SCIM error envelopes
  with `application/scim+json`, and `:memory:` lock wiring.
- [x] Register `HTTPDefaultErrorHandler`, add the SCIM-specific exception
  handler, and use an explicit temporary lock file for in-memory audit
  configurations.
- [x] Add missing function docstrings and deterministic temporary-resource
  cleanup.
- [ ] Run the focused health, path, and lifecycle suites.

### Task 5: Deployment durability and review hygiene

**Files:**
- Modify: `docker-compose.yml`
- Modify: `helm/cwl-idp/values.yaml`
- Modify: `helm/cwl-idp/templates/account-unification.yaml`
- Modify: `deploy/keycloak/README.md`
- Modify: `docs/passwordless-policy.md`
- Modify: `services/account_unification/tools/seed_config_store.py`
- Modify: `services/account_unification/tests/test_config.py`
- Modify: `services/account_unification/tests/test_federation.py`
- Modify: `services/account_unification/tests/test_kcadm_bootstrap.py`
- Modify: `services/account_unification/tests/test_storage_concurrency.py`
- Create: `services/account_unification/tests/test_deployment_contracts.py`

**Interfaces:**
- Produces: persistent Compose/Helm audit volume and optional Helm digest
  enforcement.

- [x] Add contract tests for persistent audit storage, digest enforcement,
  non-temporary seed defaults, and stable bootstrap markers.
- [x] Add the named volume, `requireDigest` render guard, project-local seed
  path, fixture-safe tests, context-managed SQLite test resources, and truthful
  documentation.
- [ ] Run focused tests and Compose/Helm rendering checks.

### Task 6: Protected completion

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/plans/2026-08-03-keyverse-review-remediation.md`

- [x] Resolve the prior review threads after implementing the corresponding
  findings; all old threads are currently resolved/outdated.
- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run `uv run pytest -q` with 100% production statement and branch coverage.
- [ ] Run realm, Compose, Helm, CodeQL, Semgrep, security, and central coverage
  checks on the exact head.
- [ ] Obtain independent approval on the exact head.
- [ ] Merge only after the repository's protected policy is satisfied.
- [ ] Re-list open PRs and continue until the queue is zero or an external
  approval/runner blocker remains.
