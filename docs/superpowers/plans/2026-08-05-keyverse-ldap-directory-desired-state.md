# LDAP and Active Directory Desired-State Implementation Plan

> Execute with Superpowers TDD, systematic debugging, and verification-before-completion.

**Goal:** Add protected KV/DB-backed LDAP desired-state CRUD and Keycloak
component reconciliation without weakening preflight, secret, passwordless, or
review boundaries.

**Architecture:** Extend the existing pure LDAP validator with a stateful service
that uses the shared `KvStore`, a narrow `ProductAdminApi` component adapter,
short storage critical sections, and serialized remote convergence. All HTTP
responses are redacted and distinguish observable state from unobservable
credentials.

## Global constraints

- [ ] No production code before a failing behavior test.
- [ ] Existing `/user-directories:validate` remains side-effect-free.
- [ ] No network call while the desired-state storage lock is held.
- [ ] Bind DN and credential never appear in responses, errors, logs, fixtures,
      comments, or command arguments.
- [ ] No new database schema; use multi-word namespace
      `directory_federation_sources`.
- [ ] Existing review-agent credentials and hourly NVIDIA NIM OpenCode workflow
      remain unchanged.
- [ ] Production docstrings, statement coverage, and branch coverage remain 100%.

## Task 1 — RED service contract

**Files:**
- Create `services/account_unification/tests/test_directory_federation_desired_state.py`

- [ ] Specify realistic AD create, no-op, update, outage, rebuild, duplicate,
      delete-ordering, redaction, and lock-release behavior.
- [ ] Run the focused suite and record the expected import/attribute/route failure
      before production implementation.

## Task 2 — Keycloak component adapter

**Files:**
- Modify `services/account_unification/app/product_keycloak_client.py`
- Modify `services/account_unification/tests/mock_product_keycloak.py`
- Modify `services/account_unification/tests/test_keycloak_client.py`
- Modify `services/account_unification/tests/test_keycloak_client_coverage.py`
  or the current full-coverage adapter test file.

- [ ] Extend `ProductAdminApi` with list/create/update/delete user-storage
      component methods.
- [ ] Add guarded `components` and `components/{id}` route shapes.
- [ ] Validate names and generated component IDs before transport.
- [ ] Preserve exact one-shot 401 reauthentication.
- [ ] Test query parameters, Location ID parsing, 404/empty responses, route
      rejection, and all verbs.

## Task 3 — Stateful directory service

**Files:**
- Modify `services/account_unification/app/directory_federation.py`
- Modify `services/account_unification/app/main.py`

- [ ] Add namespace `directory_federation_sources`.
- [ ] Add redacted status and convergence-state models.
- [ ] Add list/get/put/delete/reconcile service methods.
- [ ] Reuse the existing preflight validator before every write and after every
      stored-state parse.
- [ ] Snapshot storage before remote observation.
- [ ] Implement exact match classification: zero, one, or duplicate.
- [ ] Compare only observable non-secret fields.
- [ ] Create when absent; update only on observable drift; no-op when matched.
- [ ] Preserve desired state and return bounded status on outage/apply failure.
- [ ] Delete remote before local desired state.
- [ ] Map duplicate mutation attempts to HTTP 409 and remote mutation failures to
      bounded HTTP 502.

## Task 4 — HTTP and concurrency regressions

**Files:**
- Extend `services/account_unification/tests/test_directory_federation_desired_state.py`
- Create additional focused coverage tests only when needed.

- [ ] Verify operator authentication and path/body name equality.
- [ ] Verify sorted list, get 404, and delete 204.
- [ ] Verify every response and error is secret-free.
- [ ] Block a Keycloak call and prove a concurrent storage read reaches the next
      network boundary rather than blocking on the state lock.
- [ ] Prove concurrent same-name mutations serialize under the convergence lock.
- [ ] Prove malformed stored state fails closed without raw text disclosure.

## Task 5 — Deployment and operator documentation

**Files:**
- Modify `README.md`
- Modify `ARCHITECTURE.md`
- Modify `CLAUDE.md`
- Modify `AGENTS.md` only if the contract changes
- Modify `docs/ldap-directory-onboarding.md`
- Modify `deploy/templates/README.md`
- Create `docs/doctoring/ldap-directory-desired-state.md`
- Modify `CHANGELOG.md`

- [ ] Replace direct-create guidance with validate → desired-state PUT → reconcile.
- [ ] Document duplicate recovery, outage behavior, secret-observation limitation,
      single active reconciler limitation, rollback, and recovery after rebuild.
- [ ] Add APA 7th references and separate standard, vendor, product policy,
      measurement, assumption, and inference.

## Task 6 — Protected completion

- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run focused tests and observe green after the recorded RED.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run `uv run coverage run --branch --source=app -m pytest -q`.
- [ ] Run `uv run coverage report --show-missing --fail-under=100`.
- [ ] Run compileall and `uv build`.
- [ ] Run realm, Compose, and all deployment-template JSON validation.
- [ ] Run `git diff --check`.
- [ ] Open one draft PR linked to #51.
- [ ] Address all actionable review threads.
- [ ] Require exact-current-head CI, CodeQL, Semgrep, Security Scan, central
      review evidence, zero unresolved threads, and protected merge policy.
- [ ] Merge without admin bypass, re-list PRs, and continue the product loop.
- [ ] Keep changes under `[Unreleased]`; do not version or release until broader
      release evidence is complete.
