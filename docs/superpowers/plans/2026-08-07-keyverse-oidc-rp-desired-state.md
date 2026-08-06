# OIDC Relying-Party Desired-State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a secret-free, durable, idempotent Keyverse lifecycle for the
closed OIDC relying-party client representation already accepted by preflight.

**Architecture:** Keep validation pure in `relying_party.py`; add a separate
stateful service using `KvStore` and explicit `ProductAdminApi` client CRUD.
Each client ID has its own process-local reconciliation lock, while KV locks
never cover Keycloak network calls. Every successful mutation is re-observed
before a canonical receipt is recorded.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic 2, httpx, Keycloak Admin REST,
SQLite/InMemory `KvStore`, pytest, Ruff, Coverage, Interrogate.

## Global Constraints

- Accept, persist, return, log, and generate no client secret.
- Reuse the existing bearer-token cache, route guard, and one-shot 401 refresh.
- Preserve standalone, CWL, and Naruon module boundaries.
- Use only multi-word `snake_case` database namespaces and objects.
- Production docstrings, statement coverage, and branch coverage remain 100%.
- Current-head review and protected Checks may not be bypassed.
- No version, tag, package publication, or release is created in this slice.

---

### Task 1: Establish failing lifecycle behavior

**Files:**
- Create: `services/account_unification/tests/test_relying_party_desired_state.py`

**Interfaces:**
- Consumes: `RelyingPartyRegistration` and the existing secure client fixture.
- Produces: required `RelyingPartyService`, states, namespaces, and HTTP routes.

- [ ] Write tests for empty-realm create, repeat no-op, drift repair, outage,
  duplicate detection, realm rebuild, malformed state, remote-first delete,
  canonical receipt, independent-client concurrency, and authenticated HTTP CRUD.
- [ ] Run the focused file and verify collection fails because
  `app.relying_party_state` does not yet exist.
- [ ] Preserve the failing output as the RED receipt in the implementation run.

### Task 2: Add explicit Keycloak client transport

**Files:**
- Modify: `services/account_unification/app/product_keycloak_client.py`
- Modify: `services/account_unification/tests/mock_product_keycloak.py`
- Create: `services/account_unification/tests/test_relying_party_client_transport.py`

**Interfaces:**
- Produces:
  - `list_relying_party_clients(client_id: str) -> list[dict]`
  - `create_relying_party_client(client_payload: dict) -> str | None`
  - `update_relying_party_client(client_uuid: str, client_payload: dict) -> None`
  - `delete_relying_party_client(client_uuid: str) -> None`

- [ ] Write transport tests for exact collection queries, malformed response,
  Location parsing, missing Location, unsafe UUID rejection, exact PUT/DELETE,
  body-ID pinning, and one-shot 401 retry.
- [ ] Add `clients` collection/resource routes to the guarded allowlist.
- [ ] Declare every method on `ProductAdminApi` and implement it explicitly on
  `ProductHttpAdminApi`.
- [ ] Extend the deterministic product mock with defensive client copies.
- [ ] Run transport and protocol-completeness tests.

### Task 3: Implement durable desired state

**Files:**
- Create: `services/account_unification/app/relying_party_state.py`
- Modify: `services/account_unification/app/relying_party.py`
- Modify: `services/account_unification/app/main.py`

**Interfaces:**
- Produces:
  - `RELYING_PARTY_NAMESPACE = "relying_party_sources"`
  - `RELYING_PARTY_RECEIPT_NAMESPACE = "relying_party_apply_receipts"`
  - `RelyingPartyConvergenceState`
  - `RelyingPartyStatus`
  - `RelyingPartyService`
  - `relying_party_state_router`
  - `parse_relying_party_registration(payload)`

- [ ] Add a public non-reflective parser wrapper without changing preflight
  behavior.
- [ ] Store validated desired state before convergence.
- [ ] Reconcile zero/one/multiple exact `clientId` matches.
- [ ] Re-observe successful create/update before recording the receipt.
- [ ] Implement keyed locks, stale-snapshot-safe bulk reconciliation, bounded
  stored-state errors, and remote-first deletion.
- [ ] Wire the service and router into live and test application factories.
- [ ] Run focused lifecycle and HTTP tests.

### Task 4: Close every reliability branch

**Files:**
- Modify: `services/account_unification/tests/test_relying_party_desired_state.py`
- Modify: `services/account_unification/tests/test_relying_party_client_transport.py`

- [ ] Exercise create/update exceptions and every post-mutation verification
  result: unavailable, absent, ambiguous, mismatched UUID, and observable drift.
- [ ] Prove blocked network I/O does not hold the KV state lock.
- [ ] Prove bulk reconciliation re-reads the current value and cannot resurrect
  a concurrently deleted desired record.
- [ ] Prove malformed private storage and hostile HTTP bodies never reflect
  submitted values.
- [ ] Run branch coverage and add only realistic tests for remaining lines.

### Task 5: Document the operator and standards contract

**Files:**
- Create: `docs/operations/oidc-rp-reconciliation.md`
- Create: `docs/doctoring/oidc-rp-client-desired-state.md`
- Modify: `docs/rp-onboarding.md`
- Modify: `ARCHITECTURE.md`
- Modify: `CHANGELOG.md`

- [ ] Document validate → PUT → observe → controlled login E2E.
- [ ] Document outage, duplicate, drift, realm rebuild, delete, and rollback.
- [ ] Distinguish readiness, observable equality, receipt, and successful login.
- [ ] Record RFC 9700, RFC 7636, OIDC registration, and Keycloak sources in APA
  7th style, separating standards, vendor behavior, product policy, evidence,
  assumptions, and limitations.
- [ ] Keep the change under `[Unreleased]`.

### Task 6: Protected completion

- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run `uv run coverage run --branch --source=app -m pytest -q`.
- [ ] Run `uv run coverage report --show-missing --fail-under=100`.
- [ ] Run compileall, wheel/sdist build, realm, Compose, and JSON validation.
- [ ] Remove any one-shot implementation workflow or script before publication.
- [ ] Run exact-head CI, CodeQL, Semgrep, Security Scan, review, and thread gates.
- [ ] Merge only through branch protection, then re-list open PRs and issues.
