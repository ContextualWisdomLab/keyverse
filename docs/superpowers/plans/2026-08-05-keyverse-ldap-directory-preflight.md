# Keyverse LDAP/AD Directory Preflight Implementation Plan

> Execute with Superpowers test-driven development, systematic debugging, and
> verification-before-completion. Do not merge or release before exact-head
> protected evidence succeeds.

**Goal:** Reject unsafe LDAP/Active Directory user-storage component payloads
before they reach Keycloak Admin REST, while returning a secret-redacted,
side-effect-free validation result.

**Architecture:** Add an isolated `directory_federation` module whose request
schema mirrors the bounded Keycloak component payload. Include one operator-
authenticated FastAPI route. Keep this slice free of KV, Keycloak, DNS, socket,
and mutation dependencies so the same validator can be embedded by CWL and
Naruon deployment controllers.

## Task 1 — Establish RED behavior contracts

**Files:**
- Create: `services/account_unification/tests/test_directory_federation_preflight.py`

- [ ] Add a valid AD payload fixture matching the deployment template.
- [ ] Prove the new endpoint is absent before implementation.
- [ ] Add transport, DN, attribute, mutation-policy, redaction, resource-bound,
  schema, and authentication cases.
- [ ] Run the focused test and record the expected missing-module/route failure.

## Task 2 — Implement the minimal preflight module

**Files:**
- Create: `services/account_unification/app/directory_federation.py`
- Modify: `services/account_unification/app/main.py`

- [ ] Add aliased Keycloak component request/response models.
- [ ] Add exact single-value configuration extraction.
- [ ] Add ASCII slug, LDAP descriptor/OID, object-class list, integer, boolean,
  LDAPS URL list, and RFC 4514 lexical validation.
- [ ] Require READ_ONLY, imported users, no registration sync, no Kerberos, no
  trusted email, bounded timeouts, and current Keycloak truststore policy.
- [ ] Redact bind DN and bind credential from the successful response.
- [ ] Include the router under existing operator authentication and path
  security.
- [ ] Run the focused tests until green.

## Task 3 — Close production branch coverage

**Files:**
- Modify: `services/account_unification/tests/test_directory_federation_preflight.py`
- Optionally create: `services/account_unification/tests/test_full_coverage_directory_federation.py`

- [ ] Run branch coverage with `--source=app`.
- [ ] Add behavior-oriented cases for every uncovered validation branch.
- [ ] Require 100% production statement and branch coverage.
- [ ] Require 100% production docstring coverage.

## Task 4 — Align deployment contracts and documentation

**Files:**
- Modify: `deploy/templates/ldap-source.json`
- Modify: `deploy/templates/README.md`
- Modify: `docs/federation-onboarding.md`
- Create: `docs/doctoring/ldap-directory-preflight.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `ARCHITECTURE.md` if present; otherwise create it with the relevant
  standalone/MSA boundary.
- Modify: `CHANGELOG.md`

- [ ] Remove non-payload `$...` fields from the JSON template.
- [ ] Set LDAPS, READ_ONLY, no registration sync, no Kerberos, no trusted email,
  and `useTruststoreSpi=always` defaults.
- [ ] Document private-file rendering, exact-200 preflight, secret redaction,
  direct Keycloak apply, and the lack of live connectivity testing.
- [ ] Record RFC 4511/4513/4514/4515 and current Keycloak sources in APA 7th
  style without claiming formal conformance.
- [ ] Record the addition under `[Unreleased]`.

## Task 5 — Verify the exact branch head

- [ ] `uv sync --locked --extra dev`
- [ ] `uv run ruff check app tests tools`
- [ ] `uv run interrogate .`
- [ ] `uv run coverage run --branch --source=app -m pytest -q`
- [ ] `uv run coverage report --show-missing --fail-under=100`
- [ ] `python -m compileall -q app tests tools`
- [ ] package build and installed-wheel smoke test
- [ ] `python scripts/validate_realm.py deploy/keycloak/realm-cwl.json`
- [ ] `docker compose -f docker-compose.yml config`
- [ ] validate every deployment JSON template
- [ ] `git diff --check`
- [ ] exact-head CI, CodeQL, Semgrep, Security Scan, and review-thread checks

## Task 6 — Protected completion

- [ ] Open one focused draft PR against `main`.
- [ ] Request current-head CodeRabbit/central review without altering the review
  agent's credential system.
- [ ] Address every valid review thread and rerun exact-head Checks.
- [ ] Enable auto-merge or squash merge only after the protected policy is
  satisfied.
- [ ] Re-list open PRs and continue the commercialization loop.
- [ ] Do not bump version or publish a release unless the complete product and
  supply-chain release criteria are met.
