# Federation Preflight Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` to
> implement this plan task by task.

**Goal:** Add an authenticated, side-effect-free federation preflight endpoint
and fail-closed ADFS/SAML runtime validation before desired state is persisted.

**Architecture:** Extend the existing federation service boundary so preflight
and `PUT` share pure validation. Return only the redacted operator view, keep KV
and Keycloak calls out of preflight, and make the ADFS template use the Keyverse
desired-state contract.

**Tech stack:** Python 3.11+, FastAPI, Pydantic v2, pytest, Keycloak 26 Admin
REST representations, and GitHub Actions.

## Global constraints

- Preserve the existing authenticated federation router and routes.
- Perform no remote metadata fetch in preflight.
- Never echo provider secrets or unknown configuration values.
- Reject unresolved `{{...}}` markers before persistence.
- Accept standards-valid absolute URI entity identifiers, including `urn:`.
- Require explicit SP and IdP identifiers, SAML signature validation, and a
  metadata-backed or manual certificate trust source.
- Keep production docstrings and statement/branch coverage at 100%.
- Keep database object naming unchanged and two-word-or-longer snake_case.
- Update `CHANGELOG.md`; do not version-bump until broader 0.2.0 release criteria
  are met.

---

### Task 1: Specify preflight behavior with failing tests

**Files:**

- Create: `services/account_unification/tests/test_federation_preflight.py`
- Create: `services/account_unification/tests/test_federation_url_hardening.py`
- Modify: `services/account_unification/tests/test_federation.py`

- [x] Add a no-side-effect HTTP preflight test with redacted output.
- [x] Add unresolved-template rejection with zero side effects.
- [x] Cover missing and malformed entity identifiers, SSO endpoints, boolean
  security fields, metadata URLs, and certificate-source modes.
- [x] Preserve standards-valid `urn:` entity identifiers.
- [x] Add raw whitespace, backslash, malformed authority, fragment,
  percent-encoded control, and ordinary percent-encoding regressions.
- [x] Verify RED. Tests-only head
  `99b88fe74376ff42718660bd7dec6df38906cb11` failed because the route returned
  HTTP 404; URL-hardening head
  `3dd95ba154823c1c9d1d344e3005d86b2c169378` failed on the three ambiguous URL
  classes before the production fix.

### Task 2: Implement the shared validation boundary

**Files:**

- Modify: `services/account_unification/app/federation.py`

- [x] Add `IdentityProviderValidationResult` with a redacted registration view.
- [x] Reject unresolved template markers generically.
- [x] Add required strict `true` / `false` parsing.
- [x] Add bounded absolute-URI validation for `entityId` and `idpEntityId`.
- [x] Add bounded HTTPS-only validation for SSO and metadata locations while
  preserving HTTP(S) and `urn:` entity identifiers.
- [x] Reject whitespace, backslashes, raw/encoded controls, userinfo, fragments,
  malformed authorities, and non-HTTP network schemes.
- [x] Require `validateSignature=true` and an explicit certificate-source mode.
- [x] Add `FederationService.validate_registration` and authenticated
  `POST /federation/identity-providers:validate` without store or network calls.
- [x] Share the stronger validation with `PUT` before persistence.
- [x] Verify GREEN. Bootstrap workflow run `30875502879` completed the locked
  dependency install, Ruff, interrogate, complete pytest suite, realm validator,
  Compose validation, JSON validation, and `git diff --check`, then committed
  implementation head `39223fad8329a2d5ed7cc133f219d18825eb9b83`.

### Task 3: Correct operator artifacts and documentation

**Files:**

- Modify: `deploy/templates/saml-idp-employer-adfs.json`
- Modify: `deploy/templates/README.md`
- Create: `docs/federation-onboarding.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`

- [x] Convert the ADFS template to `IdentityProviderRegistration` and remove raw
  Keycloak-only top-level fields.
- [x] Parameterize SP entity ID, IdP entity ID, metadata URL, and SSO URL.
- [x] Document render → preflight → `PUT` with private payload and curl-config
  files so bearer credentials do not enter process arguments.
- [x] Document convergence, outage recovery, certificate rotation, HTTPS-only
  egress and redirect-downgrade restriction, redaction, and deletion semantics.
- [x] Correct root and agent guidance that still claimed external federation was
  embedded in portable realm code or that every template used the same control
  plane.
- [x] Record the feature and documentation corrections under `[Unreleased]`.

### Task 4: Exact-head review, coverage, and merge readiness

- [ ] Verify the final human-authored head after all documentation and template
  commits: locked CI, realm validation, Compose validation, Semgrep, CodeQL,
  security scan, 100% docstrings, and central statement/branch coverage.
- [ ] Inspect every current review submission and unresolved thread; resolve only
  feedback addressed on the unchanged head.
- [ ] Mark the PR ready and enable exact-head auto-merge only after required
  checks and independent approval satisfy repository policy.
- [ ] After merge, close issue #3 with the merge SHA and confirm the open PR queue
  before choosing the next buyer-visible slice.
