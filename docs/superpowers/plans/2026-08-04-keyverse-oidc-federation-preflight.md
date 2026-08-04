# OIDC Federation Preflight Implementation Plan

> **For agentic workers:** Use the Superpowers test-driven-development and
> verification-before-completion workflows. Keep every change traceable to
> issue #44 and do not weaken protected merge gates.

**Goal:** Reject unsafe external OIDC federation desired state before storage or
Keycloak convergence while preserving a side-effect-free operator preflight.

**Architecture:** Extend the existing pure federation validation boundary for
`oidc` and `keycloak-oidc`. Require explicit pinned endpoints, signature/JWKS
validation, PKCE S256, confidential-client credentials, and an OIDC scope set.
Keep discovery fetches and redirect traversal outside the service.

**Tech stack:** Python 3.11+, FastAPI, Pydantic v2, pytest, Keycloak 26 Admin
REST representations, GitHub Actions.

## Global constraints

- No DNS lookup, discovery fetch, redirect traversal, KV write, or Keycloak call
  during preflight.
- The existing `PUT` route must run the same validation before mutation.
- All protocol endpoints must use HTTPS.
- `clientSecret` and unknown provider fields must never enter operator responses.
- Production docstring, statement, and branch coverage must remain 100%.
- Existing two-word-or-longer snake_case database object names remain unchanged.
- Update `CHANGELOG.md`; do not version-bump until broader 0.2.0 criteria pass.

---

### Task 1: Specify the unsafe current behavior

**Files:**

- Create: `services/account_unification/tests/test_oidc_federation_preflight.py`
- Create: `docs/superpowers/specs/2026-08-04-keyverse-oidc-federation-preflight-design.md`
- Create: `docs/superpowers/plans/2026-08-04-keyverse-oidc-federation-preflight.md`

- [x] Define the standards-backed OIDC validation contract.
- [x] Add valid OIDC and Keycloak-OIDC preflight cases with redaction and zero
  side effects.
- [x] Add missing-field, insecure URL, issuer-shape, remote-discovery,
  signature/JWKS, PKCE, client-authentication, and scope regressions.
- [x] Add a `PUT` regression proving failure precedes persistence and Keycloak.
- [x] Add a deployment-template contract test.
- [ ] Run the tests against the pre-implementation head and record the expected
  RED failures.

### Task 2: Implement pure OIDC validation

**Files:**

- Modify: `services/account_unification/app/federation.py`
- Modify: `services/account_unification/tests/test_oidc_federation_preflight.py`

- [ ] Add explicit OIDC provider IDs, allowed client-auth methods, PKCE method,
  forbidden discovery keys, and RFC 6749 scope-token constants.
- [ ] Add bounded required-text validation without secret echoing.
- [ ] Return parsed HTTPS URLs from the shared helper and enforce issuer query
  and fragment restrictions.
- [ ] Require explicit authorization, token, and JWKS endpoints; validate
  optional UserInfo and logout endpoints when present.
- [ ] Require signature validation, JWKS URL use, PKCE S256, confidential-client
  credentials, and exactly one `openid` scope.
- [ ] Reject runtime discovery import keys.
- [ ] Expose only explicitly safe OIDC operational fields in redacted views.
- [ ] Run focused tests, Ruff, interrogate, and full production coverage.

### Task 3: Add operator and deployment contracts

**Files:**

- Create: `deploy/templates/oidc-idp-partner.json`
- Modify: `deploy/templates/README.md`
- Modify: `docs/federation-onboarding.md`
- Modify: `CHANGELOG.md`

- [ ] Add a provider-neutral OIDC desired-state template with `trust_email=false`
  by default.
- [ ] Document verified out-of-band metadata rendering, preflight, apply,
  egress restrictions, redirect downgrade protection, PKCE, and secret handling.
- [ ] Distinguish OIDC IdP desired state from the existing OIDC RP-client raw
  Keycloak template.
- [ ] Record the buyer-visible security contract under `[Unreleased]`.
- [ ] Validate JSON, Markdown shell snippets, and deployment contracts.

### Task 4: Protected completion

- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run `uv run coverage run --branch --source=app -m pytest -q`.
- [ ] Run `uv run coverage report --show-missing --fail-under=100`.
- [ ] Run realm, Compose, JSON-template, and package-build checks.
- [ ] Obtain CodeQL, Semgrep, Security Scan, CodeRabbit, and independent review
  evidence on the exact final head.
- [ ] Merge without admin bypass only after every repository gate passes.
- [ ] Close issue #44, re-list open PRs, and continue with the next portion of
  issue #2.
