# Federation Preflight Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an authenticated, side-effect-free federation preflight endpoint and fail-closed ADFS/SAML runtime validation before desired state is persisted.

**Architecture:** Extend the existing federation service boundary so the same pure validation functions are shared by preflight and `PUT`. Return only the existing redacted operator view, keep Keycloak and KV calls out of preflight, and update the ADFS template to the Keyverse API contract.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, pytest, Keycloak 26 Admin REST representations, GitHub Actions.

## Global Constraints

- Preserve the existing operator-authenticated federation router and all current routes.
- Perform no remote metadata fetch in preflight.
- Never echo provider secrets or unknown configuration values.
- Reject unresolved `{{...}}` markers before persistence.
- Require SAML signature validation and either metadata-backed or manual certificate trust.
- Keep all production docstrings and statement/branch coverage at 100%.
- Keep database object naming unchanged and two-word-or-longer snake_case.
- Update `CHANGELOG.md`; do not version-bump until broader 0.2.0 release criteria are met.

---

### Task 1: Specify preflight behavior with failing tests

**Files:**
- Modify: `services/account_unification/tests/test_federation.py`

**Interfaces:**
- Consumes: existing `FederationService`, `IdentityProviderRegistration`, `InMemoryKvStore`, `create_app`, Keycloak mock fixtures.
- Produces: executable tests for `POST /federation/identity-providers:validate` and stronger SAML policy.

- [ ] **Step 1: Add a no-side-effect HTTP preflight test**

Add a test that wires a fresh store and mock API, posts a valid SAML registration, and asserts:

```python
assert response.status_code == 200
assert response.json()["ready_to_apply"] is True
assert response.json()["registration"]["provider_config"]["clientSecret"] == "<redacted>"
assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
assert api.calls == []
```

- [ ] **Step 2: Add unresolved-template regression coverage**

Post a registration whose metadata URL is `{{employer_adfs_metadata_url}}`; assert HTTP 400 and the same zero-side-effect checks.

- [ ] **Step 3: Add SAML policy branch tests**

Cover missing/relative `entityId`, missing/relative `singleSignOnServiceUrl`, disabled or malformed `validateSignature`, malformed `useMetadataDescriptorUrl`, missing/relative metadata URL, missing manual certificate, and successful manual-certificate validation.

- [ ] **Step 4: Open a draft PR and verify RED**

Run the repository CI on the tests-only head. Expected: the focused federation tests fail because the preflight route and new validation behavior do not exist. Record the exact failing check and head SHA in the PR timeline.

### Task 2: Implement the shared validation boundary

**Files:**
- Modify: `services/account_unification/app/federation.py`

**Interfaces:**
- Produces: `IdentityProviderValidationResult`, `FederationService.validate_registration`, `_validate_saml_registration`, `_validate_provider_boolean`, `_validate_http_url`, and the preflight route.

- [ ] **Step 1: Add the redacted validation result model**

```python
class IdentityProviderValidationResult(BaseModel):
    """Redacted result proving a registration is ready for persistence."""

    registration: IdentityProviderView
    ready_to_apply: bool = True
```

- [ ] **Step 2: Reject unresolved template markers generically**

During `_validate_registration`, inspect every configuration value and raise HTTP 400 when `{{` or `}}` is present. Error text must not include the supplied value.

- [ ] **Step 3: Add strict boolean parsing for SAML policy fields**

Accept only trimmed, case-insensitive `true` or `false`; reject all other non-empty values with HTTP 400.

- [ ] **Step 4: Add bounded absolute HTTP(S) URL validation**

Use `urllib.parse.urlsplit`. Require scheme `http` or `https`, non-empty authority, no username/password, no fragment, and no ASCII control character. Do not fetch the URL.

- [ ] **Step 5: Add SAML-specific validation**

Require:

```text
entityId: absolute HTTP(S)
singleSignOnServiceUrl: absolute HTTP(S)
validateSignature: true
useMetadataDescriptorUrl=true -> metadataDescriptorUrl: absolute HTTP(S)
useMetadataDescriptorUrl=false -> signingCertificate: non-empty
```

- [ ] **Step 6: Add the service and router method**

`FederationService.validate_registration` runs validation and returns a redacted result. Add authenticated `POST /federation/identity-providers:validate`; do not access the store or Keycloak API.

- [ ] **Step 7: Verify GREEN on focused tests**

Run:

```bash
cd services/account_unification
uv run pytest -q tests/test_federation.py
```

Expected: all federation tests pass.

### Task 3: Correct the operator artifact and documentation

**Files:**
- Modify: `deploy/templates/saml-idp-employer-adfs.json`
- Modify: `deploy/templates/README.md`
- Modify: `README.md`
- Create: `docs/federation-onboarding.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the new `IdentityProviderRegistration` API contract.
- Produces: one render → preflight → apply workflow for employer ADFS.

- [ ] **Step 1: Convert the ADFS template**

Replace the raw Keycloak representation with:

```json
{
  "provider_alias": "employer-adfs",
  "display_name": "Employer ADFS (hssmartdev)",
  "provider_id": "saml",
  "enabled": true,
  "trust_email": true,
  "provider_config": {}
}
```

Retain the existing ADFS endpoints and security settings inside `provider_config`; remove `$comment` and `$mapping_notes` keys rejected by the closed Pydantic schema.

- [ ] **Step 2: Document side-effect-free preflight**

Show an operator-token flow that renders placeholders to a temporary JSON file, calls `:validate`, then calls `PUT` only after 200. State that unresolved placeholders return 400 and no desired state is stored.

- [ ] **Step 3: Correct stale root documentation**

State that the committed realm contains no external IdP or LDAP source and that external providers are deployment data reconciled from the KV/DB desired-state API.

- [ ] **Step 4: Update the changelog**

Add preflight validation, secure SAML requirements, and the corrected ADFS template under `[Unreleased]`.

### Task 4: Full verification and PR readiness

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run the complete locked verification suite**

```bash
cd services/account_unification
uv sync --locked --extra dev
uv run ruff check app tests tools
uv run interrogate .
uv run pytest -q
cd ../..
python scripts/validate_realm.py deploy/keycloak/realm-cwl.json
docker compose -f docker-compose.yml config >/dev/null
```

Expected: all commands exit 0, production docstrings are 100%, and production statement/branch coverage remains 100%.

- [ ] **Step 2: Inspect all review threads and checks**

Resolve only feedback addressed on the exact current head. Do not treat stale or superseded reviews as current approval.

- [ ] **Step 3: Mark ready and enable exact-head auto-merge**

Only after required checks and independent approval pass, mark the draft PR ready and enable auto-merge. Merge immediately only if GitHub reports all repository policy conditions satisfied for the unchanged head SHA.

- [ ] **Step 4: Close the roadmap issue after merge**

Close issue #3 as completed with the merge SHA and a concise statement that employer ADFS now has an operational, validated desired-state onboarding path.
