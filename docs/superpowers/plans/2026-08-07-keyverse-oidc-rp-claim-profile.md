# OIDC Relying-Party Claim Mapper Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` and
> preserve the RED→GREEN→REFACTOR evidence for every behavior change.

**Goal:** Add one closed, secret-free Keycloak audience and session-claim mapper
profile to OIDC relying-party preflight and desired-state reconciliation.

**Architecture:** Extend the manually parsed alias-shaped
`RelyingPartyRegistration` with optional nested mapper models. Keep all policy in
the pure preflight module, and add one normalization seam in the reconciliation
module so Keycloak-generated mapper IDs and ordering do not create false drift.
The Keycloak transport remains unchanged because protocol mappers travel inside
the existing `ClientRepresentation` create/update body.

**Tech stack:** Python 3.11+, FastAPI, Pydantic v2, httpx, pytest, coverage,
Ruff, Keycloak Admin REST, JSON deployment templates.

## Global constraints

- No LLM is used for deterministic validation or reconciliation.
- No `COPILOT_GITHUB_TOKEN` or review-agent credential changes.
- Preflight performs no storage, DNS, socket, HTTP, Keycloak, secret, or file
  side effect.
- Desired state remains secret-free and uses existing multi-word `snake_case`
  namespaces.
- Production docstrings, statement coverage, and branch coverage are 100%.
- Existing standalone, CWL, and Naruon module contracts remain compatible.
- Every behavior change updates `CHANGELOG.md` and APA 7th doctoring.

---

### Task 1: Establish the missing-feature RED receipt

**Files:**
- Create: `services/account_unification/tests/test_relying_party_claim_mappers.py`

**Interfaces:**
- Consumes: `create_app(wire=False)`, operator authentication, the existing
  `/clients/relying-parties:validate` route.
- Produces: `_naruon_registration_with_mappers() -> dict` reused by later tests.

- [ ] **Step 1: Add a production-shaped Naruon request fixture**

The fixture starts from the existing valid public RP payload and adds exactly
four mappers: audience, role, org, and workspace.

- [ ] **Step 2: Add the first behavior test**

```python
def test_naruon_claim_mapper_profile_is_accepted(client, auth_header):
    response = client.post(
        "/clients/relying-parties:validate",
        headers=auth_header,
        json=_naruon_registration_with_mappers(),
    )
    assert response.status_code == 200
    assert response.json()["ready_to_apply"] is True
```

- [ ] **Step 3: Run the focused test and retain the RED evidence**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py::test_naruon_claim_mapper_profile_is_accepted
```

Expected failure: HTTP 422 because `protocolMappers` is an unsupported field.

- [ ] **Step 4: Commit only the failing test**

```bash
git add tests/test_relying_party_claim_mappers.py
git commit -m "test(clients): specify closed RP claim mapper profile"
```

### Task 2: Add non-reflective nested mapper parsing

**Files:**
- Modify: `services/account_unification/app/relying_party.py`
- Modify: `services/account_unification/tests/test_relying_party_claim_mappers.py`

**Interfaces:**
- Produces:
  - `RelyingPartyProtocolMapper`
  - optional `protocol_mappers: list[RelyingPartyProtocolMapper]`
  - `_parse_protocol_mappers(value: Any) -> list[RelyingPartyProtocolMapper]`

- [ ] **Step 1: Add failing shape tests**

Cover non-array `protocolMappers`, non-object entries, non-string keys, missing
fields, extra fields, non-boolean `consentRequired`, non-object `config`, and
non-string config values. Each assertion requires bounded field-only HTTP 422
output that does not contain hostile submitted values.

- [ ] **Step 2: Run the focused shape tests and verify the expected failures**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py -k shape
```

- [ ] **Step 3: Add the closed nested model and manual parser**

Use exact mapper fields `name`, `protocol`, `protocolMapper`,
`consentRequired`, and `config`. Add `protocolMappers` to allowed fields but not
to required fields; absent input canonicalizes to `[]`.

- [ ] **Step 4: Run the shape tests and original preflight suite**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py -k shape
uv run pytest -q tests/test_relying_party_preflight.py
```

- [ ] **Step 5: Commit**

```bash
git add app/relying_party.py tests/test_relying_party_claim_mappers.py
git commit -m "feat(clients): parse closed RP protocol mapper objects"
```

### Task 3: Enforce the audience mapper policy

**Files:**
- Modify: `services/account_unification/app/relying_party.py`
- Modify: `services/account_unification/tests/test_relying_party_claim_mappers.py`

**Interfaces:**
- Produces `_validate_protocol_mappers(registration) -> None`.

- [ ] **Step 1: Add failing audience-policy tests**

Test valid audience-only, duplicate audience, missing audience when any mapper is
present, wrong mapper name, wrong protocol, wrong mapper type, consent enabled,
extra/missing config, audience unequal to `clientId`, and wrong token
claim-destination flags.

- [ ] **Step 2: Verify failures**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py -k audience
```

- [ ] **Step 3: Implement the exact audience policy**

Require `keyverse-audience`, `openid-connect`, `oidc-audience-mapper`,
`consentRequired=false`, and exactly:

```text
included.client.audience = registration.client_id
access.token.claim = true
id.token.claim = false
introspection.token.claim = true
```

- [ ] **Step 4: Verify focused and full preflight tests**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py -k audience
uv run pytest -q tests/test_relying_party_preflight.py tests/test_relying_party_claim_mappers.py
```

- [ ] **Step 5: Commit**

```bash
git add app/relying_party.py tests/test_relying_party_claim_mappers.py
git commit -m "feat(clients): pin the RP access-token audience mapper"
```

### Task 4: Enforce bounded hardcoded session claims and canonical order

**Files:**
- Modify: `services/account_unification/app/relying_party.py`
- Modify: `services/account_unification/tests/test_relying_party_claim_mappers.py`

**Interfaces:**
- Produces a canonical mapper rank for audience, role, org, and workspace.

- [ ] **Step 1: Add failing claim-policy tests**

Cover valid role/org/workspace subsets, all three Naruon claims, duplicate claim,
unsupported claim, noncanonical mapper name, wrong mapper class, wrong JSON type,
wrong token destinations, empty/oversized/control/unresolved/trim-ambiguous claim
values, and noncanonical list order.

- [ ] **Step 2: Verify failures**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py -k claim
```

- [ ] **Step 3: Implement minimal closed claim policy**

Require exact `oidc-hardcoded-claim-mapper` objects for only `role`, `org`, and
`workspace`. Values are 1–128 Unicode scalar values, trimmed, non-control,
non-template text. Require canonical list order.

- [ ] **Step 4: Verify all mapper and existing preflight tests**

```bash
uv run pytest -q tests/test_relying_party_claim_mappers.py tests/test_relying_party_preflight.py
```

- [ ] **Step 5: Commit**

```bash
git add app/relying_party.py tests/test_relying_party_claim_mappers.py
git commit -m "feat(clients): validate bounded RP session claims"
```

### Task 5: Normalize live Keycloak mappers for drift comparison

**Files:**
- Modify: `services/account_unification/app/relying_party_state.py`
- Modify: `services/account_unification/tests/test_relying_party_desired_state.py`
- Modify: `services/account_unification/tests/mock_product_keycloak.py` only if
  the mock must simulate generated mapper IDs or ordering.

**Interfaces:**
- Produces:
  - `_normalized_observed_mappers(value: object) -> list[dict] | None`
  - mapper-aware `_observable_client_matches(...)`.

- [ ] **Step 1: Add failing reconciliation tests**

After a successful apply, inject generated mapper `id` fields and reverse the
live mapper order. Status must remain `in_sync`. Add separate tests proving an
unknown mapper, duplicate mapper, malformed mapper, or changed claim value is
`drifted` and repaired by reconciliation.

- [ ] **Step 2: Verify RED**

```bash
uv run pytest -q tests/test_relying_party_desired_state.py -k mapper
```

- [ ] **Step 3: Implement mapper normalization**

Ignore only live `id`; select product-owned fields, validate shape, rank known
mapper identity, and compare the canonical list. Any unknown or duplicate live
mapper returns a mismatch rather than raising raw vendor data.

- [ ] **Step 4: Verify lifecycle tests**

```bash
uv run pytest -q tests/test_relying_party_desired_state.py tests/test_relying_party_state_integrity.py
```

- [ ] **Step 5: Commit**

```bash
git add app/relying_party_state.py tests/test_relying_party_desired_state.py tests/mock_product_keycloak.py
git commit -m "fix(clients): normalize observed RP mapper state"
```

### Task 6: Add the Naruon runtime template and operator evidence

**Files:**
- Create: `deploy/templates/oidc-rp-naruon.json`
- Create or modify: `services/account_unification/tests/test_relying_party_template.py`
- Modify: `deploy/templates/README.md`
- Modify: `docs/rp-onboarding.md`
- Modify: `docs/operations/oidc-rp-reconciliation.md`

**Interfaces:**
- Produces one secret-free rendered artifact accepted by preflight and desired
  state after placeholder substitution.

- [ ] **Step 1: Add failing template tests**

Require valid JSON, no secret-bearing field, canonical four-mapper order,
audience pinned to `naruon-web`, and a rendered form accepted by the production
parser/validator.

- [ ] **Step 2: Add the template**

Use exact HTTPS placeholders for redirect/origin/logout and bounded placeholders
for `role`, `org`, and `workspace` values. Do not include a client secret.

- [ ] **Step 3: Update operator documentation**

Document render → preflight → desired-state PUT → exact status → controlled
login acceptance. State that claim values are visible product routing data and
must not carry credentials or personal secrets.

- [ ] **Step 4: Verify**

```bash
uv run pytest -q tests/test_relying_party_template.py tests/test_relying_party_claim_mappers.py
python - <<'PY'
import json
from pathlib import Path
for path in Path('deploy/templates').glob('*.json'):
    json.loads(path.read_text(encoding='utf-8'))
PY
```

- [ ] **Step 5: Commit**

```bash
git add deploy/templates docs/rp-onboarding.md docs/operations/oidc-rp-reconciliation.md tests/test_relying_party_template.py
git commit -m "docs(clients): add the Naruon runtime RP claim profile"
```

### Task 7: Complete architecture, changelog, and APA 7th doctoring

**Files:**
- Create: `docs/doctoring/oidc-rp-claim-mapper-profile.md`
- Modify: `ARCHITECTURE.md`
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`

**Interfaces:** None; these files define the operational and review contract.

- [ ] **Step 1: Record standards and vendor interpretation**

Separate OIDC Core ID-token audience, RFC 9068 access-token guidance, RFC 8725
JWT guidance, Keycloak mapper representation, stricter product policy, measured
evidence, assumptions, and limitations. Use APA 7th references.

- [ ] **Step 2: Update architecture and agent rules**

Add the mapper-profile boundary and preserve the follow-up requirement to remove
runtime application clients from the portable realm under #71.

- [ ] **Step 3: Update `[Unreleased]`**

Record the optional mapper profile, normalization, template, and remaining realm
migration boundary. Do not create a release section.

- [ ] **Step 4: Commit**

```bash
git add ARCHITECTURE.md AGENTS.md CLAUDE.md CHANGELOG.md docs/doctoring
git commit -m "docs(clients): trace the closed RP claim mapper profile"
```

### Task 8: Close complete coverage and package/deployment verification

**Files:**
- Modify production/tests only when the measured report identifies a real
  uncovered branch or defect.

- [ ] **Step 1: Run the full exact-tree acceptance suite**

```bash
cd services/account_unification
uv sync --locked --extra dev
uv run ruff check app tests tools
uv run interrogate .
uv run python -m compileall -q app tests tools
uv run coverage erase
uv run coverage run --branch --source=app -m pytest -q
uv run coverage report --show-missing --fail-under=100
uv build --out-dir dist
cd ../..
python scripts/validate_realm.py deploy/keycloak/cwl-realm.json
docker compose -f docker-compose.yml config
python - <<'PY'
import json
from pathlib import Path
for path in Path('deploy/templates').glob('*.json'):
    json.loads(path.read_text(encoding='utf-8'))
PY
git diff --check main...HEAD
```

- [ ] **Step 2: Fix only evidence-backed gaps with TDD**

For each failure, preserve the failing test or command output, make one focused
change, and rerun the focused command before repeating the full suite.

- [ ] **Step 3: Update the PR body with exact-head evidence**

Include the RED commit/run, final head, complete verification commands, measured
statement/branch totals, and residual risks.

- [ ] **Step 4: Request current-head review and arm protected auto-merge**

No self-approval or administrator bypass. Merge only after exact-current-head
CI, CodeQL, Semgrep, Security Scan, review, and unresolved-thread gates pass.
