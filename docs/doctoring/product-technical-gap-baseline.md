# Product-technical gap baseline doctoring record

**Date:** 2026-08-20
**Scope:** Keyverse product, trust-boundary, PR queue, and release evidence

## Interpretation

The baseline classifies facts by evidence boundary. Repository source/tests can
prove deterministic validation and reconciliation behavior. They cannot prove a
live issuer, browser login, token signature acceptance, downstream tenant
authorization, or release provenance without an approved runtime lane. This
record therefore treats missing runtime evidence as `gap-not-claimed`, not as a
failed implementation and not as success.

The current mapper policy remains closed. `role`, `org`, and `workspace` are
issuer-side product claims; a relying party must define and verify its own
tenant/resource/purpose semantics before RBAC. Adding a generic tenant claim
would be a new authorization profile and requires a separate ADR, red tests,
consumer evidence, and traceability update.

The follow-up LineageWeave contract makes the existing mapping explicit without
expanding that profile: `org` is one opaque external tenant key, `workspace` is
one child namespace under that organization, multiple memberships have no
comma-separated or array encoding, and ambiguous membership resolution denies
before ABAC/RBAC. A changed membership requires a new token or session renewal.
This closes the contract ambiguity only; real login, token validation, local
tenant binding, cross-tenant denial, and resource authorization remain runtime
evidence gaps.

## Standards interpretation

- OpenID Connect Core requires exact issuer matching, client audience
  validation, signature validation, and expiration processing during ID Token
  validation. These are consumer acceptance requirements, not evidence supplied
  by an issuer-side mapper configuration.
- RFC 8725 requires applications to validate issuer ownership, issuer/subject
  validity, and audience association, and to reject invalid tokens. This
  supports keeping tenant and resource authorization after cryptographic token
  validation.
- RFC 9700 is the current OAuth 2.0 Security BCP used here. It supports exact
  redirect matching and authorization-code + PKCE protection, with `S256` as
  the interoperable code-challenge method for this profile.
- Keycloak's current administration guide documents protocol mappers as the
  mechanism that projects roles and user/session data into tokens. That vendor
  behavior does not establish that a receiving application enforces ABAC/RBAC.

## APA 7th references

OpenID Foundation. (2014). *OpenID Connect Core 1.0*.
https://openid.net/specs/openid-connect-core-1_0-18.html

Keycloak. (2026). *Server administration guide*.
https://www.keycloak.org/docs/latest/server_admin/

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (RFC 9700). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc9700.html

Sheffer, Y., Hardt, D., & Jones, M. (2020). *JSON Web Token best current
practices* (RFC 8725). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc8725.html

## Evidence sources

- `docs/PRD.md`, `docs/TRD.md`, `ARCHITECTURE.md`, `docs/OPERABILITY.md`,
  `docs/THREAT_MODEL.md`, `docs/TEST_STRATEGY.md`, and `docs/TRACEABILITY.md`.
- ADR-0008 and ADR-0009 plus their related specification, plan, operations,
  and doctoring records.
- Exact-head GitHub PR, review, issue, check-run, ruleset, and scheduled-run
  queries performed on 2026-08-20. PR #113's current SCIM lock head
  `c2c03a5dba46b207b02d296c26d8bb1dbf215092` includes a normal merge of
  prerequisite PR #112 and a spawned-process SQLite lock regression; its hosted
  Checks are queued and it requires independent review. Its local RED-to-GREEN,
  root-level SCIM error-wire, and cross-process sidecar evidence are not
  protected-main evidence. PR #112's lockfile head
  `f02acf93367a40dbfb23a73985017dca8d42ff39` has terminal-success Checks but
  still requires independent review. PR #105's exact head
  `72de5499d6e97ae7f7bd804ab78b3e1644dd5a4f` has a failed
  `account-unification-tests` Check: `uv 0.12.5` reproduces
  `uv sync --locked` refusing the stale `coverage==7.15.2` and
  `setuptools==83.0.0` lock entries while the current `pyproject.toml` requires
  `7.15.4` and `84.0.0`; #112 is the existing prerequisite lock refresh.
  PR #103's
  terminal Strix run 32092025335 / job 95576032571 emitted a MEDIUM IDOR report
  with contradictory model text; its operator-admin trust boundary still
  requires independent validation. PR #100's live current head
  is recorded as pending until its Checks and a fresh review complete; this
  record travels in that PR, so the live PR record is authoritative for its
  changing exact hash. A complete read-only Keyverse Actions registry/tree
  reconciliation at protected `main` `ce207dfd` found 43 active identities:
  four repository workflow paths present in the exact tree, 37 active
  repository paths absent from it, and two `dynamic/*` GitHub-owned paths. The
  workflow registry used one API page and the recursive protected-tree response
  was not truncated. No workflow state was mutated; the evidence is recorded
  on Keyverse issue #99 and central issue #945 for the owning lifecycle
  operator. No credential, private payload, or PII is recorded here.
