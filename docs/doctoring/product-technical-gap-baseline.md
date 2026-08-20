# Product-technical gap baseline doctoring record

**Date:** 2026-08-21
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

## 2026-08-21 local runtime probe

This is partial protocol-readiness evidence, not login or release acceptance.

- Docker Engine 29.5.2 was available. The existing Compose runtime reported
  `idp_database` healthy, `idp_engine` healthy, and the one-shot
  `idp_profile_bootstrap` completed successfully. The account-unification
  service was not running.
- `docker compose config --quiet` remained structurally valid but warned that
  the deployment-only `IDP_DB_PASSWORD` and
  `IDP_BOOTSTRAP_ADMIN_PASSWORD` values were unset. The ignored
  `deploy/bootstrap/bootstrap.yaml` was absent; only the secret-free example
  pointer exists. No secret or credential value was recorded.
- The live realm discovery endpoint returned HTTP 200 with issuer
  `http://localhost:28080/realms/cwl`, authorization/token/JWKS endpoints, and
  advertised `S256` among the realm-wide code-challenge methods.
- A real authorization request for the committed `naruon-web` client, its
  committed `https://naruon.example/auth/callback` redirect, and a valid
  `S256` challenge reached the Keycloak login page with HTTP 200. The earlier
  intentionally invalid localhost redirect returned HTTP 400, confirming
  redirect enforcement at the live client boundary.
- No account was created, no password or passkey credential was entered, no
  authorization code was exchanged, and no token signature/issuer/audience/
  tenant/resource acceptance was claimed. Browser automation was unavailable
  in this environment, so browser-clicked passwordless E2E remains absent.

**Result:** the live issuer and authorization-start boundary are reachable,
but controlled passwordless login, token validation, downstream authorization,
and account-service runtime acceptance remain `gap-not-claimed`. The missing
bootstrap/config-store path is an actionable standalone-Compose deployment gap
that requires deployment-owned secret/config setup before a safe service start;
placeholder credentials must not be committed to close it.

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
  queries performed on 2026-08-21. Fourteen Keyverse PRs are open: #112, #101,
  and #83 each have 23 successful Checks with no queued run; the other eleven
  currently have queued Checks, including #100 after its default-path coverage
  test fix and #104 after its intentional stacked-base rebase. No current open PR has a terminal failure, error, timeout, or
  cancellation, and no current open PR has a qualifying formal approval.
  Queued Checks remain unverified.
  PR #113's current SCIM lock head
  `50f19ec6338fb8eb959b8c797bdfa938e1071c87` includes the normal prerequisite
  lockfile history and a realistic SCIM PatchOp race plus spawned-process
  SQLite lock regression; its hosted Checks are queued and it requires
  independent review. Its local RED-to-GREEN, root-level SCIM error-wire, and
  cross-process sidecar evidence are not protected-main evidence. PR #112's
  lockfile head `f02acf93367a40dbfb23a73985017dca8d42ff39` has terminal-success
  Checks but still requires independent review.
  The historical PR #105 exact head
  `72de5499d6e97ae7f7bd804ab78b3e1644dd5a4f` had a failed
  `account-unification-tests` Check: `uv 0.12.5` reproduced
  `uv sync --locked` refusing the stale `coverage==7.15.2` and
  `setuptools==83.0.0` lock entries while the current `pyproject.toml` required
  `7.15.4` and `84.0.0`; the current #105 head is queued with no terminal
  failure, and #112 remains the lock-refresh prerequisite.
  PR #103's historical terminal Strix run 32092025335 / job 95576032571
  emitted a MEDIUM IDOR report with contradictory model text. Current head
  `157b76893b32cda66fc586aa67ae72a30ac6b0d6` adds direct-mount operator-auth
  regression evidence, but the operator-admin trust boundary still requires
  independent validation. PR #100's pre-doctoring-refresh head was
  `c483bd53ea74aad5fcea7d3cec2f402e4d8f27c2`; successor head
  `3777f54a824d3b2d3458b94f88e5627a7761a2c0` adds a regression test that invokes
  the validator's committed default realm/profile paths after an exact-head
  Devin coverage finding. This evidence refresh creates another pending
  successor, so its hosted Checks must be re-fetched; its prior review state is
  not approval. PR #104 is ready for review at
  `0353001438efb060b85373c121f4d54dfd48e8c8`, intentionally based on #112's
  lockfile head with no net lockfile change; its stacked Checks remain queued.
  This record travels in these PRs, so the live PR records remain authoritative
  for their changing exact hashes.
  The active ruleset requires two approving reviews, resolved threads, and
  latest-push approval, while its read-only audit exposes an
  `OrganizationAdmin` always-bypass actor. The ordinary documentation push
  emitted GitHub's server-side bypass warning; no explicit bypass option,
  protected merge, or self-approval was used. A complete read-only Keyverse
  Actions registry/tree reconciliation at protected `main` `ce207dfd` found 43 active identities:
  four repository workflow paths present in the exact tree, 37 active
  repository paths absent from it, and two `dynamic/*` GitHub-owned paths. The
  workflow registry used one API page and the recursive protected-tree response
  was not truncated. No workflow state was mutated; the evidence is recorded
  on Keyverse issue #99 and central issue #945 for the owning lifecycle
  operator. No credential, private payload, or PII is recorded here.
