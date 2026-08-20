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

## 2026-08-21 storage evidence

- The focused exact-tree run `uv run pytest -q
  tests/test_storage_concurrency.py tests/test_lifecycle.py` passed 6 tests.
  This is evidence for the SQLite sidecar's local lock contention and lifecycle
  behavior only.
- No PostgreSQL migration/rollback, concentrated-tenant skew, partition-key,
  backup/restore, or production recovery evidence was observed. G5 therefore
  remains `gap-not-claimed`; the local SQLite result must not be promoted into a
  production database acceptance claim.

## 2026-08-21 physical PostgreSQL probe

- The running Compose `idp_database` container uses the pinned PostgreSQL 17
  image. A read-only catalog probe found 88 non-system tables, 3,981,312
  relation bytes, zero partitioned tables, and `pg_is_in_recovery=false`.
  Observed settings were `max_connections=100`, `shared_buffers=163848kB`,
  `work_mem=4096kB`, `wal_level=replica`, and `archive_mode=off`.
- This is local Keycloak system-of-record smoke evidence only. The
  account-unification service uses its SQLite sidecar for local state, and
  neither runtime path proves tenant-concentration behavior, application-owned
  partitioning, backup/restore, failover, or production sizing. G5 therefore
  remains `gap-not-claimed`.

## 2026-08-21 exact local CI contract verification

- The repository CI-scoped command passed the full test suite with 2,786
  application statements and 770 branches at 100% coverage, with no missing
  statements or branches.
- The committed validator-path command passed with 181 statements and 114
  branches at 100% coverage. Interrogate, Ruff, compileall, and diff checks
  also passed on the same local tree.
- These results are exact local evidence for the current PR head only. Hosted
  GitHub Checks, independent approval, latest-pusher compliance, and protected
  merge evidence remain separate gates.

## 2026-08-21 cross-repository cadence dependency

- Contextual-orchestrator PR #797 is closed without merge and superseded. Its
  minute-07 caller duplicated the canonical central caller now proposed in
  `.github` PR #1178; it must not be reopened or merged while #1178 owns this
  dispatch boundary. Central PR #1183 is also closed without merge.
- Central `.github` PR #1170 is open at exact head
  `4684f6e212ba40d12e5217f0f52ee1e90c796ed8` after the gateway fallback/privacy/
  reasoning fixes and the final docstring repair. Its current hosted rollup has
  16 queued Checks, 2 successes, and no terminal failure.
- Central `.github` PR #1178 is the canonical contextual-orchestrator hourly
  caller, open at exact head
  `97b084ac28b5ccf6de7f68fd2e019d8da6f80143`. Its current rollup has 15 queued,
  1 in-progress, and 8 successful Checks; the one cancelled scheduler run is
  historical and a newer exact-head scheduler run is queued. Neither #1170 nor
  #1178 has qualifying formal approval or protected merge evidence.
- Keyverse's existing `Hourly product development` workflow remains active at
  `41 * * * *`; its latest observed scheduled runs succeeded. No duplicate
  scheduler was added. Activation of the central caller remains conditional on
  independent approval and terminal exact-head evidence for #1170 and #1178.

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
  and #83 each have 22 successful Checks with no queued run; the other eleven
  have queued or in-progress Checks without a terminal failure. #110, #111,
  and #113 each have 18 successful Checks and two queued Checks after their
  lock-refresh/external-security reruns.
  No current open PR has a qualifying formal approval.
  Queued Checks remain unverified.
  PR #113's current SCIM lock head
  `50f19ec6338fb8eb959b8c797bdfa938e1071c87` includes the normal prerequisite
  lockfile history and a realistic SCIM PatchOp race plus spawned-process
  SQLite lock regression; its hosted Checks now have 18 successful runs and
  two queued reruns with no terminal failure. The earlier Strix job could not
  pull `ghcr.io/usestrix/strix-sandbox:1.3.0` because GHCR returned HTTP
  500/EOF, and it produced no structured vulnerability report, so that run
  failed closed; the fresh exact-head rerun remains unverified while queued.
  Its local RED-to-GREEN, root-level SCIM error-wire, and cross-process
  sidecar evidence are not protected-main evidence. PR #112's lockfile head
  `f02acf93367a40dbfb23a73985017dca8d42ff39` has 22 terminal-success Checks
  but still requires independent review. PR #111's current head
  `e1d0fee6ce29cb9ec75d9fbdb38cd15242bf4fdc` is now stacked on #112. Its
  prior `account-unification-tests` failure occurred against the old `main`
  base because `uv sync --locked` found a stale `uv.lock` before tests began;
  the rerun against the lock-refresh base now has no terminal failure and two
  queued Checks. It remains coupled to #112 and #110. PR #110's current head
  `07acd65145c9522a74858d1ff8761ea05a09e8f0` was likewise retargeted to #112
  after the same pre-test lock failure; its rerun now has 18 successful Checks
  and two queued Checks with no terminal failure.
  The historical PR #105 exact head
  `72de5499d6e97ae7f7bd804ab78b3e1644dd5a4f` had a failed
  `account-unification-tests` Check: `uv 0.12.5` reproduced
  `uv sync --locked` refusing the stale `coverage==7.15.2` and
  `setuptools==83.0.0` lock entries while the current `pyproject.toml` required
  `7.15.4` and `84.0.0`; the current #105 head has nine queued and nine
  successful Checks with no terminal failure, and #112 remains the
  lock-refresh prerequisite.
  PR #103's historical terminal Strix run 32092025335 / job 95576032571
  emitted a MEDIUM IDOR report with contradictory model text. Current head
  `157b76893b32cda66fc586aa67ae72a30ac6b0d6` adds direct-mount operator-auth
  regression evidence, but the operator-admin trust boundary still requires
  independent validation. PR #100's pre-doctoring-refresh head was
  `c483bd53ea74aad5fcea7d3cec2f402e4d8f27c2`; successor head
  `3777f54a824d3b2d3458b94f88e5627a7761a2c0` adds a regression test that invokes
  the validator's committed default realm/profile paths after an exact-head
  Devin coverage finding. The current documentation successor is
  `0d4d1b98dfc8b722b5502dba942b322a1657902e`, with 14 queued Checks and no
  terminal failure; its prior review state is not approval. PR #104 is ready for review at
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
