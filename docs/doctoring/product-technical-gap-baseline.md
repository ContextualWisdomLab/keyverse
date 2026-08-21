# Product-technical gap baseline doctoring record

**Date:** 2026-08-22
**Scope:** Keyverse product, trust-boundary, PR queue, and release evidence

## 2026-08-22 live PR and control-plane refresh

The protected Keyverse `main` head remains
`ce207dfd42975db61c82a5963e206fc1db14ac2b`. The live open queue is #83, #100,
#101, #103, #112, and #113. Their current exact heads are respectively
`dd1ab7444a75342b42e3af013ccda6d1dbfb359d`,
`19ebd86500d17f3aebcfec6e65965c0a79fab6c0`,
`50dd9c96cab5c230f775685e8baea939fba390dd`,
`77b8f4ea9995329f1c55b916d110b460b4bc7649`,
`ec34ac14fd38c9c7c463cddbd0ced04b4dfccafd`, and
`9bd33ee0d00ef1874fd5efabac3462f678a256ed`. All report
`REVIEW_REQUIRED`; #112 has zero valid unresolved threads after the current
masked-secret disposition. No PR has a formal approval satisfying the
protected merge gate.

Current Keyverse Checks are: #83 22 successful/8 skipped; #100 22
successful/8 skipped; #101 22 successful/8 skipped;
#103 22 successful/8 skipped; #112 22 successful/8 skipped; and #113 22
successful/8 skipped. The #112 code fix for Keycloak's fixed masked
`clientSecret` read-back is locally verified at 100% production statement and
branch coverage, and its hosted Checks are terminal-success; independent
approval remains absent. No emergency bypass is justified.

Current control-plane evidence is protected `.github` main
`0156282022134484ea9d7541d5ba0730ba14fd96`. The OSV cross-fork
result-isolation root #1209 is at
`d3a3f4e6211a56d503b783d8784d1d79a262ca68` with 28 successful, 21 skipped,
1 cancelled, 3 neutral, and 2 queued Checks. The hourly OIDC caller repair
#1188 is at `2c05f05f5fbb923099e0e228d616ab9974dbd327` with 28 successful, 18
skipped, 1 cancelled, 3 neutral, and 1 queued Check. The combined security
and scheduler root #1198 is at
`801c2f1bc43e99d89ab3745ea8722779f7081b95` with 3 successful, 15 skipped,
1 cancelled, 2 in-progress, and 16 queued Checks after its exact
merge-preview repair; replay-guard repair #1166 is at
`e6c03f618d54497b98eaf96afa21724b19847bd2` with 26 successful, 29 skipped,
6 cancelled, 3 neutral, and 1 queued Check. Scheduler repair #1203 was
normally merged into the #1198 feature branch at
`4d3d24aa404959f5067735fec0558d5924ade590`; review repair #1002 was then
normally merged into that same feature branch at
`3016543f735bb24db760cfaa768e64f95f408473`; OSV repair #1208 is closed
without merge; #1172 is normally restacked at
`edab578feca63c223368aef17c175bb52ce22e5a` with 26 successful, 20 skipped,
2 cancelled, 3 neutral, and 1 queued Check; and #1026 is at
`1be76989887ab772e3ce0d2e0c7f22d3ca98dd94` with 28 successful, 22 skipped,
2 cancelled, 3 neutral, and 1 queued Check. The dependency failure and
hosted-gate state are source/hosted-gate problems, not demonstrated
control-plane deadlocks. All predecessor evidence remains non-transferable.

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

## 2026-08-21 MCP OAuth design evidence

- Issue #114 remains an active buyer gap. Keyverse must use Keycloak as the
  authorization server, not add a static MCP API key or a second user/token
  authority.
- Keyverse PR #115 is open at exact head
  `7281c3d961f40bf47383b8cddeae750af1298ad5`. It adds proposed ADR-0013 and
  `docs/doctoring/mcp-oauth-authorization.md`, covering OIDC/RFC 8414
  discovery, public-client authorization code plus `S256` PKCE, exact
  redirects, RFC 8707 resource binding, RFC 9728 LineageWeave metadata,
  centralized revocation/audit, and negative evidence.
- PR #115 is documentation-only. Its initial post-publication rollup had 2 pending, 14 queued,
  and 7 skipped Checks with review required; no MCP browser flow, resource
  metadata endpoint, resource-bound token, revocation check, or LineageWeave
  end-to-end result is claimed. RFC 8628 remains deferred until a real
  callback-less client requires it.
- After its review corrections, PR #115's current exact head is
  `0e0c15c4ba7d631660693c549dcbb7e863d6287b`; its current rollup is 2
  successful, 14 queued, and 7 skipped Checks. This remains documentation
  evidence only, not a protected merge or runtime acceptance.

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
  `1f2b93ead7205b33712de1865d84c004d93be7ed` for routing OpenCode reviews
  through the contextual gateway. Its current hosted rollup has 5 successful,
  16 pending, and 13 skipped Checks; no terminal source failure or qualifying
  formal approval is recorded. Its current-head review threads are resolved.
  The current head removes inherited GitHub
  credentials and workflow-file channels from the child gateway process and
  has passed the focused contract test plus full local central verification.
- Central `.github` PR #1178 is the canonical contextual-orchestrator hourly
  caller, open at exact head
  `97b084ac28b5ccf6de7f68fd2e019d8da6f80143`. Its current rollup has 25
  successful, 3 neutral, 2 pending, 1 cancelled, and 19 skipped Checks, with
  no terminal source failure. Neither #1170 nor #1178 has qualifying formal approval or protected
  merge evidence.
- Central `.github` PR #1176 is open at exact head
  `33b85a8cf48d5b6e0880d5071b360ffa46f83457` to require central reviews for
  stacked PRs. Its current rollup has 23 successful, 3 neutral, 6 pending, and
  15 skipped Checks, with no qualifying formal approval.
- Central `.github` PR #1187 is open at exact head
  `91c16ebf5187daad749ae57ec01d16cb7afec7b3` for scoped Rust coverage
  evidence. Its current rollup has 6 successful, 16 pending, 15 skipped, and
  1 cancelled Check, with no terminal source failure; the cancelled
  `scan-pr-queue` job has a newer queued retry. It has no qualifying formal
  approval or protected merge evidence.
- Central `.github` PR #1152 is open at exact head
  `11491068712859e936e7ce4ed7f204f5c1157f0c` for the OpenCode retry path. Its
  current rollup has 1 successful and 16 pending Checks, with 13 skipped and
  no terminal source failure or qualifying formal approval.
- Central `.github` PR #1174 is open at exact head
  `11f397988f871b7566e6e1c5dcf5fd82be905dc0` for the mention-router
  acknowledgement recovery path. Its current rollup has 26 terminal
  successes, 3 neutral, 1 queued, and 15 skipped Checks, with no terminal
  source failure or qualifying formal approval. It is the normal
  source fix for recent main-branch `Review Agent Mention Router` failures
  (`32438800573`, `32438736861`, and `32438190241`) where a target
  acknowledgement reaction returned HTTP 403 after durable dispatch. The
  current head preserves the durable dispatch and retries only the cosmetic
  acknowledgement without creating a duplicate dispatch.
- Central `.github` PR #1189 is open at exact head
  `07cdefca207e8bc09e714e33740a47809cb5d9a4` to close the pre-existing
  repository-wide docstring gap in the organization commercial-readiness
  coordinator. The one-line behavior-neutral fix passed the full local suite,
  100% statement/branch coverage, and 100% interrogate verification. Its
  current hosted rollup has 3 successful, 16 queued, 1 cancelled, and 15
  skipped Checks, with no terminal source failure or qualifying formal approval
  or protected merge.
- Central `.github` PR #1155 is open at exact head
  `4b9a933d77a1d68459bf2c51abfbdba9e2d03d8b` for stable deduplication of
  unscoped scheduler dispatches and bounded stale-review input. Its current
  rollup has 26 successful, 3 neutral, 1 queued, and 15 skipped Checks, with
  no qualifying formal approval. Historical run `32434533013` remains a
  fail-closed malformed targeted dispatch for `ContextualWisdomLab/TEPP`
  without a PR number; it is not treated as successful scheduler evidence or
  as permission to weaken target validation.
- Central `.github` PR #1171 is open at exact head
  `ff65c16063f7b687df09253d31d84dac6517c0ea` to refuse scheduler head
  mutations when required checks cannot be started. Its current rollup has 5
  successful, 16 queued, and 13 skipped Checks, with no qualifying formal
  approval. The exact head passed the full local central suite and scheduler
  100% statement/branch coverage; hosted queued evidence remains unverified.
- Central `.github` PR #1188 is open at exact head
  `7f9f9f0606ac5c88df3857eb5e5367d5bdbad420` to grant the DiskSage and
  Clearfolio hourly reusable-workflow callers job-scoped OIDC permission. Its
  current rollup has 4 successful, 16 queued, 15 skipped, and 1 cancelled
  Check, with no qualifying formal approval or protected merge.
- The scheduled central `.github` Organization Commercial Readiness Loop run
  `32437647976` failed before coordination because the configured
  `PR_REVIEW_MERGE_TOKEN` was unavailable. This is a fail-closed credential
  configuration gap, not permission to substitute `GITHUB_TOKEN` or bypass the
  reviewer credential boundary; remediation requires the owning secret
  configuration or an explicit owner decision.
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

Internet Engineering Task Force. (2018). *OAuth 2.0 authorization server
metadata* (RFC 8414). https://doi.org/10.17487/RFC8414

Internet Engineering Task Force. (2020). *Resource indicators for OAuth 2.0*
(RFC 8707). https://doi.org/10.17487/RFC8707

Internet Engineering Task Force. (2025). *OAuth 2.0 protected resource
metadata* (RFC 9728). https://doi.org/10.17487/RFC9728

Model Context Protocol. (2025, November 25). *Authorization*.
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

GitHub. (2026). *REST API endpoints for workflows*.
https://docs.github.com/en/rest/actions/workflows?apiVersion=2022-11-28

## Evidence sources

- `docs/PRD.md`, `docs/TRD.md`, `ARCHITECTURE.md`, `docs/OPERABILITY.md`,
  `docs/THREAT_MODEL.md`, `docs/TEST_STRATEGY.md`, and `docs/TRACEABILITY.md`.
- ADR-0008, ADR-0009, and proposed ADR-0013 plus their related specification,
  plan, operations, and doctoring records.
- The live open-Issue query performed on 2026-08-21 found five open issues;
  newly tracked Issue #114 defines the buyer gap for MCP-compatible OAuth client
  authorization for headless agents. PR #115 proposes its design contract;
  implementation remains deferred until that contract is independently
  reviewed and the PR/Issue queue permits a bounded runtime change.
- LineageWeave PRs #333 and #334 are both currently closed without merge;
  their managed/static MCP API-key direction is superseded by Issue #114's
  centralized Keyverse OAuth boundary and must not be revived as a second
  identity, issuance, revocation, or audit system.
- Exact-head GitHub PR, review, issue, check-run, ruleset, and scheduled-run
  queries performed on 2026-08-21. Fifteen Keyverse PRs are open: #112, #101,
  and #83 each have 23 successful and 8 skipped Checks with no pending run;
  #108 and #107 each have 21 successful, 1 queued, and 8 skipped; #110 and
  #109 each have 20 successful, 1 queued, and 8 skipped; #111 has 19
  successful, 2 queued, and 7 skipped; #106 and #105 each have 20 successful,
  1 queued, and 8 skipped; #104 has 21 successful, 1 queued, and 8 skipped;
  #103 and #100 each have 2 successful, 14 queued, and 7 skipped; #113 has 2
  successful, 14 queued, and 7 skipped; and #115 has 2 pending, 14 queued,
  and 7 skipped Checks. No current open PR has a qualifying formal approval or
  terminal failure. Pending and queued Checks remain unverified.
  PR #113's current SCIM lock head
  `49136c24fb07e3a8ed01171785e6946c559ea2a5` includes the normal prerequisite
  lockfile history, a realistic SCIM PatchOp race, and the corrected valid
  root-level deactivation payload. Its hosted Checks remain pending with no
  terminal failure. Local focused/full verification and 100% statement/branch
  coverage passed, but hosted security and independent approval remain
  unverified. The earlier Strix job could not pull
  `ghcr.io/usestrix/strix-sandbox:1.3.0` because GHCR returned HTTP 500/EOF and
  produced no structured vulnerability report, so that run failed closed.
  Its local RED-to-GREEN, root-level SCIM error-wire, and cross-process sidecar
  evidence are not protected-main evidence. PR #112's lockfile head
  `f02acf93367a40dbfb23a73985017dca8d42ff39` has 23 successful and 8 skipped
  Checks but still requires independent review. PR #111's current head
  `032f730b0239d062cf9803525ba66c740e0b2d2e` now contains #112's lockfile
  through a normal branch update. Its prior `account-unification-tests`
  failure occurred before that update; the fresh run remains unverified. Its
  first Strix attempt also failed on contradictory model-generated Compose
  evidence; the neighboring #110 check used its neutral backend fallback and
  #112 passed. A normal exact-head attempt 2 is queued. It remains coupled to
  #112 and #110. PR #110's current head
  `c3e307fc3d4f6d98ec5a0514f35aa8038b2737b7` remains on the #112 base with
  20 successful, 1 queued, and 8 skipped Checks; its hosted reruns remain
  unverified.
  The historical PR #105 exact head
  `72de5499d6e97ae7f7bd804ab78b3e1644dd5a4f` had a failed
  `account-unification-tests` Check: `uv 0.12.5` reproduced
  `uv sync --locked` refusing the stale `coverage==7.15.2` and
  `setuptools==83.0.0` lock entries while the current `pyproject.toml` required
  `7.15.4` and `84.0.0`; the current #105 head
  `77f83dfb2c4611345c0d48f92fceaa6195b4630c` is stacked on #112 and has 20
  successful, 1 queued, and 8 skipped Checks with no terminal failure. The
  current #106 head `e7fafd4192cc3cc344b8f8e536bc0495afaa739f` likewise has
  20 successful, 1 queued, and 8 skipped Checks. PR #109's head
  `7b726b16d38ce16d13d00c946b5c8bc0c406191f` has 20 successful, 1 queued,
  and 8 skipped
  Checks; local
  locked-install, full pytest, Ruff, Interrogate, and compileall verification
  passed before its normal merge commit was pushed.
  PR #107 was rebased cleanly onto #112 at
  `53842560d397aa20309a6b16aceb560540611686`, and PR #108 was rebased cleanly
  onto #112 at `538cead991a7c1bed32f2dcb5413b5fc56f53e93`; the latest rollups
  are 21 successful, 1 queued, and 8 skipped for #107 and 21 successful,
  1 queued, and 8 skipped for #108, with no terminal failure. Local
  `uv sync --locked --extra dev` plus the full service pytest suite passed on
  both rebased trees. Their fresh hosted Checks remain unverified and #112
  remains the lock-refresh prerequisite.
  PR #103's historical terminal Strix run 32092025335 / job 95576032571
  emitted a MEDIUM IDOR report with contradictory model text. Its current exact
  head `e765f4860177af47b80b05ee3a918a4dc2cb4450` adds RED-to-GREEN regressions
  for percent-encoded discovery markers, inactive and expired token rotation,
  invalid token rotation settings, KV/audit lifecycle failures, direct router
  embedding, tenant isolation, software-unit ABAC, runtime authentication, and
  untrusted public issuers. Local focused/full tests, Ruff, Interrogate, and
  100% application statement/branch coverage pass; required hosted Checks are
  still pending or queued, so hosted security and independent approval success
  are not claimed. The operator-admin trust boundary and the fresh security
  changes still require independent exact-head validation. PR #100's
  earlier documentation head was
  `f331938a4f3cd6808101b8888b76c0f87b1eb841`, with 2 successful, 14 queued,
  and 7 skipped Checks; its changes-requested review state is not approval. PR #104's updated
  head `7da9d43087d5647fefb946eb154ee1e5c10c576d` is based on #112's lockfile
  head and has 21 successful, 1 queued, and 8 skipped Checks.
  After the baseline/reference update, PR #100 advanced normally to
  `ee6c13f059b6074f990f51ae7cf26de62d2c6d67`; its then-observed rollup was 1
  successful, 1 pending, 14 queued, and 7 skipped Checks with changes
  requested. The new exact head remains unverified for protected merge.
  A subsequent docs-only push advanced PR #100 to
  `630cd320f6bfe305bc79c54755f6215a276bca9f`; its latest observed rollup is 2
  successful, 14 queued, and 7 skipped Checks with changes requested. The
  product baseline table supersedes the earlier #100 sub-record; this
  documentation refresh creates a later head that requires fresh hosted
  revalidation.
  This record travels in these PRs, so the live PR records remain authoritative
  for their changing exact hashes.
  The active ruleset requires two approving reviews, resolved threads, and
  latest-push approval, while its read-only audit exposes an
  `OrganizationAdmin` always-bypass actor. The ordinary documentation push
  emitted GitHub's server-side bypass warning; no explicit bypass option,
  protected merge, or self-approval was used. A complete read-only Keyverse
  Actions registry/tree reconciliation at protected `main` `ce207dfd` found 43
  active identities: four repository workflow paths present in the exact tree,
  37 active repository paths absent from it, and two `dynamic/*` GitHub-owned
  paths. The workflow registry used one API page and the recursive
  protected-tree response was not truncated. This is the immutable
  pre-mutation record for Keyverse issue #99; no credential, private payload, or
  PII is recorded here.

## 2026-08-21 workflow registry lifecycle remediation

- The protected-main ref was re-fetched immediately before mutation and
  remained `ce207dfd42975db61c82a5963e206fc1db14ac2b`.
- The four exact tree workflows (`ci.yml`, `codeql.yml`,
  `hourly-pr-steward.yml`, and `hourly-product-development.yml`) were checked
  for membership before any action and were excluded from mutation.
- The GitHub Actions workflow endpoint was used by numeric workflow ID with
  the recommended JSON accept header. The 37 active repository-path identities
  absent from the protected tree were set to `disabled_manually`; the two
  `dynamic/*` Dependabot identities were not changed. GitHub documents that
  this operation changes a workflow's state to `disabled_manually` and returns
  HTTP 204 (GitHub, 2026).
- Fresh post-action reconciliation found 43 identities: 41 repository paths,
  4 active supported workflows, 37 `disabled_manually` orphan records, and 2
  unchanged active dynamic records. Active repository-path records absent from
  the exact protected tree: zero.
- Operational smoke evidence remained intact: protected-main
  `Hourly product development` run `32443743245` succeeded, the latest
  completed `Hourly PR steward` run `32425875355` succeeded, and CodeQL run
  `31783415830` succeeded on the protected SHA. The latest `ci.yml` success
  (`31555831037`) predates the protected SHA and is recorded as such rather
  than promoted to current-head evidence.
- This closes the live orphan cleanup portion of issue #99. A read-only
  recurrence detector with pagination, path/ID reuse, branch movement,
  permission-loss, transient HTTP failure, dynamic-workflow, and active-PR
  cases remains required before the issue can close.
