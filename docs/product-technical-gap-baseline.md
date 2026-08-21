# Keyverse product and technical gap baseline

**Evidence snapshot:** 2026-08-21 (Asia/Seoul)
**Repository:** `ContextualWisdomLab/keyverse`
**Protected-main head observed:** `ce207dfd42975db61c82a5963e206fc1db14ac2b`
**Status:** live inventory and gap register; not a release acceptance record

This document turns the accepted PRD, TRD, architecture, ADRs, doctoring
records, and current GitHub state into an executable buyer-facing backlog.
It separates implementation on protected `main`, active PR work, accepted
contracts, and evidence that is still absent. A green unit or preflight check
does not promote a lower-level result into login, token, authorization, or
release acceptance.

## Product contract

Keyverse is a standalone and embeddable identity control plane for CWL, Naruon,
and sibling products. Its durable boundary owns passwordless-first Keycloak
policy, federation and directory preflight/reconciliation, account
unification, SCIM lifecycle, relying-party desired state, audit, and safe
deployment operations. Downstream applications still own token verification,
tenant/resource/purpose ABAC, and bounded RBAC.

The trust order is:

```text
portable realm policy
  -> authenticated side-effect-free preflight
  -> secret-free desired state
  -> exact remote reconciliation
  -> post-mutation observation and receipt
  -> controlled protocol acceptance
  -> downstream authorization acceptance
```

The final two stages are intentionally separate from Keycloak mapper
configuration. A relying-party registration or mapper receipt is never proof
that a receiving application validates issuer, signature, expiry, audience,
tenant, or resource ownership.

## Evidence classification

| Classification | Meaning in this baseline |
|---|---|
| `implemented-main` | Source and tests are on the observed protected-main head. |
| `active-PR` | Work exists in an open PR and is not part of protected-main evidence. |
| `active-issue` | A buyer or operational gap is tracked in an open issue and is not implemented evidence. |
| `accepted-contract` | An ADR/specification defines the policy, but runtime or buyer acceptance may still be absent. |
| `gap-not-claimed` | The repository deliberately makes no success claim until stronger evidence exists. |

## Current capability map

| Capability | Current state | Evidence boundary |
|---|---|---|
| Passwordless local identity | `implemented-main` | Portable realm validation requires WebAuthn passwordless flow and rejects a password authenticator. |
| Federation and LDAP preflight | `implemented-main` | Closed validators are side-effect-free; apply and external bind/discovery remain separate. |
| Account linking, merge, and SCIM full replacement | `implemented-main` | Verified identity evidence, tombstones, audit, and shared merge/`PUT` lock are covered. SCIM `PATCH active=false` is intentionally narrower. |
| Secret-free RP desired state | `implemented-main` | Exact client identity, duplicate fail-closed behavior, re-observation, receipt, and remote-first delete are implemented. |
| Closed RP mapper profile | `implemented-main` / `accepted-contract` | Canonical `role`, `org`, `workspace` policy is protected; ADR-0009 remains a separate `lineageweave-web` profile. |
| Downstream RP authorization | `gap-not-claimed` | Each consumer must independently prove issuer/JWKS/signature/expiry/audience, tenant/resource ABAC, and RBAC. |
| Real Keyverse login and token acceptance | `gap-not-claimed` | Local tests do not establish a live issuer, controlled account, browser flow, or consumer token acceptance. |
| Standalone Compose and Helm module boundaries | `implemented-main` | Repository contracts and validators exist; release-grade deployment/rollback evidence is still required. |
| Hourly product and PR loop | `active-PR` / `implemented-main` | Workflows and fail-closed guards exist; every scheduled run must be checked against exact external evidence. |
| Release artifact acceptance | `gap-not-claimed` | Version, immutable image digest, SBOM/provenance, rollback, and exact-main acceptance remain release gates. |

## Live PR inventory

The following is the current open-PR inventory. `Checks` means the exact head
rollup observed on 2026-08-21; it is not inherited from a predecessor commit.
This record was refreshed from a live exact-head audit while PR #100 stood at
`cdd0d744352afffe29de6058ad5a3326a83beda1`; the documentation commit that
updates this snapshot is intentionally not recursively named. The audit also
includes normal branch updates from the #112 lock-refresh base for the
dependency/documentation stack. The live PR record is authoritative for the
exact hash and Checks; predecessor evidence remains non-transferable.

At this snapshot, 15 PRs are open and none has a qualifying formal approval.
#112, #101, and #83 each have 23 successful and 8 skipped Checks with no
queued Check; #108 and #107 each have 21 successful, 1 queued, and 8 skipped
Checks; #110 and #109 each have 20 successful, 1 queued, and 8 skipped Checks;
#111 has 20 successful, 2 queued, and 7 skipped Checks; #106 and #105 each have
20 successful, 1 queued, and 8 skipped Checks; #104 has 21 successful, 1
queued, and 8 skipped Checks; #103 and #100 each have 2 successful, 14 queued,
and 7 skipped Checks; #113 has 2 successful, 14 queued, and 7 skipped Checks;
and #115 has 2 pending, 14 queued, and 7 skipped Checks. The exact rollup is
listed per PR below; pending and queued Checks remain unverified rather than
green.
There is no current terminal failure bucket in this inventory. Historical
terminal failures are recorded separately and are not current-head green
evidence.

### Post-snapshot exact-head delta

After the inventory snapshot, PR #115 advanced normally to
`5550408490d868fb92fdb988aa1bae62192629b4` to correct review-verified
token-audience and RFC 8414 metadata wording. Its current rollup is 2
successful, 14 queued, and 7 skipped Checks with no formal approval. PR #113
advanced normally to `4a501a6ff9cb65a1e894e05513462fe89733d48e` to remove one
doctoring-document trailing-whitespace defect; its current rollup is 2
successful, 14 queued, and 7 skipped Checks with no formal approval. PR #100
advanced normally to `cdd0d744352afffe29de6058ad5a3326a83beda1` after the
baseline/reference updates; its latest observed rollup is 2 successful, 14
queued, and 7 skipped Checks with a changes-requested review state. This
documentation update itself will create a later head, so the resulting head
requires a fresh hosted recheck before any protected-merge claim.

| PR | Scope | Exact-head Checks | Review state | Next safe action |
|---:|---|---|---|---|
| [#115](https://github.com/ContextualWisdomLab/keyverse/pull/115) | Proposed ADR/doctoring for MCP-compatible OAuth client authorization | PENDING: 2 successful, 14 queued, 7 skipped, 0 terminal failures on `5550408490d868fb92fdb988aa1bae62192629b4` | review required | The token-audience and metadata-member findings are fixed; obtain independent ADR review and do not treat the design PR as runtime MCP evidence or begin implementation before the trust boundary is accepted. |
| [#113](https://github.com/ContextualWisdomLab/keyverse/pull/113) | SCIM `PATCH active=false` shared operation lock, stacked on #112 lockfile refresh | PENDING: 2 successful, 14 queued, 7 skipped, 0 terminal failures on `4a501a6ff9cb65a1e894e05513462fe89733d48e` | review required | The valid SCIM PatchOp and deterministic-race fixes plus the minimal doctoring cleanup are complete; wait for fresh exact-head hosted Checks and independent review. |
| [#112](https://github.com/ContextualWisdomLab/keyverse/pull/112) | Resync account-unification lockfile | PASS: 23 successful, 8 skipped, 0 queued on `f02acf93367a40dbfb23a73985017dca8d42ff39` | review required | Obtain independent review, then let protected automation re-check and merge. |
| [#111](https://github.com/ContextualWisdomLab/keyverse/pull/111) | CodeQL init 4.37.7 | PENDING: 20 successful, 2 queued, 7 skipped, 0 terminal failures on updated head `032f730b0239d062cf9803525ba66c740e0b2d2e` | review required | The normal branch update merged #112's lockfile base into the CodeQL branch; resolve the queued Strix retry and remaining coverage Check, then obtain independent review. |
| [#110](https://github.com/ContextualWisdomLab/keyverse/pull/110) | CodeQL analyze 4.37.7, stacked on #112 lockfile refresh | PENDING: 20 successful, 1 queued, 8 skipped, 0 terminal failures on updated head `c3e307fc3d4f6d98ec5a0514f35aa8038b2737b7` | review required | The normal branch update includes #112's lock-refresh base; wait for exact-head Checks and independent review. |
| [#109](https://github.com/ContextualWisdomLab/keyverse/pull/109) | `typing-inspection` update, stacked on #112 lockfile refresh | PENDING: 20 successful, 1 queued, 8 skipped, 0 terminal failures on `7b726b16d38ce16d13d00c946b5c8bc0c406191f` | review required | The normal merge and local locked-install/full-suite verification are complete; wait for fresh hosted Checks and independent review. |
| [#108](https://github.com/ContextualWisdomLab/keyverse/pull/108) | Ruff update, stacked on #112 lockfile refresh | PENDING: 21 successful, 1 queued, 8 skipped, 0 terminal failures on `538cead991a7c1bed32f2dcb5413b5fc56f53e93` | review required | The conflicting lockfile base was rebased cleanly onto #112; wait for remaining exact-head Checks and independent review. |
| [#107](https://github.com/ContextualWisdomLab/keyverse/pull/107) | Uvicorn update, stacked on #112 lockfile refresh | PENDING: 21 successful, 1 queued, 8 skipped, 0 terminal failures on `53842560d397aa20309a6b16aceb560540611686` | review required | The conflicting lockfile base was rebased cleanly onto #112; wait for the remaining exact-head Check and independent review. |
| [#106](https://github.com/ContextualWisdomLab/keyverse/pull/106) | `setup-uv` update, stacked on #112 lockfile refresh | PENDING: 20 successful, 1 queued, 8 skipped, 0 terminal failures on updated head `e7fafd4192cc3cc344b8f8e536bc0495afaa739f` | review required | The normal branch update includes #112's lockfile base; wait for exact-head Checks and independent review. |
| [#105](https://github.com/ContextualWisdomLab/keyverse/pull/105) | `harden-runner` update, stacked on #112 lockfile refresh | PENDING: 20 successful, 1 queued, 8 skipped, 0 terminal failures on updated head `77f83dfb2c4611345c0d48f92fceaa6195b4630c` | changes requested | The normal branch update includes #112's lockfile base; obtain current-head independent review. |
| [#104](https://github.com/ContextualWisdomLab/keyverse/pull/104) | ADR and buyer README expansion, stacked on #112 | PENDING: 21 successful, 1 queued, 8 skipped, 0 terminal failures on updated head `7da9d43087d5647fefb946eb154ee1e5c10c576d` | review required | Base remains `fix/account-unification-lock-20260819`; obtain independent review and terminal stacked-head Checks. |
| [#103](https://github.com/ContextualWisdomLab/keyverse/pull/103) | Hierarchical authorization, login helper, PATs | PENDING: 2 successful, 14 queued, 7 skipped, 0 terminal failures on `e765f4860177af47b80b05ee3a918a4dc2cb4450` | changes requested | Exact-tree regressions and local 100% verification pass; wait for hosted security Checks and current-head independent review before any merge claim. |
| [#101](https://github.com/ContextualWisdomLab/keyverse/pull/101) | Atomic coupled Python dependency updates | PASS: 23 successful, 8 skipped, 0 queued on `50dd9c96cab5c230f775685e8baea939fba390dd` | changes requested | Obtain fresh independent review; this is the policy companion to the lockfile gap. |
| [#100](https://github.com/ContextualWisdomLab/keyverse/pull/100) | `lineageweave-web` account-derived claims plus default validator-path coverage | PENDING: 2 successful, 14 queued, 7 skipped, 0 terminal failures on observed head `cdd0d744352afffe29de6058ad5a3326a83beda1` | changes requested | The current-tree review findings are addressed; this docs refresh creates a later head, then fresh exact-head Checks and independent review are required without self-approval. |
| [#83](https://github.com/ContextualWisdomLab/keyverse/pull/83) | Remove runtime application RPs from portable realm | PASS: 23 successful, 8 skipped, 0 queued on `dd1ab7444a75342b42e3af013ccda6d1dbfb359d` | changes requested | Reconfirm current-head approval and latest-pusher rule before protected merge. |

### Historical check failure root causes observed

The evidence set contains two relevant terminal failures from earlier exact
heads. The following items explain those failures and earlier failures that still determine safe
sequencing; they must not be copied to another PR as if they were transferable
evidence.

- PR #113's exact-head `strix` failure was an external image-pull failure, not
  a source finding: `ghcr.io/usestrix/strix-sandbox:1.3.0` returned HTTP 500
  with an EOF while downloading from GHCR, and no structured vulnerability
  report was produced. The workflow correctly failed closed. A fresh run is
  required after the external image service recovers; no code change can make
  that exact failed run green.

- PR #113's predecessor exact head
  `49136c24fb07e3a8ed01171785e6946c559ea2a5` contained the valid SCIM
  PatchOp review correction and passed focused/full local verification with
  100% statement and branch coverage. The current exact head
  `4a501a6ff9cb65a1e894e05513462fe89733d48e` adds only the doctoring
  whitespace cleanup; its hosted Checks remain pending with no terminal
  failure, and independent approval is absent.

- PR #111's prior exact-head `account-unification-tests` failure stopped before
  tests at `uv sync --locked`: the branch tree did not contain the #112 lock
  refresh even though its PR base had been retargeted. The normal, non-force
  `gh pr update-branch 111` operation merged #112's base into the branch and
  produced current head `032f730b`; its fresh `account-unification-tests` run
  is queued, so the old failure is historical and the new result is unverified.

- PR #111's first Strix attempt on the unchanged CodeQL-only diff failed after
  the Nemotron provider emitted one critical Compose configuration finding.
  The neighboring #110 check completed through its neutral backend fallback
  and #112 passed; the report contradicted the checked configuration by describing an unset
  password variable as a default credential. The failure is retained as
  historical model evidence rather than silently converted to green; a normal
  exact-head Strix retry is queued as run attempt 2.

- The representative account-test failure on Dependabot PRs stopped at
  `uv sync --locked`: the checked-in lockfile needed updating. This is a
  dependency-graph consistency failure, not evidence that the product tests
  failed after installation. On PR #105 exact head
  `72de5499d6e97ae7f7bd804ab78b3e1644dd5a4f`, `uv 0.12.5` reproduced the
  mismatch between required `coverage==7.15.4` / `setuptools==84.0.0` and
  locked `7.15.2` / `83.0.0`; PR #112 is the existing lock-refresh
  prerequisite, so #105 must be rechecked after #112's protected merge.
- PRs #110 and #111 update the two coupled CodeQL actions separately. The
  #111 run loaded configuration for 4.37.7 while running 4.37.6. They must be
  evaluated as one compatible pair, with fresh exact-head Checks after the
  lockfile queue is clear.
- PR #103 Strix run 32092025335 / job 95576032571 failed closed after emitting
  a MEDIUM IDOR report that requests binding grant-management
  actor_identity_id values to the authenticated principal. The same model
  report also says the issue was already resolved, so the evidence is
  contradictory. The routes are currently operator-admin gated and the
  operator token does not expose distinct end-user principals; independent
  security validation must resolve that trust-boundary interpretation. Until
  then the failure remains blocking and is not converted into a pass.
- PR #103's current exact head `e765f4860177af47b80b05ee3a918a4dc2cb4450`
  adds RED-to-GREEN regressions for percent-encoded discovery markers,
  inactive and expired token rotation, invalid token rotation settings, KV/audit
  lifecycle failures, direct router embedding, tenant isolation, software-unit
  ABAC, runtime authentication, and untrusted public issuers. Local
  focused/full tests, Ruff, Interrogate, and 100% application statement/branch
  coverage pass; its required hosted Checks are still pending or queued, so no
  hosted security or independent approval success is claimed.

## Open Issue inventory

| Issue | Product signal | Classification | Required outcome |
|---:|---|---|---|
| [#114](https://github.com/ContextualWisdomLab/keyverse/issues/114) | MCP-compatible OAuth client authorization for headless agents | `active-issue` / design `active-PR` | PR #115 proposes ADR-0013 and the doctoring record for Keycloak-backed discovery, public-client authorization code + PKCE, exact redirects, resource-bound least-privilege tokens, centralized revocation/audit, and negative browser/client evidence. Runtime implementation remains unclaimed; evaluate RFC 8628 only for clients that cannot use a callback. |
| [#102](https://github.com/ContextualWisdomLab/keyverse/issues/102) | Hierarchical authorization plane, login helper, PATs | `active-PR` | Security-review the proposed authority model and prove fail-closed token/tenant/resource behavior. |
| [#99](https://github.com/ContextualWisdomLab/keyverse/issues/99) | Orphaned federation and product-loop workflow identities | `active-issue` | The exact protected-main cleanup completed: 43 registry identities remain, with 4 supported repository paths active, 37 orphan repository-path identities `disabled_manually`, and 2 GitHub-owned dynamic identities unchanged. The recurrence detector, adversarial tests, and central coordination acceptance remain open. |
| [#71](https://github.com/ContextualWisdomLab/keyverse/issues/71) | Remove runtime application RPs from portable import | `active-PR` | Merge #83 only after current-head protected evidence. |
| [#2](https://github.com/ContextualWisdomLab/keyverse/issues/2) | Central IdP plus external-IdP federation | `accepted-contract` | Use the existing closed preflight/apply boundary and add approved-environment acceptance. |

## Gap register and buyer-visible order

### G0 — Protected queue convergence

**State:** `active-PR`
**Buyer impact:** A buyer cannot rely on a controlled identity product if the
repository cannot distinguish a reviewed, current, passing artifact from a
stale or coupled dependency proposal.

**Required loop:** inventory PRs; inspect review threads; fix the root cause;
verify the exact head; require independent approval; let the protected steward
arm normal auto-merge; verify merge SHA; then re-list. Never self-approve,
force-push, admin-merge, or treat queued/retrievable-missing Checks as green.

### G1 — Coupled dependency and workflow updates

**State:** `active-PR`
**Root cause:** the current queue contains a lockfile consistency fix and two
CodeQL action updates that are safe only as a coupled set.

**Acceptance:** #112 passes the full current Checks and receives independent
approval; #101/#110/#111 are then re-evaluated on current bases; `uv sync
--locked` succeeds; both CodeQL actions resolve the same compatible version;
Strix and security checks are completed; no stale predecessor evidence is
counted.

### G2 — Stable downstream tenant semantics

**State:** `active-PR` contract clarification; runtime remains `gap-not-claimed`
**Root cause:** Keyverse emits a deliberately closed `role`, `org`, and
`workspace` profile, but a consumer must not guess that either account
dimension is an application-specific `tenant_id`.

**Contract clarification:** for `lineageweave-web`, `org` is the one opaque
external tenant key and `workspace` is one child namespace under that `org`.
Multiple memberships have no comma-separated or array encoding; missing,
unmapped, or ambiguous membership resolution denies before ABAC/RBAC. A
membership change requires a new token or session renewal. The full consumer
acceptance still requires the negative vector in which a valid token for tenant
B cannot authorize tenant A, plus resource authorization evidence.
Until a consumer proves that runtime contract, it remains deployment-restricted.
Adding a generic tenant mapper to Keyverse is not an acceptable shortcut; it
would expand the closed mapper policy without a separately reviewed profile.

### G3 — Controlled real login and authorization acceptance

**State:** `gap-not-claimed`
**Buyer impact:** Static realm/template validation is not a buyer-observable
login or authorization guarantee.

**Acceptance:** in an approved environment, record redacted evidence for
discovery/issuer, JWKS signature and algorithm, authorization-code + PKCE
`S256`, passwordless browser login, token `iss`/`sub`/`aud`/time claims,
controlled logout, tenant/resource ABAC, role/scope RBAC, cross-tenant denial,
and verifier-unavailable fail-closed behavior. Keep secrets and PII out of
repository artifacts. An unavailable issuer must remain `unavailable`, never
be converted into a synthetic success.

### G8 — MCP-compatible OAuth resource authorization

**State:** `active-PR` design; runtime remains `gap-not-claimed`
**Buyer impact:** An MCP client currently has no protected-main evidence for a
passwordless authorization-code path that is bound to one LineageWeave resource
and centrally revocable.

**Current action:** PR #115 proposes ADR-0013 and its doctoring record. The
design keeps Keycloak as the authorization server, assigns RFC 9728 protected-
resource metadata to LineageWeave, requires exact public-client redirects and
`S256` PKCE, binds one canonical RFC 8707 resource URI to the token audience and
least-privilege scope set, and defers RFC 8628 until a real callback-less client
requires it. The PR is documentation-only; its pending/queued Checks and
review-required state are not runtime evidence.

**Acceptance:** after ADR review, run a real browser/client flow and record
discovery agreement, exact redirect/PKCE/resource/scope checks, wrong
issuer/audience/resource/redirect/expiry/revocation denials, cross-tenant and
cross-workspace denials, and no static MCP API-key path. Keep discovery
side-effect-free in existing preflight tests and avoid bearer material in logs.

### G4 — SCIM deactivation concurrency boundary

**State:** `active-PR` with an explicit protected-main limitation
**Root cause:** protected `main` did not cover `PATCH active=false` with the
shared cross-process lock used by merge and full-replacement `PUT`.

**Acceptance:** PR #113 adds the shared lock, root-level SCIM `503`
lock-timeout mapping, real concurrent deactivation/merge and cross-process
sidecar-lock regressions, and reconciled
PRD/TRD/UML/Threat/Test/Operability/doctoring records. The protected-main gap
closes only after exact-head hosted Checks, independent review, protected merge,
and a refreshed baseline prove the change on main.

### G5 — Physical database and hot-partition evidence

**State:** `gap-not-claimed`
**Root cause:** the ERD defines logical tenant-qualified uniqueness and
two-word-or-longer snake_case names, but a production claim needs migration,
index, partition-key, skew, and recovery evidence from the owning database.

**Current repository evidence:** the focused local SQLite storage/lifecycle
regression run (`tests/test_storage_concurrency.py` and
`tests/test_lifecycle.py`) passed 6 tests on this tree. It proves only the
sidecar's local locking and lifecycle behavior; it is not PostgreSQL migration,
partition-skew, backup, restore, or production recovery evidence.

**Current local PostgreSQL probe (2026-08-21):** the running Compose
`idp_database` uses the pinned PostgreSQL 17 image and reports 88 non-system
tables, 3,981,312 relation bytes, zero partitioned tables, and
`pg_is_in_recovery=false`. Observed settings were `max_connections=100`,
`shared_buffers=163848kB`, `work_mem=4096kB`, `wal_level=replica`, and
`archive_mode=off`. This is a local Keycloak system-of-record smoke probe; it
does not prove tenant skew tolerance, application-owned partitioning, backup/
restore, failover, or production sizing.

**Acceptance:** run PostgreSQL migration/rollback tests with tenant-scoped
composite constraints, measure skew under concentrated tenants, document the
chosen partition/index strategy, and prove backup/restore. Do not add a
partitioning abstraction before measured pressure requires it.

### G6 — Release and module acceptance

**State:** `gap-not-claimed`
**Acceptance:** on exact protected `main`, complete regression and controlled
deployment acceptance; publish immutable image digest, SBOM, provenance,
rollback/restore evidence, version consistency, and CHANGELOG entry. A green
feature PR is not a release.

### G7 — Ecosystem consumer readiness

**State:** `accepted-contract` / `gap-not-claimed`
**Root cause:** Keyverse exposes stable HTTP/protocol boundaries, but a module
boundary is only buyer-ready when each owned consumer proves its own
authorization and operational acceptance.

**Acceptance order:** Keyverse issuer and RP contract first; then the highest
leverage owned consumer with a falsifiable browser/API acceptance lane; then
federation/SCIM connectors. Preserve import/REST boundaries and do not copy
private Keycloak internals into sibling repositories.

## Hourly loop contract

The repository currently schedules:

- **Hourly PR steward:** UTC minute `17`, inventory and advance only trusted
  same-repository PRs with exact-head independent approval and required Checks.
- **Hourly product development:** UTC minute `41`, after the steward's evidence
  settles; create at most one bounded draft product-gap PR only when the open
  PR queue is empty and protected-main evidence is healthy.

The current live run inventory showed a successful product-development run at
the protected-main head and a queued PR-steward run. Queued or delayed runs are
not blockers for independent documentation, review analysis, standards work,
or test design, but they are not evidence of a merge or release.

## Standards interpretation and design tooling boundary

The baseline follows OpenID Connect's exact issuer/audience/time/signature
validation boundary, JWT Best Current Practices' issuer/subject/audience
validation, and OAuth Security BCP's authorization-code + PKCE and exact
redirect guidance. Keycloak protocol mappers are treated as claim projection
configuration, not as downstream authorization proof.

This change adds no UI or frontend behavior, so no Figma file or Storybook
inventory is required for this baseline. If a future buyer gap changes a web
surface, the owning ADR must record the Figma File ID, design tokens, reusable
components, Storybook inventory, and interaction/accessibility acceptance
before implementation is claimed.

## References

- OpenID Foundation. (2014). *OpenID Connect Core 1.0*. https://openid.net/specs/openid-connect-core-1_0-18.html
- Keycloak. (2026). *Server administration guide*. https://www.keycloak.org/docs/latest/server_admin/
- Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current practice for OAuth 2.0 security* (RFC 9700). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9700.html
- Sheffer, Y., Hardt, D., & Jones, M. (2020). *JSON Web Token best current practices* (RFC 8725). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc8725.html
- Internet Engineering Task Force. (2018). *OAuth 2.0 authorization server metadata* (RFC 8414). https://doi.org/10.17487/RFC8414
- Internet Engineering Task Force. (2024). *Resource indicators for OAuth 2.0* (RFC 8707). https://doi.org/10.17487/RFC8707
- Internet Engineering Task Force. (2025). *OAuth 2.0 protected resource metadata* (RFC 9728). https://doi.org/10.17487/RFC9728
- Model Context Protocol. (2025, November 25). *Authorization*. https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

Interpretations and repository evidence are maintained separately in
[`docs/doctoring/product-technical-gap-baseline.md`](doctoring/product-technical-gap-baseline.md).
