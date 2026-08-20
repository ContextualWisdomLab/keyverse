# Keyverse product and technical gap baseline

**Evidence snapshot:** 2026-08-20 (Asia/Seoul)
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
rollup observed on 2026-08-20; it is not inherited from a predecessor commit.
The #100 row is intentionally expressed as the current PR head rather than a
literal hash: this baseline travels on PR #100, so every documentation commit
advances that head. The live PR record is authoritative for the exact hash and
Checks; predecessor evidence remains non-transferable.

| PR | Scope | Exact-head Checks | Review state | Next safe action |
|---:|---|---|---|---|
| [#113](https://github.com/ContextualWisdomLab/keyverse/pull/113) | SCIM `PATCH active=false` shared operation lock | PENDING: hosted Checks queued | review required | Obtain independent review and terminal exact-head Checks, then let protected automation merge; do not treat local GREEN as protected-main evidence. |
| [#112](https://github.com/ContextualWisdomLab/keyverse/pull/112) | Resync account-unification lockfile | PASS | review required | Obtain independent review, then let protected automation re-check and merge. |
| [#111](https://github.com/ContextualWisdomLab/keyverse/pull/111) | CodeQL init 4.37.7 | FAIL: account tests, CodeQL, Strix | review required | Keep coupled with #110; revalidate after lockfile and action-version coupling is resolved. |
| [#110](https://github.com/ContextualWisdomLab/keyverse/pull/110) | CodeQL analyze 4.37.7 | FAIL: account tests, CodeQL | review required | Treat as the companion of #111; do not merge the action pair independently. |
| [#109](https://github.com/ContextualWisdomLab/keyverse/pull/109) | `typing-inspection` update | FAIL: account tests | review required | Re-check after #112; the observed failure is the stale locked dependency graph. |
| [#108](https://github.com/ContextualWisdomLab/keyverse/pull/108) | Ruff update | FAIL: account tests | review required | Re-check after #112; do not rerun unchanged checks. |
| [#107](https://github.com/ContextualWisdomLab/keyverse/pull/107) | Uvicorn update | FAIL: account tests | review required | Re-check after #112; do not rerun unchanged checks. |
| [#106](https://github.com/ContextualWisdomLab/keyverse/pull/106) | `setup-uv` update | FAIL: account tests | review required | Re-check after #112; do not rerun unchanged checks. |
| [#105](https://github.com/ContextualWisdomLab/keyverse/pull/105) | `harden-runner` update | FAIL: account tests | changes requested | Fix the locked dependency gate first, then obtain a new exact-head review. |
| [#104](https://github.com/ContextualWisdomLab/keyverse/pull/104) | ADR and buyer README expansion | FAIL: account tests | draft | Keep draft until scope and exact-main evidence are ready. |
| [#103](https://github.com/ContextualWisdomLab/keyverse/pull/103) | Hierarchical authorization, login helper, PATs | FAIL: Strix, MEDIUM IDOR report | changes requested | Validate the report against the operator-admin trust boundary, retain fail-closed treatment, and obtain a fresh exact-head review/check run before any merge claim. |
| [#101](https://github.com/ContextualWisdomLab/keyverse/pull/101) | Atomic coupled Python dependency updates | PASS | changes requested | Obtain fresh independent review; this is the policy companion to the lockfile gap. |
| [#100](https://github.com/ContextualWisdomLab/keyverse/pull/100) | `lineageweave-web` account-derived claims | PENDING on current PR head (exact live record) | changes requested; fresh review requested | Do not transfer the predecessor PASS; verify the live exact-head Checks and independent review, without self-approval. |
| [#83](https://github.com/ContextualWisdomLab/keyverse/pull/83) | Remove runtime application RPs from portable realm | PASS | changes requested | Reconfirm current-head approval and latest-pusher rule before protected merge. |

### Check failure root causes observed

- The representative account-test failure on Dependabot PRs stopped at
  `uv sync --locked`: the checked-in lockfile needed updating. This is a
  dependency-graph consistency failure, not evidence that the product tests
  failed after installation.
- PRs #110 and #111 update the two coupled CodeQL actions separately. The
  #111 run loaded configuration for 4.37.7 while running 4.37.6. They must be
  evaluated as one compatible pair, with fresh exact-head Checks after the
  lockfile queue is clear.
- The historical #103 Strix run is not currently retrievable through the
  Actions API. That is missing evidence, not a pass and not permission to
  bypass the security gate.

## Open Issue inventory

| Issue | Product signal | Classification | Required outcome |
|---:|---|---|---|
| [#102](https://github.com/ContextualWisdomLab/keyverse/issues/102) | Hierarchical authorization plane, login helper, PATs | `active-PR` | Security-review the proposed authority model and prove fail-closed token/tenant/resource behavior. |
| [#99](https://github.com/ContextualWisdomLab/keyverse/issues/99) | Orphaned federation and product-loop workflow identities | `gap-not-claimed` | Disable only through the owning protected workflow/organization path and record live identity evidence. |
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

### G4 — SCIM deactivation concurrency boundary

**State:** `active-PR` with an explicit protected-main limitation
**Root cause:** protected `main` did not cover `PATCH active=false` with the
shared cross-process lock used by merge and full-replacement `PUT`.

**Acceptance:** PR #113 adds the shared lock, root-level SCIM `503`
lock-timeout mapping, a real concurrent deactivation/merge regression, and reconciled
PRD/TRD/UML/Threat/Test/Operability/doctoring records. The protected-main gap
closes only after exact-head hosted Checks, independent review, protected merge,
and a refreshed baseline prove the change on main.

### G5 — Physical database and hot-partition evidence

**State:** `gap-not-claimed`
**Root cause:** the ERD defines logical tenant-qualified uniqueness and
two-word-or-longer snake_case names, but a production claim needs migration,
index, partition-key, skew, and recovery evidence from the owning database.

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

Interpretations and repository evidence are maintained separately in
[`docs/doctoring/product-technical-gap-baseline.md`](doctoring/product-technical-gap-baseline.md).
