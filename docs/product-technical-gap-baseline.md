# Keyverse product and technical gap baseline

**Evidence snapshot:** 2026-08-21T14:24:31Z (UTC)
**Repository:** `ContextualWisdomLab/keyverse`
**Protected-main head observed:** `ce207dfd42975db61c82a5963e206fc1db14ac2b`
**Status:** live inventory and gap register; not a release acceptance record

This baseline joins the product, architecture, ADR, standards, operations,
and exact-head GitHub evidence into one executable backlog. It distinguishes
protected-main evidence from open-PR work, accepted contracts, and claims that
remain intentionally unverified.

## Product and authority boundary

Keyverse is a standalone and embeddable identity control plane for CWL, Naruon,
and sibling products. It owns passwordless-first Keycloak policy, federation
and directory preflight/reconciliation, account unification, SCIM lifecycle,
relying-party desired state, audit, and safe deployment operations.

Downstream applications own token signature/issuer/audience validation,
tenant/resource/purpose ABAC, and bounded RBAC. A Keycloak mapper receipt is
issuer-side configuration evidence, never proof that a relying party accepts a
token or enforces authorization.

## Evidence vocabulary

| Classification | Meaning |
|---|---|
| `implemented-main` | Source and representative tests are on protected `main`. |
| `active-PR` | Work exists only in an open PR and is not released evidence. |
| `active-issue` | An open issue records a product or operational gap. |
| `accepted-contract` | An ADR or standard defines policy; runtime acceptance may still be absent. |
| `gap-not-claimed` | The repository makes no success claim until stronger evidence exists. |

Queued, cancelled, skipped-required, stale, predecessor-head, and
rate-limited checks are not successful evidence. Formal approval must bind to
the exact current head and satisfy the latest-pusher and independent-review
rules.

## Capability and buyer acceptance map

| Capability | Current maturity | Buyer-visible boundary |
|---|---|---|
| Passwordless local identity | `implemented-main` | Realm validators and tests protect WebAuthn/passwordless policy; live login remains separate evidence. |
| Federation and LDAP preflight | `implemented-main` | Validators are side-effect-free; external bind/discovery and apply remain separate. |
| Account merge and SCIM full replacement | `implemented-main` | Verified identity matching, tombstones, audit, and shared merge/PUT locking are covered on main. |
| SCIM `PATCH active=false` lock parity | `active-PR` | PR #113 is not protected-main evidence until its current head passes all gates and merges. |
| Closed RP mapper profile | `implemented-main` / `accepted-contract` | Canonical `role`, `org`, and `workspace` claims remain closed; consumers must prove their own authorization. |
| Real login and token acceptance | `gap-not-claimed` | No live controlled passwordless browser flow, token exchange, downstream ABAC/RBAC, or revocation acceptance is claimed. |
| Standalone Compose/Helm operation | `implemented-main` / `gap-not-claimed` | Repository validators exist; deployment secret/configuration, rollback, and immutable artifact evidence remain required. |
| Product loop and protected merge | `active-PR` | The scheduler and review path must bind every decision to a current exact head. |
| Release artifact acceptance | `gap-not-claimed` | Version, immutable image digest, SBOM/provenance, rollback, and exact-main regression are still release gates. |

## Current exact-head PR inventory

This table was queried from the live GitHub state at the snapshot time. Counts
exclude informational CodeRabbit/Devin contexts and count only CheckRun
success, skipped, or non-terminal results.

| PR | Scope | Base | Exact head | Checks | Gate / next safe action |
|---:|---|---|---|---|---|
| [#113](https://github.com/ContextualWisdomLab/keyverse/pull/113) | SCIM deactivation shared lock | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | `9bd33ee0d00ef1874fd5efabac3462f678a256ed` | 21 success / 8 skipped / 1 pending | `REVIEW_REQUIRED`; obtain exact-head independent approval and finish the pending review gate. |
| [#112](https://github.com/ContextualWisdomLab/keyverse/pull/112) | Account-unification lockfile and stacked contract updates | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | `31dd486cb97ca215da451151f618a954a07b0ea5` | 0 success / 7 skipped / 14 pending | `REVIEW_REQUIRED`; local evidence is complete, but hosted Checks and independent approval are pending. |
| [#104](https://github.com/ContextualWisdomLab/keyverse/pull/104) | ADR 0001–0007 and operator README expansion | `31dd486cb97ca215da451151f618a954a07b0ea5` | `c623a3d8df6e0f6da0e9623b23e3178e0f0296f0` | 0 success / 0 skipped / 4 pending | Restacked normally; wait for fresh Checks and independent review before merging into the #112 stack. |
| [#103](https://github.com/ContextualWisdomLab/keyverse/pull/103) | Hierarchical authorization, login helper, and PATs | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | `77b8f4ea9995329f1c55b916d110b460b4bc7649` | 20 success / 8 skipped / 1 pending | `REVIEW_REQUIRED`; retain fail-closed security boundary and obtain current approval. |
| [#101](https://github.com/ContextualWisdomLab/keyverse/pull/101) | Coupled Python dependency updates | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | `50dd9c96cab5c230f775685e8baea939fba390dd` | 22 success / 8 skipped / 0 pending | `REVIEW_REQUIRED`; revalidate against the final lockfile stack and obtain approval. |
| [#100](https://github.com/ContextualWisdomLab/keyverse/pull/100) | LineageWeave account-derived RP profile | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | `ede8075f82bb082b7d992b824992bf44792f744e` | 18 success / 7 skipped / 2 pending | `REVIEW_REQUIRED`; downstream issuer/audience/tenant acceptance remains unclaimed. |
| [#83](https://github.com/ContextualWisdomLab/keyverse/pull/83) | Remove runtime application RPs from portable realm | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | `dd1ab7444a75342b42e3af013ccda6d1dbfb359d` | 22 success / 8 skipped / 0 pending | `REVIEW_REQUIRED`; confirm exact-head approval and latest-pusher policy before merge. |

The central coordination PR [`.github#1203`](https://github.com/ContextualWisdomLab/.github/pull/1203)
is open at exact head `babb411e5132f67a665e302eb492da69f7d91afb` against
`731af58e954901c4f1cc853231c592abb1eaf617`. Its `scan-pr-queue` run
`32487969901` was cancelled by the normal concurrency scheduler; successor run
`32488287515` is queued. This is not a source failure or D1–D5 emergency
evidence, so no bypass or guarded force merge is allowed.

This baseline is itself carried by #104. The table records that PR at the
pre-baseline snapshot head `c623a3d8df6e0f6da0e9623b23e3178e0f0296f0`; adding
this baseline advanced it normally to successor `8077aa46e120ea5977464f2e611d44ab44bab695`.
The successor's hosted Checks and review state must be read from the live PR,
and neither snapshot is protected-main evidence.

## Open issue inventory

| Issue | Signal | Classification | Required outcome |
|---:|---|---|---|
| [#114](https://github.com/ContextualWisdomLab/keyverse/issues/114) | MCP-compatible OAuth authorization for headless agents | `active-issue` | Independently review the design, then prove a real resource-bound client flow before runtime implementation. |
| [#102](https://github.com/ContextualWisdomLab/keyverse/issues/102) | Hierarchical authorization plane and PATs | `active-PR` | Prove tenant/resource fail-closed behavior and current-head security review. |
| [#99](https://github.com/ContextualWisdomLab/keyverse/issues/99) | Orphaned federation and product-loop identities | `active-issue` | Preserve the registry recurrence detector and central coordination evidence. |
| [#71](https://github.com/ContextualWisdomLab/keyverse/issues/71) | Remove runtime application RPs from portable import | `active-PR` | Merge #83 only after exact protected evidence. |
| [#2](https://github.com/ContextualWisdomLab/keyverse/issues/2) | Central IdP and external-IdP federation | `accepted-contract` | Complete approved-environment acceptance without weakening preflight boundaries. |

## Buyer-visible gap order

### G0 — Protected queue convergence

The repository must distinguish current, reviewed, passing artifacts from stale
or coupled proposals. The loop is inventory, review disposition, focused fix,
exact-head local and hosted checks, independent approval, protected merge, merge
SHA verification, and re-listing. Never self-approve, force-push, admin-merge,
publish fake status, or reuse predecessor evidence.

### G1 — Controlled real login and authorization acceptance

In an approved environment, prove discovery/issuer, JWKS signature and allowed
algorithm, authorization-code + PKCE `S256`, passwordless browser login, token
`iss`/`sub`/`aud`/time claims, logout, tenant/resource ABAC, role/scope RBAC,
cross-tenant denial, and verifier-unavailable fail-closed behavior. An
unavailable issuer stays `unavailable`; it is never replaced with a synthetic
success.

### G2 — Downstream tenant semantics

For `lineageweave-web`, `org` is one opaque external tenant key and `workspace`
is one child namespace. Ambiguous or missing membership denies before ABAC/RBAC;
membership changes require a new token or session. Generic tenant claims must
not be added to the closed mapper profile.

### G3 — SCIM concurrency and database evidence

After #113, prove real concurrent PATCH/merge behavior on protected main. For
production storage, add PostgreSQL migration/rollback, tenant-qualified
constraints, concentrated-tenant skew measurements, partition/index decisions,
backup/restore, and recovery evidence. Local SQLite tests are not that proof.

### G4 — MCP resource authorization

The design-only ADR requires Keycloak authorization code + PKCE, exact redirects,
RFC 8707 resource binding, RFC 9728 protected-resource metadata, RFC 9207
callback issuer comparison, RFC 9068 JWT validation, revocation, and negative
evidence. Runtime MCP acceptance remains `gap-not-claimed`.

### G5 — Release and module acceptance

On exact protected main, complete regression and controlled deployment
acceptance, publish immutable image digest plus SBOM/provenance, and prove
rollback. A green feature PR is not a release.

## Loop and design boundary

The hourly PR steward may advance only trusted same-repository PRs with exact
head, independent approval, and required Checks. The hourly product loop may
create at most one bounded draft product-gap PR only after the open queue is
empty and protected-main evidence is healthy. GitHub review/check waiting is not
a reason to stop independent review, documentation, or test design, but queued
results are never promoted to success.

This repository has no current frontend change in this baseline. Therefore no
Figma file or Storybook inventory is claimed. If a future buyer gap changes a
web surface, its ADR must record the Figma File ID, design tokens, reusable
components, Storybook scene/edge events, and accessibility/interaction/
performance/responsive/form/navigation/chart acceptance before implementation
is claimed.

## APA 7th references

- OpenID Foundation. (2014). *OpenID Connect Core 1.0*. https://openid.net/specs/openid-connect-core-1_0-18.html
- Internet Engineering Task Force. (2020). *JSON Web Token best current practices* (RFC 8725). https://www.rfc-editor.org/rfc/rfc8725.html
- Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current practice for OAuth 2.0 security* (RFC 9700). https://www.rfc-editor.org/rfc/rfc9700.html
- Internet Engineering Task Force. (2018). *OAuth 2.0 authorization server metadata* (RFC 8414). https://doi.org/10.17487/RFC8414
- Internet Engineering Task Force. (2020). *Resource indicators for OAuth 2.0* (RFC 8707). https://doi.org/10.17487/RFC8707
- Internet Engineering Task Force. (2025). *OAuth 2.0 protected resource metadata* (RFC 9728). https://doi.org/10.17487/RFC9728
- Model Context Protocol. (2026, July 28). *Authorization*. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

Interpretations and evidence boundaries are maintained in
[`docs/doctoring/product-technical-gap-baseline.md`](doctoring/product-technical-gap-baseline.md).
