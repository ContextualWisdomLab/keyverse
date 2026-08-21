# Keyverse product and technical gap baseline

**Evidence snapshot:** 2026-08-22 (Asia/Seoul)
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

## Live queue refresh — 2026-08-22T05:42:27+09:00

This section supersedes the older queue snapshots below for current-state
decisions. The protected `main` head is
`ce207dfd42975db61c82a5963e206fc1db14ac2b`. Counts are exact-head GitHub REST
check-runs; pending, queued, and failed results are never promoted to green.
The current exact-head review audit reports `REVIEW_REQUIRED` for every open
Keyverse PR. #112 has zero valid unresolved threads after its current review
disposition; no open PR has a formal approval that satisfies the protected
merge gate.

| PR | Exact head | Base | Checks | Safe disposition |
|---:|---|---|---|---|
| [#113](https://github.com/ContextualWisdomLab/keyverse/pull/113) | `9bd33ee0d00ef1874fd5efabac3462f678a256ed` | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | 22 success, 8 skipped | Await independent approval; no merge claim. |
| [#112](https://github.com/ContextualWisdomLab/keyverse/pull/112) | `ec34ac14fd38c9c7c463cddbd0ced04b4dfccafd` | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | 22 success, 8 skipped | Masked-secret finding fixed and current threads resolved; await independent approval. |
| [#103](https://github.com/ContextualWisdomLab/keyverse/pull/103) | `77b8f4ea9995329f1c55b916d110b460b4bc7649` | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | 22 success, 8 skipped | Await independent approval; no merge claim. |
| [#101](https://github.com/ContextualWisdomLab/keyverse/pull/101) | `50dd9c96cab5c230f775685e8baea939fba390dd` | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | 22 success, 8 skipped | Await independent approval; no merge claim. |
| [#100](https://github.com/ContextualWisdomLab/keyverse/pull/100) | `f4f85e953805146c20455a9934ccec8aa52d8eb4` | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | 14 queued, 2 pending, 7 skipped | Documentation head is current at observation time; hosted Checks are non-terminal and independent approval is absent. |
| [#83](https://github.com/ContextualWisdomLab/keyverse/pull/83) | `dd1ab7444a75342b42e3af013ccda6d1dbfb359d` | `ce207dfd42975db61c82a5963e206fc1db14ac2b` | 22 success, 8 skipped | Await independent approval; no merge claim. |

The #100 row records the source head observed immediately before this
documentation snapshot. The documentation-only commit carrying this table
creates a later #100 head, so its predecessor Checks and review evidence are
deliberately not treated as current merge evidence.

The current central control-plane queue is also not merge-ready: protected
`.github` main is `0156282022134484ea9d7541d5ba0730ba14fd96`. The OSV
cross-fork result-isolation root #1209 is at
`225c415179180606f9a935304f61b09dc3e5c084` with 19 successful, 24 skipped,
5 cancelled, 1 in-progress, and 7 queued Checks. The hourly OIDC caller repair
#1188 is at `2c05f05f5fbb923099e0e228d616ab9974dbd327` with 23 successful, 18
skipped, 1 cancelled, 1 queued, 3 neutral, and 2 pending
Checks. The combined security and scheduler root #1198 is at
`dbb3c8a131d708754d2879ec6475d8c45a4ff140` with 5 successful, 19 skipped,
3 cancelled, 16 queued, and 2 pending Checks; replay-guard repair #1166 is at
`e6c03f618d54497b98eaf96afa21724b19847bd2` with 17 successful, 26 skipped,
6 cancelled, 3 neutral, 1 in-progress, and 6 queued Checks; scheduler repair
#1203 was normally merged into the
#1198 feature branch at `4d3d24aa404959f5067735fec0558d5924ade590` from child
head `c627d4ae7a26222ed3d2ee1ded19e270930aa1f2`; review repair #1002 was then
normally merged into that same feature branch at `3016543f735bb24db760cfaa768e64f95f408473`;
OSV repair #1208 is closed without merge; and #1026 is at
`1be76989887ab772e3ce0d2e0c7f22d3ca98dd94` with 21 successful, 19 skipped,
2 cancelled, 1 in-progress, and 4 queued Checks. These are normal
source/hosted-gate or dependency-order problems, not D1–D5 emergency
deadlocks. The central heads can move again through normal scheduler restacks;
all listed evidence is observation-time only.

All queue statements below this section are historical snapshots. They do not
override the exact-head evidence above.

The organization ruleset `CWL Central required workflows` (`18156473`) is
active and requires two approving reviews, latest-push approval, resolved
threads, and required workflows. Its live `bypass_actors` list is empty. No
Keyverse PR therefore qualifies for an emergency bypass or a protected merge
until the normal review and hosted gates are satisfied.

PR #104 is now closed by squash merge at
`44c2adb18687f8df457bd4bafade551533cee5b9` (2026-08-21T16:24:25Z), with the
feature-base parent `31dd486cb97ca215da451151f618a954a07b0ea5`; protected
`main` remains unchanged. Its feature-base merge was outside ruleset
`18156473`, whose live ref condition is only `~DEFAULT_BRANCH`, so the merge
did not establish a default-branch protected approval. This is a governance
gap, not a force push or direct protected-branch push, and is retained here as
audit evidence rather than as normal protected-merge evidence.

The relevant central control-plane PRs are also not merge-ready: `.github`
#1153 (`ebda81f832261489289447778b0e0e7726f9741e`) has 26 successful, 3
neutral, 13 skipped, 1 failed, and 1 queued Check; #1203
(`94c09152a843db1a0d3a3463900ef4d30467f085`) has 27 successful, 3 neutral, 21
skipped, 2 failed, 2 cancelled, and 1 queued Check; #1198
(`d2490ad594bd2ab8cccd5ff9e0b6f2a3fa8e23d4`) has 27 successful, 3 neutral, 17
skipped, and 1 queued Check; #1189
(`5838e0ae10d5cfbd7d7d6766cb0197fad9ffd641`) has 25 successful, 3 neutral, 17
skipped, 1 failed, and 1 queued Check; and #1026
(`71c0cc890bd06a0ff97aa10267cb075b02c62f9e`) has 4 successful, 15 skipped, 1
cancelled, and 16 queued Checks. None has an exact-head formal approval. OSV #1158
(`6ea77b1c59265e6f708d71128fa726cf447d427b`) has one exact-head failure: both
base and head scans found vulnerable `pip==26.1.2` (`PYSEC-2026-3721`), which
is owned by the dependency root #1198 and must be revalidated after that root
normally merges. Their local verification does not substitute for protected
hosted evidence.

Fleet-lifecycle PR #1026 is now normally synchronized at
`71c0cc890bd06a0ff97aa10267cb075b02c62f9e`. Its local RED-to-GREEN repair
fails closed on partial workflow inventories; its hosted Checks remain queued
and the PR remains pending until #1198 and all current hosted gates settle.

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
`28b69f676e593333bc2ddf6cd492a4027355ea77`; the documentation commit that
updates this snapshot is intentionally not recursively named. The audit also
includes the current central `.github` coordination handoff for issue #99:
PR #1026 is normally updated to exact head
`8d141d51d5b891fda7e8638164f64d5f6fed5ea8` against base
`731af58e954901c4f1cc853231c592abb1eaf617`, with local central verification
complete but hosted Checks and independent approval still pending. The
organization-level `CWL Central required workflows` ruleset remains active,
now targets only `~DEFAULT_BRANCH`, and has no bypass actors; required workflow,
review, deletion, and non-fast-forward protections remain enabled. The live PR
record is authoritative for the exact hash and Checks; predecessor evidence
remains non-transferable.

At this snapshot, 15 PRs are open and none has a qualifying formal approval.
#112, #101, and #83 each have 23 successful and 8 skipped Checks with no
queued Check; #107 and #108 each have 22 successful, 1 queued, and 8 skipped
Checks; #104 has 22 successful, 1 queued, and 8 skipped Checks; #105, #106,
#109, #110, and #111 each have 21 successful, 1 queued, and 8 skipped Checks;
#115 and #113 each have 2 successful, 14 pending, and 7 skipped Checks; PR #103
has 14 queued and 7 skipped check runs, with Devin and CodeRabbit status
contexts pending; PR #100 has 14 queued and 6 skipped check runs, with Devin
and CodeRabbit status contexts pending. The exact rollup is
listed per PR below; pending and queued Checks remain unverified rather than
green.
There is no current terminal failure bucket in this inventory. Historical
terminal failures are recorded separately and are not current-head green
evidence.

### Post-snapshot exact-head delta

The live queue changed again after the snapshot recorded below. PR #115 is now
normally stacked on #112's exact branch head
`fix/account-unification-lock-20260819@f02acf93367a40dbfb23a73985017dca8d42ff39`.
Its earlier `account-unification-tests` failure was the inherited stale-lock
failure at `main@ce207dfd42975db61c82a5963e206fc1db14ac2b`, not a documentation
test failure; the failed job was rerun after the base transition and remains
unverified while queued. PR #112 remains a normal protected-merge candidate
with all terminal Checks successful, auto-merge armed, and no qualifying
approval. PRs #83 and #101 also have successful exact-head coverage evidence;
fresh current-head reviews were requested because their old OpenCode
`CHANGES_REQUESTED` verdicts were bound to predecessor heads. No approval or
merge is claimed for any of these states.

The current exact-head audit confirms PR #115 at
`e7ad4524712b18809d8c409371142071270b2ea0`, #113 at
`9bd33ee0d00ef1874fd5efabac3462f678a256ed`, #103 at
`77b8f4ea9995329f1c55b916d110b460b4bc7649`, and #100 at
`28b69f676e593333bc2ddf6cd492a4027355ea77`. #103's current Devin finding
about separate audit-failure compensation writes was fixed with an atomic
upsert/delete store operation and a RED-to-GREEN regression. #100's current
audience-only mapper observation was checked against the generic optional
profile contract and dispositioned without a source change; its dynamic
account-derived exception still requires all three claims. Both PRs remain
without formal approval and hosted gates are pending. This documentation
commit creates a later #100 head, so that resulting head requires a fresh
hosted recheck before any protected-merge claim.

### Post-fix exact-head delta — PR #100

Before this baseline refresh, PR #100 was at exact head
`44f0f7420d4b02d11c8f870bd0415aaa4a486b39` against base
`ce207dfd42975db61c82a5963e206fc1db14ac2b`, pushed through the normal feature
branch path. Its live Check run currently has 14 queued and 7 completed runs;
CodeRabbit is successful, Devin is pending, and no formal approval exists. This
is pending hosted evidence, not a merge claim, and no D1-D5 emergency deadlock
has been established.

The three current Devin observations were processed against this exact head:

- The admin-required `org`/`workspace` concern reproduced as an HTTP 400 on a
  rebuilt local Keycloak 26.3.2 Admin REST create. The profile now keeps the
  attributes scalar and administrator-managed but optional at initial creation;
  the no-attribute probe then succeeded and was deleted. Operator assignment
  and downstream fail-closed routing remain required.
- The live account-role mapper read-back omitted an empty
  `usermodel.clientRoleMapping.rolePrefix`; reconciliation now normalizes only
  that exact vendor default and keeps all other missing/changed configuration
  fail-closed.
- The local-only `cwl-idp/keycloak:local` bootstrap image observation was
  verified as the documented Compose build/dependency contract and required no
  source change.

Local exact-head evidence is 799 tests passed, 100% production statement and
branch coverage, 100% `validate_realm.py` statement and branch coverage, 100%
interrogate coverage, service/test Ruff success, Semgrep 151-rule success,
package build, Compose config, dependency, and diff checks. Hosted Checks and
independent protected review remain required.
This baseline commit creates a later documentation-only #100 head, so hosted
evidence must be refreshed against that later exact head.

### Live queue refresh — 2026-08-21T10:54:08Z

Immediately before this documentation refresh, the exact Keyverse queue was
rechecked from the GitHub REST API. Every current open PR had zero terminal
failed check-runs:

- #100 `40923074b1d7a395aa3d83c854a07fe3060af682`: 14 pending, 0 failed;
  CodeRabbit successful, Devin pending, no formal approval.
- #103 `77b8f4ea9995329f1c55b916d110b460b4bc7649`: 14 pending, 0 failed.
- #115 `e7ad4524712b18809d8c409371142071270b2ea0` and #113
  `9bd33ee0d00ef1874fd5efabac3462f678a256ed`: 2 pending each, 0 failed.
- #112, #108, #107, #101, and #83: 22 successful, 0 pending, 0 failed.
- #111, #110, #109, #106, #105, and #104: 21 successful, 1 pending,
  0 failed each.

The central lifecycle owner PR `.github#1026` is currently at exact head
`84b84aededaf25d88441121fd8c171a94e13eac9`, against
`731af58e954901c4f1cc853231c592abb1eaf617`; its live checks show 4 successes,
14 non-terminal results, and 12 skipped results, with no exact-head approval.
The oldest queued Keyverse workflow observed was created at 09:54 UTC. This
does not satisfy the six-hour/two-observation D2 threshold, and no D1, D3, D4,
or D5 evidence exists. No bypass, direct protected push, force push, fake
status, or self-approval was used.

This refresh itself is documentation-only and creates a later #100 head;
fresh hosted Checks and independent review must bind to that later SHA.

| PR | Scope | Exact-head Checks | Review state | Next safe action |
|---:|---|---|---|---|
| [#115](https://github.com/ContextualWisdomLab/keyverse/pull/115) | Proposed ADR/doctoring for MCP-compatible OAuth client authorization | PENDING: 2 successful, 14 pending, 7 skipped on `e7ad4524712b18809d8c409371142071270b2ea0` | review required | The token-audience, metadata-member, scope-array, and missing-reference findings are fixed; obtain independent ADR review and do not treat the design PR as runtime MCP evidence or begin implementation before the trust boundary is accepted. |
| [#113](https://github.com/ContextualWisdomLab/keyverse/pull/113) | SCIM `PATCH active=false` and `DELETE` shared operation lock, stacked on #112 lockfile refresh | PENDING: 2 successful, 14 pending, 7 skipped on `9bd33ee0d00ef1874fd5efabac3462f678a256ed` | review required | The valid SCIM PatchOp, deterministic-race, DELETE-lock, value-object coverage, and documentation fixes are complete; wait for fresh exact-head hosted Checks and independent review. |
| [#112](https://github.com/ContextualWisdomLab/keyverse/pull/112) | Resync account-unification lockfile | PASS: 23 successful, 8 skipped, 0 queued on `f02acf93367a40dbfb23a73985017dca8d42ff39` | review required | Obtain independent review, then let protected automation re-check and merge. |
| [#111](https://github.com/ContextualWisdomLab/keyverse/pull/111) | CodeQL init 4.37.7 | PENDING: 21 successful, 1 queued, 8 skipped on `032f730b0239d062cf9803525ba66c740e0b2d2e` | review required | The normal branch update merged #112's lockfile base into the CodeQL branch; resolve the queued Strix retry and remaining coverage Check, then obtain independent review. |
| [#110](https://github.com/ContextualWisdomLab/keyverse/pull/110) | CodeQL analyze 4.37.7, stacked on #112 lockfile refresh | PENDING: 21 successful, 1 queued, 8 skipped on updated head `c3e307fc3d4f6d98ec5a0514f35aa8038b2737b7` | review required | The normal branch update includes #112's lock-refresh base; wait for exact-head Checks and independent review. |
| [#109](https://github.com/ContextualWisdomLab/keyverse/pull/109) | `typing-inspection` update, stacked on #112 lockfile refresh | PENDING: 21 successful, 1 queued, 8 skipped on `7b726b16d38ce16d13d00c946b5c8bc0c406191f` | review required | The normal merge and local locked-install/full-suite verification are complete; wait for fresh hosted Checks and independent review. |
| [#108](https://github.com/ContextualWisdomLab/keyverse/pull/108) | Ruff update, stacked on #112 lockfile refresh | PENDING: 22 successful, 1 queued, 8 skipped on `538cead991a7c1bed32f2dcb5413b5fc56f53e93` | review required | The conflicting lockfile base was rebased cleanly onto #112; wait for remaining exact-head Checks and independent review. |
| [#107](https://github.com/ContextualWisdomLab/keyverse/pull/107) | Uvicorn update, stacked on #112 lockfile refresh | PENDING: 22 successful, 1 queued, 8 skipped on `53842560d397aa20309a6b16aceb560540611686` | review required | The conflicting lockfile base was rebased cleanly onto #112; wait for the remaining exact-head Check and independent review. |
| [#106](https://github.com/ContextualWisdomLab/keyverse/pull/106) | `setup-uv` update, stacked on #112 lockfile refresh | PENDING: 21 successful, 1 queued, 8 skipped on updated head `e7fafd4192cc3cc344b8f8e536bc0495afaa739f` | review required | The normal branch update includes #112's lockfile base; wait for exact-head Checks and independent review. |
| [#105](https://github.com/ContextualWisdomLab/keyverse/pull/105) | `harden-runner` update, stacked on #112 lockfile refresh | PENDING: 21 successful, 1 queued, 8 skipped on updated head `77f83dfb2c4611345c0d48f92fceaa6195b4630c` | changes requested | The normal branch update includes #112's lockfile base; obtain current-head independent review. |
| [#104](https://github.com/ContextualWisdomLab/keyverse/pull/104) | ADR and buyer README expansion, stacked on #112 | PENDING: 22 successful, 1 queued, 8 skipped on `7da9d43087d5647fefb946eb154ee1e5c10c576d` | review required | Base remains `fix/account-unification-lock-20260819`; obtain independent review and terminal stacked-head Checks. |
| [#103](https://github.com/ContextualWisdomLab/keyverse/pull/103) | Hierarchical authorization, login helper, PATs | PENDING: 14 queued, 7 skipped; Devin and CodeRabbit pending on `77b8f4ea9995329f1c55b916d110b460b4bc7649` | changes requested | Menu inheritance metadata, tenant-scoped grant GET/DELETE, and atomic forward/compensation token rotation storage are fixed with RED-to-GREEN tests; wait for fresh hosted security Checks and current-head independent review before any merge claim. |
| [#101](https://github.com/ContextualWisdomLab/keyverse/pull/101) | Atomic coupled Python dependency updates | PASS: 23 successful, 8 skipped, 0 queued on `50dd9c96cab5c230f775685e8baea939fba390dd` | changes requested | Obtain fresh independent review; this is the policy companion to the lockfile gap. |
| [#100](https://github.com/ContextualWisdomLab/keyverse/pull/100) | `lineageweave-web` account-derived claims plus default validator-path coverage | PENDING: 14 queued, 6 skipped; Devin and CodeRabbit pending on observed head `28b69f676e593333bc2ddf6cd492a4027355ea77` | changes requested | The current audience-only observation was dispositioned against the generic optional profile; the reserved dynamic account-derived profile still requires all three claims, and the prior static-claim mismatch is fixed by RED-to-GREEN coverage. This docs refresh creates a later head, then fresh exact-head Checks and independent review are required without self-approval. |
| [#83](https://github.com/ContextualWisdomLab/keyverse/pull/83) | Remove runtime application RPs from portable realm | PASS: 23 successful, 8 skipped, 0 queued on `dd1ab7444a75342b42e3af013ccda6d1dbfb359d` | changes requested | Reconfirm current-head approval and latest-pusher rule before protected merge. |

### Live queue refresh — 2026-08-21T11:22:53Z

This later audit supersedes the older snapshot rows above for current-state
decisions. PR #115 normally squash-merged into its stacked base at
`2026-08-21T11:15:50Z`, producing merge commit
`ec91eb3af436ac7fa5e682d31d78cd5b01782d01` from source head
`e7ad4524712b18809d8c409371142071270b2ea0`. It was not a forced merge or a
protected-main merge. The detached merge-result verification passed the root
documentation contract (5 tests), the account-unification suite (742 tests),
100% statement/branch coverage (2734/738), interrogate 100%, Ruff, and
`git diff --check`. Hosted delayed runs remain queued and are not reported as
success.

The normal stacked merge advanced the #112 root branch to exact successor head
`ec91eb3af436ac7fa5e682d31d78cd5b01782d01` against protected main
`ce207dfd42975db61c82a5963e206fc1db14ac2b`. Its predecessor `f02acf9` Checks
and review evidence are invalid. The successor currently has 14 queued and 7
skipped Checks, no terminal failure, auto-merge armed, and zero exact-head
formal approvals. Fresh independent review and hosted verification were
requested for the combined lockfile plus #115 documentation diff.

At this refresh, #100 and #103 each have 14 queued and 7 skipped Checks with
no terminal failure; #113 has 18 successful, 1 in-progress, 1 queued, and 7
skipped; #101 and #83 each have 22 successful and 8 skipped Checks; and
#107/#108 each have 22 successful and 8 skipped Checks on their downstream
stack base. All inspected merge candidates have zero exact-head formal
approvals. Central `.github#1026` has 4 successful, 16 queued, and 13 skipped
Checks with no exact-head approval. Queued or in-progress results remain
unverified hosted evidence. No D1-D5 emergency deadlock classification is
made; no bypass, direct protected push, force push, fake status, or
self-approval occurred.

### Live queue refresh — 2026-08-21T11:58:44Z

This refresh is the current read-only GitHub inventory for Keyverse and
supersedes earlier queue rows for merge decisions. The protected-main base is
`ce207dfd42975db61c82a5963e206fc1db14ac2b`; the local feature worktree used for
this documentation update was clean and remote branch
`codex/per-account-rp-claims` was at `a92fdcb038e26788eea17d8b77dbae60982b3e04`
before this commit. Fourteen Keyverse PRs are open. The numeric Check columns
count only terminal `success`/`skipped` and non-terminal status results;
blank-provider contexts such as CodeRabbit or Devin are not promoted to
success. No current open PR had a terminal failed Check in this observation.

| PR | Base | Exact head | Checks (`success / skipped / pending`) | Live gate |
|---:|---|---|---:|---|
| [#113](https://github.com/ContextualWisdomLab/keyverse/pull/113) | `main` | `9bd33ee0d00ef1874fd5efabac3462f678a256ed` | `19 / 8 / 1` | protected, review required; `coverage-source-tree` pending |
| [#112](https://github.com/ContextualWisdomLab/keyverse/pull/112) | `main` | `d2f48232fff1505c3274fe4296ca21cece5db102` | `0 / 7 / 14` | protected, review required; auto-merge armed |
| [#111](https://github.com/ContextualWisdomLab/keyverse/pull/111) | `fix/account-unification-lock-20260819` | `032f730b0239d062cf9803525ba66c740e0b2d2e` | `22 / 8 / 0` | downstream stack; no qualifying formal approval |
| [#110](https://github.com/ContextualWisdomLab/keyverse/pull/110) | `fix/account-unification-lock-20260819` | `c3e307fc3d4f6d98ec5a0514f35aa8038b2737b7` | `21 / 8 / 1` | downstream stack; one pending Check |
| [#109](https://github.com/ContextualWisdomLab/keyverse/pull/109) | `fix/account-unification-lock-20260819` | `7b726b16d38ce16d13d00c946b5c8bc0c406191f` | `21 / 8 / 1` | downstream stack; one pending Check |
| [#108](https://github.com/ContextualWisdomLab/keyverse/pull/108) | `fix/account-unification-lock-20260819` | `538cead991a7c1bed32f2dcb5413b5fc56f53e93` | `22 / 8 / 0` | downstream stack; no qualifying formal approval |
| [#107](https://github.com/ContextualWisdomLab/keyverse/pull/107) | `fix/account-unification-lock-20260819` | `53842560d397aa20309a6b16aceb560540611686` | `22 / 8 / 0` | downstream stack; no qualifying formal approval |
| [#106](https://github.com/ContextualWisdomLab/keyverse/pull/106) | `fix/account-unification-lock-20260819` | `e7fafd4192cc3cc344b8f8e536bc0495afaa739f` | `21 / 8 / 1` | downstream stack; one pending Check |
| [#105](https://github.com/ContextualWisdomLab/keyverse/pull/105) | `fix/account-unification-lock-20260819` | `77f83dfb2c4611345c0d48f92fceaa6195b4630c` | `21 / 8 / 1` | downstream stack; current review must be re-established |
| [#104](https://github.com/ContextualWisdomLab/keyverse/pull/104) | `fix/account-unification-lock-20260819` | `7da9d43087d5647fefb946eb154ee1e5c10c576d` | `21 / 8 / 1` | downstream stack; `DIRTY`, no merge |
| [#103](https://github.com/ContextualWisdomLab/keyverse/pull/103) | `main` | `77b8f4ea9995329f1c55b916d110b460b4bc7649` | `0 / 7 / 14` | protected, review required; auto-merge armed |
| [#101](https://github.com/ContextualWisdomLab/keyverse/pull/101) | `main` | `50dd9c96cab5c230f775685e8baea939fba390dd` | `22 / 8 / 0` | protected, review required; auto-merge armed |
| [#100](https://github.com/ContextualWisdomLab/keyverse/pull/100) | `main` | `a92fdcb038e26788eea17d8b77dbae60982b3e04` | `0 / 7 / 14` | protected, review required; auto-merge armed |
| [#83](https://github.com/ContextualWisdomLab/keyverse/pull/83) | `main` | `dd1ab7444a75342b42e3af013ccda6d1dbfb359d` | `22 / 8 / 0` | protected, review required; auto-merge armed |

The central lifecycle owner [`.github#1026`](https://github.com/ContextualWisdomLab/.github/pull/1026)
was independently observed at exact head
`84b84aededaf25d88441121fd8c171a94e13eac9`, base
`731af58e954901c4f1cc853231c592abb1eaf617`, with `4 / 13 / 16`
`success / skipped / pending`, zero failed Checks, and no formal approval.
The queue contains no D1, D3, D4, or D5 evidence; the newly queued runs are
also below the D2 six-hour and two-observation threshold. Stale
infrastructure/predecessor `CHANGES_REQUESTED` reviews were dismissed with
audit reasons, not converted into approvals. No bypass, direct protected
push, force push, fake status, or self-approval was used.

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
- PR #103's current exact head `77b8f4ea9995329f1c55b916d110b460b4bc7649`
  adds RED-to-GREEN regressions for percent-encoded discovery markers,
  inactive and expired token rotation, invalid token rotation settings, KV/audit
  lifecycle failures, direct router embedding, tenant isolation, software-unit
  ABAC, runtime authentication, untrusted public issuers, exact-org menu
  inheritance metadata, tenant-scoped grant administration, and atomic token
  rotation forward and audit-compensation storage. Local
  focused/full tests, Ruff, Interrogate, package/build, deployment, realm,
  Compose, Semgrep, and 100% application statement/branch coverage pass; its
  required hosted Checks are still pending or queued, so no hosted security or
  independent approval success is claimed.

## Open Issue inventory

| Issue | Product signal | Classification | Required outcome |
|---:|---|---|---|
| [#114](https://github.com/ContextualWisdomLab/keyverse/issues/114) | MCP-compatible OAuth client authorization for headless agents | `active-issue` / design merged in stacked PR #115 | PR #115's ADR-0013 and doctoring design merged normally into the #112 stack at `ec91eb3`; runtime implementation and real browser/client evidence remain unclaimed. Evaluate RFC 8628 only for clients that cannot use a callback. |
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

**Current action:** PR #115 merged ADR-0013 and its doctoring record into the
#112 stack. The design keeps Keycloak as the authorization server, assigns RFC 9728 protected-
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
