# PR governance ownership after local steward retirement

**Date:** 2026-10-04
**Scope:** private PR103 + pinned-main reconciliation; no protected promotion

## Root cause and retained owner

Pinned source `7d9151cd2da260e118020c938c7358e2ee75d541` includes
#140's deletion of `.github/workflows/hourly-pr-steward.yml`, but retains five
tests that open that deleted file. The predecessor composition tree
`9a4f87eafce569470cc1e97d32f41dddf5c96781` executed 888 cases:
883 passed, five steward `FileNotFoundError` failures, zero errors/skips.
That actual failed run remains unchanged in the predecessor packet.

This successor reuses only the inspected source-governance subset of reviewed
PR #143 source `2728b04493f17eb5256533448875398fb1325056`: retired-test deletion,
75-line ownership regression, central-owner architecture clarification,
operating-guide retirement/publication-race correction, and changelog wording.
The existing source record informs this bounded interpretation; its remote
inventory and historical execution assertions are not new observations here.
No runner-routing, checkout-credential, CI-selector, or workflow delta is adopted.

## Interpretation and regression boundary

- **Repository policy:** central `pr-review-merge-scheduler.yml` owns PR
  maintenance; local product authoring must not become another merge owner.
- **Vendor contract:** reusable workflows are called at job level and declare
  `workflow_call` (GitHub, n.d.-b). Definition existence is not execution evidence.
  Protected branch review/status checks remain separate gates (GitHub, n.d.-a).
- **Measured RED:** before source correction, the three replacement ownership
  tests failed on the surviving obsolete test, missing central owner, and
  publication-race dependency on the retired steward; zero errors.
- **Measured GREEN:** the five reviewed ownership cases passed after correction,
  including copied otherwise-valid documents with the obsolete active-owner
  sentence restored independently to each. Positive documents pass before each
  mutation. These are bounded static oracles, not general contradiction detection.
- **Protection boundary:** local tests do not replace hosted exact-head Checks,
  independent approval, unresolved-thread disposition, or central dispatch.
- **Non-goals:** no production Python, credential, workflow, review gate,
  passwordless policy, SCIM implementation, release version or deployment changes.

## Maturity reconciliation and evidence grammar

The inspected pinned-main `scim.py` implements shared user-operation locking
for `PUT`, supported `PATCH active=false`, and soft `DELETE`, with retryable
SCIM `503` on lock contention. `PRD`, `UML`, `OPERABILITY`, and `TRACEABILITY`
now distinguish that integrated source from deployed acceptance. PR #103's
hierarchical authorization, SSO combinations, start-login helper, and PATs
remain unmerged candidate source; FR011–016 specifications, Orgmetra employment
SoR, issuer/token validation, tenant/resource constraints and downstream RP PEP
boundaries are preserved. Accepted ADR design status is not runtime promotion.
The dated gap-baseline source/table is unchanged rather than retrospectively
rewriting its historical inventory.

The new maturity tests use exact capability headings, explicitly labelled,
blank-line-delimited status paragraphs and unique table rows. Ordinary decimal
versions and line wrapping pass; absent status/source-only/readiness markers,
methods moved out of the authoritative paragraph, current candidate bullets,
wrong row maturity, stale SCIM promotion conditions and same-line/wrapped
contradictory claims fail. This declared grammar is not arbitrary language
interpretation. Before prose correction, the actual-document cohort recorded
five failures and 53 passes, zero errors/skips. A separate probe first accepts
otherwise-valid fixtures then directly restores 16 unsafe source/deployment
sentences: all 16 fail assertions, zero errors/skips. The corrected-document
cohort passes all 58 cases. These receipts are private local evidence only.

## Separate whitespace repair

ADR-0010–0012's three inherited `**Status:** Accepted` hard-break lines caused
`git diff --check` exit 2 in the predecessor. Only their two trailing spaces are
replaced with explicit `<br>`; accepted design meaning and rendered line break
remain. No global whitespace exemption or design-status change is introduced.

## References — APA 7th

GitHub. (n.d.-a). *About protected branches*. GitHub Docs. Retrieved October 4,
2026, from
https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

GitHub. (n.d.-b). *Reuse workflows*. GitHub Docs. Retrieved October 4, 2026, from
https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows

ContextualWisdomLab. (2026). *Remove stale hourly-pr-steward test left behind by
#140* (Keyverse PR #143; local reviewed source snapshot
`2728b04493f17eb5256533448875398fb1325056`; inspected Git objects, not a new
remote read). https://github.com/ContextualWisdomLab/keyverse/pull/143

Both GitHub Docs pages were actually returned by `web.run` on October 4,
2026, after `web_extract` timed out on both. The initial draft's premature
retrieval statement was not evidence; only the subsequent returned pages
support this record. The PR143 reference is local-source provenance, not an
asserted fresh web retrieval. No central scheduler dispatch or hosted Check
was observed.
