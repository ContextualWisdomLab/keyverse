# PR governance ownership after local steward retirement

**Date:** 2026-10-03
**Scope:** local verification of existing PR #143/#154 remediation; not protected promotion

## Root cause and retained owner

Protected source `7d9151cd2da260e118020c938c7358e2ee75d541` includes
#140's deletion of `.github/workflows/hourly-pr-steward.yml`, but retains five
tests that open that deleted file. The complete local account-unification
suite reproduced five `FileNotFoundError` failures before any repair.

PR #154 at `85deb471a2e5de412e0f378eadd537750bb8476c` removes the obsolete
module. PR #143 at `dc2ca97ae7a33d4660d0179dd6050b57e9faa076` additionally
updates the operating guide. This local candidate reuses #143's two-path
repair and adds ownership regressions, architecture clarification, and this
record; it does not create another PR or adopt either remote branch's authority.
The operator wording is narrowed: observing central workflow source does not
prove its dispatch or effective protection on Keyverse.

## Interpretation and regression boundary

- **Repository policy:** central `pr-review-merge-scheduler.yml` owns PR
  maintenance; local product authoring must not become another merge owner.
- **Vendor contract:** reusable workflows are called at job level and use
  `workflow_call`. A reusable definition's existence is not execution evidence.
- **Protection boundary:** local tests do not replace required hosted Checks,
  independent current-head review, unresolved-thread disposition, or protection.
- **Measured RED:** both new ownership tests failed before the repair: the
  retired test remained and architecture did not name the central owner.
- **Measured GREEN:** the replacement tests pass after the repair. They check
  that the retired workflow/test stays absent, the local product workflow stays
  present, and current operating/architecture prose names central ownership.
- **Harness correction:** a case-sensitive `exact-head` assertion rejected
  sentence-initial `Exact-head`; only the assertion was made case-insensitive.
- **Review correction:** independent review rejected the initial candidate
  because publication-race guidance still depended on a subsequent hourly
  steward. A third test reproduced that contradiction before prose was changed
  to the normal protected PR path under central governance. The replacement
  makes no claim that central dispatch has executed.
- **Hosted review sensitivity correction (2026-10-04):** CodeRabbit noted
  that central-owner wording could coexist with the former statement that the
  hourly PR steward advances trusted PRs. Two copied-document controls first
  passed unchanged guidance, then restored that contradiction; both initially
  failed because the contract did not reject it. The contract now rejects the
  exact obsolete active-owner statement in both documents while preserving
  historical retirement references. These controls do not claim general
  natural-language contradiction detection or central execution evidence.
- **Non-goals:** no production Python, credential, workflow, review gate,
  passwordless policy, SCIM contract, or release version is changed. This is
  static ownership and local regression evidence, not live login, Keycloak,
  PostgreSQL, or central scheduler acceptance.

## Inventory and product-priority decision

Read-only GitHub inventory on 2026-10-03 returned 29 distinct open PRs and
11 distinct issues (the Issues API also returns PRs, which were excluded).
PRD-FR-001 through PRD-FR-010 and gap G0 retain passwordless, verified-email,
side-effect-free preflight, exact reconciliation, and protected queue rules.
The baseline's August inventory is historical, not today's queue.

The existing CI repair takes priority over opening a new product-gap proposal.
Key-vault, authorization, consumer subject/signer trust, and immutable release
requests (#152, #102/#103, #155, #156, #158, #160) remain separate unresolved
owner scopes; this repair does not claim to satisfy them. Likewise issue #131's
orchestrator routing work remains on its existing candidate paths.

GitHub CLI authentication failed. Public API/browser reads and normal git fetch
worked without changing credentials. No remote write, approval, merge, release,
production deployment, or credential migration was performed.

## References — APA 7th

GitHub. (n.d.). *Reuse workflows*. GitHub Docs. Retrieved October 3, 2026, from
https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows

GitHub. (n.d.). *About protected branches*. GitHub Docs. Retrieved October 3,
2026, from
https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

ContextualWisdomLab. (2026). *Remove redundant hourly-pr-steward workflow*
(Keyverse PR #140; commit `d8ff4eded4f82ad5e72deec940cd73e1583b4640`).
https://github.com/ContextualWisdomLab/keyverse/pull/140

ContextualWisdomLab. (2026). *Remove stale hourly-pr-steward test left behind by
#140* (Keyverse PR #143; reviewed source snapshot
`dc2ca97ae7a33d4660d0179dd6050b57e9faa076`).
https://github.com/ContextualWisdomLab/keyverse/pull/143
