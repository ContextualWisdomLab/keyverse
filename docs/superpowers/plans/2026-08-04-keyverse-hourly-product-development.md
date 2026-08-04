# Keyverse Hourly Product Development Implementation Plan

> **For agentic workers:** Use Superpowers test-driven-development,
> systematic-debugging, and verification-before-completion. Do not weaken
> protected merge gates or broaden workflow permissions.

**Goal:** Start at most one bounded buyer-visible Keyverse development task each
hour when the pull-request queue and cloud-agent queue are both empty and the
exact default branch is healthy.

**Architecture:** Add a read-only GitHub Actions scheduler at minute 41. The
workflow uses the normal `GITHUB_TOKEN` only for repository state and a separate
fine-grained user token only for Agent Tasks API inventory and task creation. It
does not review, update, approve, merge, push, or release repository code.

**Tech stack:** GitHub Actions, Bash, GitHub CLI, Python 3 standard library, JSON,
pytest contract tests.

## Global constraints

- One scheduled decision at a time; never cancel an in-flight decision.
- One task maximum per run and one active task maximum per repository.
- Open PRs, unknown task states, incomplete inventory, missing credentials, or
  unhealthy default-branch evidence suppress dispatch.
- Workflow and job `GITHUB_TOKEN` permissions remain read-only.
- Agent Tasks calls use `COPILOT_GITHUB_TOKEN` and API version `2026-03-10`.
- The delegated agent creates one draft PR and may not approve, merge, bypass,
  version-publish, or release-publish its own work.
- Production docstring, statement, and branch coverage remain 100%.
- No database schema change is required.

---

### Task 1: Specify the scheduler contract

**Files:**

- Create: `services/account_unification/tests/test_hourly_product_development.py`
- Create: `docs/superpowers/specs/2026-08-04-keyverse-hourly-product-development-design.md`
- Create: `docs/superpowers/plans/2026-08-04-keyverse-hourly-product-development.md`

- [x] Define hourly, serialized, non-cancelling scheduling.
- [x] Define read-only repository permissions.
- [x] Define missing-token, PR-queue, task-inventory, unknown-state, and
  default-branch health suppression.
- [x] Define one-POST and one-draft-PR bounds.
- [x] Define the commercial, modularity, evidence, testing, database naming,
  LLM, Figma, and protected-merge prompt invariants.
- [x] Run the focused test before implementation and record the expected
  `FileNotFoundError` for the intentionally missing workflow.

### Task 2: Implement the eligibility gate

**Files:**

- Create: `.github/workflows/hourly-product-development.yml`

- [x] Schedule at minute 41 and add `workflow_dispatch`.
- [x] Set workflow and job repository permissions to read-only.
- [x] Add stable concurrency with `cancel-in-progress: false`.
- [x] Fail closed when `COPILOT_GITHUB_TOKEN` is empty.
- [x] Read the open-PR queue and fail closed on API or shape errors.
- [x] Resolve the exact `main` SHA.
- [x] Require successful exact-main `ci` and `CodeQL` workflow evidence; retain
  `Security Scan` and `SAST Semgrep` as protected pull-request merge gates.
- [x] Require every latest check run, excluding the current scheduler run, to be
  completed with an accepted conclusion.
- [x] Fetch all non-archived repository Agent Tasks with pagination.
- [x] Treat malformed records and unknown states as active.
- [x] Emit `eligible=true` only after every gate succeeds.

### Task 3: Implement one bounded task dispatch

**Files:**

- Modify: `.github/workflows/hourly-product-development.yml`

- [x] Build one immutable repository-specific task prompt.
- [x] Request `base_ref: main` and `create_pull_request: true`.
- [x] Perform exactly one Agent Tasks POST when eligible.
- [x] Require one buyer-visible slice, Superpowers, TDD, realistic tests, 100%
  docstring/statement/branch coverage, standalone plus CWL/Naruon modularity,
  APA 7th standards documentation, database naming, guarded LLM usage, and
  UI-only Figma/Product Design usage.
- [x] Ban self-approval, self-merge, bypass, push by the scheduler, and release
  publication by the delegated agent.

### Task 4: Document operations and release state

**Files:**

- Create: `docs/operations/hourly-product-development.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`

- [x] Document the two offset loops: PR stewardship at minute 17 and product
  development at minute 41.
- [x] Document `COPILOT_GITHUB_TOKEN` type and minimum permissions.
- [x] Document fail-closed and single-flight behavior.
- [x] Document first-run, rotation, revocation, and incident validation.
- [x] Record the new scheduler under `[Unreleased]`.
- [x] Do not bump version or publish a release.

### Task 5: Protected completion

- [ ] Run the focused scheduler contract tests.
- [ ] Run `uv sync --locked --extra dev`.
- [ ] Run `uv run ruff check app tests tools`.
- [ ] Run `uv run interrogate .` and require 100%.
- [ ] Run the complete pytest suite under production statement and branch
  coverage and require 100%.
- [ ] Run realm, Compose, JSON template, package-build, and documentation checks.
- [ ] Obtain exact-head CI, CodeQL, Semgrep, Security Scan, CodeRabbit, and review
  evidence.
- [ ] Merge without admin bypass.
- [ ] Confirm issue #46 closes and the schedule exists on `main`.
- [ ] Re-list open PRs and continue the normal maintenance/development loop.
