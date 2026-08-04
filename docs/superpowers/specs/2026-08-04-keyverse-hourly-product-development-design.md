# Keyverse Hourly Product Development Design

## Problem

Keyverse now has a protected hourly pull-request steward, but that loop stops when
the open pull-request queue reaches zero. The repository therefore lacks a safe,
repeatable transition from completed maintenance to the next buyer-visible
product slice. Manual continuation creates idle time; an unconstrained coding
agent creates the opposite risk: duplicated work, concurrent branches, mutable
or unreviewed scope, and self-merged changes.

The desired behavior is not a free-running autonomous merger. It is a bounded
scheduler that delegates exactly one product-development task only when the
repository has no active pull request, no active or ambiguous cloud-agent task,
and a healthy default branch. The delegated task must produce one draft pull
request and then stop at the repository's normal review and verification gates.

## Decision

Add a repository-local caller workflow named
`.github/workflows/hourly-product-development.yml`. It runs at minute 41 of every
hour, offset from the existing PR steward at minute 17. The workflow performs a
read-only eligibility decision and, when eligible, starts one GitHub Copilot
cloud-agent task through the public-preview Agent Tasks REST API.

The workflow does not duplicate organization-central review, repair, or merge
logic. It creates no branch itself, writes no repository content, approves no
review, and merges no pull request. The Copilot task is explicitly instructed to
open one draft pull request; the existing hourly PR steward and protected checks
own every later state transition.

## Alternatives considered

### 1. Extend the existing PR steward job

This reduces workflow count, but it mixes two trust domains. The steward holds
write permissions needed to update branches and arm auto-merge, while product
selection needs only read access plus a separate user-to-server Agent Tasks
token. Combining them would broaden blast radius and make a failure in product
selection capable of affecting merge operations. Rejected.

### 2. Add the entire loop to the organization-central `.github` repository

A central reusable workflow is attractive for many repositories, but product-gap
selection is repository-specific and the current organization already has
central review/repair schedulers. A central implementation would require a new
cross-repository policy surface and rollout before Keyverse can use it. The
Keyverse workflow is kept narrow and structured so it can later become a caller
of a central reusable workflow without changing its product contract. Deferred,
not rejected.

### 3. Use GitHub Copilot Automations instead of GitHub Actions

Copilot Automations are designed for scheduled cloud-agent work, but the
repository already enforces its maintenance loops through version-controlled
GitHub Actions contracts and tests. Keeping the scheduler as code allows exact
review of token scopes, queue ownership, health gates, and prompt invariants.
Rejected for this slice; it remains a future migration option.

## Trust boundaries

### Repository token

The workflow-level and job-level `GITHUB_TOKEN` permissions are read-only:

- `actions: read`
- `contents: read`
- `pull-requests: read`
- `checks: read`

This token reads the open-PR queue, the default-branch head, workflow evidence,
and check runs. It cannot push, approve, merge, create issues, or create an agent
task.

### Agent Tasks token

The Agent Tasks API requires a user-to-server token. GitHub App installation
tokens, including the default Actions `GITHUB_TOKEN`, are not supported. The
repository secret `COPILOT_GITHUB_TOKEN` must therefore contain a fine-grained
personal access token or GitHub App user access token with repository-level
`Agent tasks: read and write` permission.

If the secret is absent, rejected, expired, or unable to list the complete task
inventory, the workflow exits successfully without creating work. This
fail-closed behavior avoids repeated task creation during credential or API
incidents.

## Eligibility algorithm

One run may create at most one task. The run is eligible only when every gate
below succeeds.

### 1. Serialize decisions

Workflow concurrency uses the repository-stable group
`keyverse-hourly-product-development` and `cancel-in-progress: false`. A newer
scheduled event cannot cancel an in-flight queue decision.

### 2. Require the dedicated user token

An empty `COPILOT_GITHUB_TOKEN` records a warning and returns
`eligible=false`.

### 3. Require an empty pull-request queue

The scheduler requests one open pull request from the repository. A failed or
unparseable response is treated as unknown and suppresses dispatch. Any open
pull request owns the development queue, including drafts and dependency PRs.

### 4. Require a healthy default branch

The workflow resolves the exact `main` head SHA. It requires successful,
completed evidence for the workflows that actually execute on a `main` push:

- `ci`
- `CodeQL`

`Security Scan` and `SAST Semgrep` remain exact-head pull-request merge gates;
they do not currently run again for the squash-generated `main` commit. Requiring
nonexistent main-push runs would leave the scheduler permanently fail-closed.
Their successful PR evidence is therefore owned by protected merge policy,
while the scheduler independently verifies the two exact-main push workflows.

The scheduler also inspects the latest check run for each app/name pair on the
exact `main` SHA, excluding the current scheduler run. Missing evidence, a
pending latest check, or an unsuccessful latest conclusion suppresses dispatch.
Success, neutral, and skipped are accepted for non-core check runs; `ci` and
`CodeQL` require successful completed workflow runs.

This is a development-start health gate, not a replacement for branch protection
or release verification.

### 5. Require a complete, idle Agent Tasks inventory

The repository-scoped task endpoint is fetched with `per_page=100`, pagination,
and `--slurp`. The parser accepts the documented `{ "tasks": [...] }` response
and paginated page arrays. An unsupported response shape is an error.

Known active states are:

- `queued`
- `in_progress`
- `idle`
- `waiting_for_user`

Known terminal states are:

- `completed`
- `failed`
- `timed_out`
- `cancelled`

Every unknown state and every malformed task record is counted as active. This
preserves single-flight behavior if the public-preview API adds a state before
the workflow is updated.

### 6. Start one task

The scheduler sends exactly one `POST /agents/repos/{owner}/{repo}/tasks` request
with:

- `base_ref: main`
- `create_pull_request: true`
- one immutable prompt assembled in the workflow

No issue loop, retry loop, or second POST exists in the workflow.

## Delegated task contract

The task prompt tells the agent to inspect repository guidance, open issues,
recent commits, architecture, tests, security posture, and the end-to-end buyer
journey. It must select exactly one highest-impact product gap that fits one
bounded pull request.

The prompt requires:

- Superpowers design, test-driven development, systematic debugging, and
  verification-before-completion;
- a failing test observed before production implementation;
- realistic identity-control-plane cases, not only synthetic happy paths;
- 100% production docstring, statement, and branch coverage;
- standalone operation and CWL/Naruon module compatibility;
- authoritative current standards or primary research when behavior is
  ambiguous, documented in APA 7th style;
- two-word-or-longer snake_case database object names;
- `CHANGELOG.md`, operator, architecture, and testing documentation updates;
- `contextual-orchestrator` and `NVIDIA_NIM_API_KEY` only when an LLM is truly
  needed, never as an unnecessary dependency;
- Figma or Product Design only when the selected slice has a real user interface;
- exactly one draft pull request;
- no self-approval, merge, protected-check bypass, version publication, or
  release publication by the delegated agent.

Release eligibility is assessed only after protected merge and verification on
`main`.

## Error handling and observability

Expected suppression states use workflow notices or warnings and terminate with
`eligible=false`, not failure. This includes an absent user token, an existing
pull request, an active task, or a temporarily unhealthy default branch.

Malformed GitHub API responses, unknown task state, and missing workflow evidence
are treated as unsafe and suppress dispatch. The workflow must not log the user
token or task prompt as shell-expanded secrets.

A successful task creation records only the task identifier, state, and URL in
the Actions log, without exposing credentials or the complete prompt payload.

## Testing

Static contract tests verify:

- the hourly offset and non-cancelling concurrency;
- read-only repository permissions;
- secret, PR queue, default-branch health, inventory, and unknown-state gates;
- pagination and current API version headers;
- one POST maximum;
- draft-PR creation request;
- prompt invariants;
- absence of merge, approval, admin bypass, and repository push commands.

The existing complete service suite remains the integration gate, including
Ruff, 100% docstrings, and 100% production statement and branch coverage.

## Rollout

1. Merge this workflow through normal protected review.
2. Configure `COPILOT_GITHUB_TOKEN` with the minimum Agent Tasks permission.
3. Observe the first scheduled run while an open PR exists; it must suppress
   dispatch.
4. After the PR queue reaches zero and `main` is green, observe exactly one task
   and one draft PR.
5. Rotate or revoke the token to confirm fail-closed behavior.
6. If a central reusable product-development scheduler becomes available, move
   the implementation there and retain this repository as a pinned caller.

## References

GitHub. (2026). *REST API endpoints for agent tasks*. GitHub Docs.
https://docs.github.com/en/rest/agent-tasks/agent-tasks

GitHub. (2026). *Using Copilot cloud agent via the API*. GitHub Enterprise Cloud
Docs.
https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/use-copilot-agents/cloud-agent/use-cloud-agent-via-the-api

GitHub. (2026). *Workflow syntax for GitHub Actions*. GitHub Docs.
https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions
