# Hourly product-development loop

Keyverse uses two offset GitHub Actions schedules to keep maintenance and product
development separate:

| Minute (UTC) | Workflow | Responsibility |
| --- | --- | --- |
| `17 * * * *` | `hourly-pr-steward.yml` | Update trusted PR branches, require approval and required Checks, then arm exact-head auto-merge. |
| `41 * * * *` | `hourly-product-development.yml` | When no PR or active cloud-agent task exists and `main` is healthy, start one bounded buyer-visible development task. |

The product scheduler does not merge or approve changes. It delegates one draft
pull request; the normal PR steward and protected repository rules own review,
repair, revalidation, and merge.

## Credential boundary

The workflow's normal `GITHUB_TOKEN` is read-only and receives only:

- `actions: read`
- `checks: read`
- `contents: read`
- `pull-requests: read`

Agent Tasks API calls use the separate repository secret
`COPILOT_GITHUB_TOKEN`. GitHub's Agent Tasks REST API does not support GitHub App
installation access tokens, including the default Actions token. Configure one
of the following user-to-server credentials instead:

- a fine-grained personal access token; or
- a GitHub App user access token.

Grant the token access only to `ContextualWisdomLab/keyverse` and set the
repository-level **Agent tasks** permission to **Read and write**. Do not reuse a
broad organization-administration token.

The workflow passes this credential only to the task-inventory and task-creation
steps. It is not a job-wide environment variable and is never printed.

## Eligibility gates

A scheduled or manually dispatched run creates no task unless every gate passes.

### Empty PR queue

Any open pull request, including drafts and dependency updates, owns the product
development queue. Failure to list or parse the PR response also suppresses
dispatch.

### Healthy exact `main`

The workflow resolves the current `main` SHA and requires completed successful
runs for the workflows that actually execute on that exact squash-generated
commit:

- `ci`
- `CodeQL`

`Security Scan` and `SAST Semgrep` remain exact-head pull-request merge gates,
but they do not currently run a second time on `main` push. Their evidence is
therefore enforced by the protected merge path rather than invented as a
nonexistent main-push requirement.

The scheduler also reads all check runs for the exact commit, excludes its own
run, and evaluates only the latest occurrence of each app/name pair. Pending or
unsuccessful latest evidence suppresses dispatch. This is a start-of-work guard,
not a substitute for branch protection or post-merge release verification.

### Complete idle Agent Tasks inventory

Task listing uses API version `2026-03-10`, pagination, and slurped page output.
The parser accepts documented task collections and fails closed on an unknown
response shape.

The following states are active:

- `queued`
- `in_progress`
- `idle`
- `waiting_for_user`

The following states are terminal:

- `completed`
- `failed`
- `timed_out`
- `cancelled`

An unknown state or malformed task record counts as active. This prevents a new
API state from silently defeating the one-task-at-a-time invariant.

## One-task dispatch

An eligible run performs exactly one request to the repository-scoped Agent
Tasks endpoint with:

```json
{
  "prompt": "<repository-specific bounded task contract>",
  "base_ref": "main",
  "create_pull_request": true
}
```

The prompt requires the delegated agent to:

- select exactly one highest-impact buyer-visible gap;
- use Superpowers design, test-driven development, systematic debugging, and
  verification-before-completion;
- observe a realistic failing test before production implementation;
- preserve 100% production docstring, statement, and branch coverage;
- remain independently useful as a standalone service and as a CWL/Naruon
  module;
- cite authoritative standards or primary research in APA 7th style;
- preserve two-word-or-longer snake_case database object names;
- use `contextual-orchestrator` and `NVIDIA_NIM_API_KEY` only when a model is
  genuinely required;
- use Figma or Product Design only for an actual user-interface slice;
- update `CHANGELOG.md` and beginner-readable operating and architecture docs;
- open exactly one draft pull request;
- never self-approve, self-merge, bypass required Checks, or publish a release.

## First activation

1. Merge the workflow through the normal protected PR path.
2. Add the minimum-permission `COPILOT_GITHUB_TOKEN` repository secret.
3. While an open PR exists, manually dispatch the workflow and confirm that it
   records an ineligible queue without creating a task.
4. After the PR queue is empty and `main` is green, dispatch it again and confirm
   that exactly one Agent Task and one draft PR appear.
5. Dispatch it once more while that task or PR is active and confirm that no
   second task is created.

The scheduled workflow becomes active only after it exists on the default
branch.

## Rotation and incident handling

Rotate the fine-grained token according to the organization's credential policy.
A revoked, expired, or missing token causes a warning and no task creation. This
is the intended fail-closed response.

During an Agent Tasks API incident, leave the workflow enabled: incomplete or
unreadable task inventory prevents duplicate work. Disable the workflow only if
GitHub begins returning a misleading successful response that violates the
recorded contract; restore it after updating the parser and contract tests.

If duplicate tasks ever appear, revoke `COPILOT_GITHUB_TOKEN`, close or cancel
all but one task, inspect the concurrency and inventory evidence in the Actions
logs, add a reproducing test, and only then restore the credential.

## Release boundary

Task creation is not release authorization. A delegated slice may update
`CHANGELOG.md` and version metadata when appropriate, but no release can be
published until its PR is protected-merged and the resulting `main` commit has
completed release-specific verification, artifact signing, provenance, SBOM,
and rollback checks.

## References

GitHub. (2026). *REST API endpoints for agent tasks*. GitHub Docs.
https://docs.github.com/en/rest/agent-tasks/agent-tasks

GitHub. (2026). *Using Copilot cloud agent via the API*. GitHub Enterprise Cloud
Docs.
https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/use-copilot-agents/cloud-agent/use-cloud-agent-via-the-api

GitHub. (2026). *Workflow syntax for GitHub Actions*. GitHub Docs.
https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions
