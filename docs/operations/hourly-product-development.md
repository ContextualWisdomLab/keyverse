# Hourly product-development loop

Keyverse separates protected pull-request maintenance from autonomous product
development. The schedules are offset so the merge loop has time to settle the
repository before a new product slice is considered.

| Minute (UTC) | Workflow | Responsibility |
| --- | --- | --- |
| `17 * * * *` | `hourly-pr-steward.yml` | Update trusted PR branches, require approval and required Checks, then arm exact-head auto-merge. |
| `41 * * * *` | `hourly-product-development.yml` | When the PR queue is empty and exact `main` is healthy, use OpenCode with NVIDIA NIM to produce one bounded buyer-visible draft PR. |

The development scheduler never approves or merges its own work and never
publishes a release. The existing review-agent workflows and their credentials
remain unchanged. Review, repair, revalidation, and merge stay owned by the
normal protected PR path.

## Architecture

The workflow uses three jobs with different trust levels.

1. **Discover and package.** A model runs as an unprivileged Unix user inside a
   disposable, credential-free archive of `main`. It may edit only the bounded
   product paths. A local broker injects the real NVIDIA credential into a fixed
   upstream host; OpenCode receives only a non-secret placeholder key.
2. **Independently reverify.** A fresh checkout validates the textual patch,
   applies it to the exact base SHA, and runs the complete Keyverse quality,
   coverage, package, realm, Compose, and template gates without a model.
3. **Publish.** A second fresh checkout verifies the sealed patch hash and base
   SHA again, then uses a dedicated publication credential to create one branch
   and one draft PR.

Only a sanitized text patch and bounded PR metadata cross job boundaries. The
model workspace has no `.git` directory, GitHub token, Actions OIDC token,
publication token, or upstream NVIDIA key.

## Credentials

### `NVIDIA_NIM_API_KEY`

This repository secret is available only to the local credential broker. The
broker derives one-way fingerprints for the raw and common encoded forms,
publishes only those fingerprints to the later patch scanner, and then removes
the raw value from its process environment. It is not placed in the OpenCode
process environment. The model process receives
`NVIDIA_API_KEY=keyverse-local-broker` and sends requests to
`http://127.0.0.1:8765/v1`.

The broker:

- binds only to IPv4 loopback;
- forwards only bounded GET and POST requests under `/v1`;
- rejects absolute URLs, traversal, nested encoding, encoded separators, and
  controls;
- uses a fixed upstream host, `integrate.api.nvidia.com`;
- creates a verified TLS client with TLS 1.2 or newer;
- strips caller-controlled authorization and injects the real key itself;
- suppresses request logging so prompts and responses do not enter Actions
  logs;
- limits request size, response size, and concurrent upstream requests.

The patch guard rejects the raw key and common Base64, URL-safe Base64, and hex
representations from changed files, the generated patch, and PR metadata when
the trusted broker can hold the raw key. The post-model scanner receives only
the broker-derived `length:sha256` fingerprints and hashes candidate
non-whitespace tokens; it never receives the raw key.

### `OPENCODE_PRODUCT_DEVELOPMENT_TOKEN`

This dedicated fine-grained token is used only in the final publication step.
It must be scoped to `ContextualWisdomLab/keyverse` with the minimum permissions
needed to create a branch and draft pull request:

- **Contents:** read and write;
- **Pull requests:** read and write;
- **Metadata:** read.

Do not reuse `PR_REVIEW_MERGE_TOKEN`, `OPENCODE_APPROVE_TOKEN`, CodeRabbit
credentials, or any review-agent secret. Development publication and review
approval are separate trust domains.

The normal `GITHUB_TOKEN` remains read-only throughout the workflow. The
publication token is supplied through `GIT_ASKPASS` and `GH_TOKEN`; it is not
embedded in a remote URL or written to the repository.

## Eligibility gate

A run proceeds only when all of these statements are true.

- `NVIDIA_NIM_API_KEY` is configured.
- No open pull request exists, including drafts and dependency updates.
- The current `main` SHA can be resolved unambiguously.
- The exact `main` SHA has completed successful `ci` and `CodeQL` push runs.
- The latest check run for every observed app/name pair is complete with a
  `success` conclusion. Optional neutral/skipped checks are not treated as
  required evidence by this gate.
- The workflow is not a `dry_run` invocation.

Failure to list or parse any required GitHub response stops development. The
scheduler does not infer health from older commits or from a similarly named
check on another SHA.

`Security Scan` and `SAST Semgrep` remain protected exact-head PR merge gates.
They do not currently emit a second push run for the squash-generated `main`
commit, so the scheduler does not fabricate nonexistent post-merge evidence.

## OpenCode isolation

OpenCode is installed from a versioned release archive whose SHA-256 digest is
pinned in the workflow. The configured model pool is limited to NVIDIA NIM
models. The project-local `opencode.json` allows reading, editing, searching,
and bounded shell use while denying subagents, web search, web fetch, LSP, and
external-directory access.

The agent runs under UID and GID `65532` with `env -i`. Its environment contains
only a minimal executable path, an isolated home and temporary directory, the
workspace-local Python import path, deterministic locale settings, the local
broker placeholder key, and OpenCode update suppression. GitHub, Actions OIDC,
and publication credentials are absent.

The model receives a repository-specific contract requiring:

- exactly one highest-impact buyer-visible product gap;
- Superpowers design, test-driven development, systematic debugging, and
  verification-before-completion;
- a real failing regression before production implementation;
- realistic OIDC, SAML, SCIM, merge, outage, concurrency, migration, or
  deployment cases where applicable;
- 100% production docstring, statement, and branch coverage;
- standalone and CWL/Naruon module compatibility;
- current authoritative standards or primary research documented in APA 7th
  style;
- two-word-or-longer snake_case database object names;
- `contextual-orchestrator` only when a model is genuinely necessary;
- Figma or Product Design only for an actual user-interface slice;
- no merge, approval, release, dependency change, workflow change, or secret
  disclosure.

Repository prose, issues, comments, fixtures, provider metadata, generated
files, payloads, and fetched references are treated as untrusted data rather
than instructions.

## Patch boundary

The autonomous workspace may change only:

- `services/account_unification/app/**`;
- `services/account_unification/tests/**`;
- `services/account_unification/tools/**`;
- `deploy/templates/**`;
- `docs/**`;
- `README.md`;
- `CHANGELOG.md`.

The guard rejects:

- deletions and renames;
- `.github`, `.git`, scripts, locks, dependency manifests, realm source,
  Docker/Helm configuration, security policy, and release configuration;
- symlinks, hard links, executables, binary files, NUL bytes, mode changes, and
  unsafe paths;
- more than 12 files, 1,500 changed lines, 512 KiB per file, or 2 MiB in total;
- malformed or duplicate patch paths;
- a patch or PR message containing the NVIDIA credential or common encodings.

The patch receipt records the exact base SHA, changed paths, title, body, and
SHA-256 digest. The verification and publication jobs compare this receipt to
the downloaded artifact before applying it.

## Independent verification

The fresh verification job requires that the PR queue is still empty and that
`main` still equals the measured base SHA. It then runs:

```bash
python scripts/ci/hourly_product_guard.py self-test
cd services/account_unification
uv sync --locked --extra dev
uv run ruff check app tests tools
uv run interrogate .
uv run python -m compileall -q app tests tools
uv run coverage run --branch --source=app -m pytest -q
uv run coverage report --show-missing --fail-under=100
uv build --out-dir dist
cd ../..
python scripts/validate_realm.py deploy/keycloak/realm-cwl.json
docker compose -f docker-compose.yml config
python -m json.tool deploy/templates/<each-json-template>.json
git diff --check
```

No model credential or publication credential is present in this job.

## Publication and race handling

Immediately before publication, the workflow repeats the exact-base and
zero-open-PR checks, validates the sealed patch digest, and applies the patch to
a fresh checkout. It creates one run-unique branch named
`nim-agent/product-dev-<run>-<attempt>` and one draft PR.

Workflow concurrency serializes scheduled runs, but GitHub does not provide an
atomic compare-base-and-create-PR operation. If another actor opens a PR in the
final network interval, branch protection and the subsequent hourly steward
remain authoritative. During a duplicate-publication incident, revoke
`OPENCODE_PRODUCT_DEVELOPMENT_TOKEN`, close all but one draft, preserve the
Actions logs and artifacts, add a reproducing contract test, and only then
restore the token.

## First activation

1. Merge the workflow through the normal protected PR path.
2. Configure `NVIDIA_NIM_API_KEY` and the dedicated
   `OPENCODE_PRODUCT_DEVELOPMENT_TOKEN`.
3. While a PR is open, manually dispatch the workflow and confirm that it exits
   at the queue gate without starting OpenCode.
4. After the PR queue is empty and exact `main` is green, run a dry run and
   confirm the health gate succeeds without invoking a model.
5. Run a normal dispatch and confirm that one draft PR is created.
6. Dispatch again while that draft is open and confirm that no second agent
   session begins.

The hourly schedule is active only after the workflow exists on the default
branch.

## Rotation, revocation, and incident response

Rotate both credentials according to the organization policy and never rotate
review-agent credentials as part of this workflow. A missing or revoked NIM key
stops before authoring. A missing publication token allows no branch or PR
creation and fails the publication step visibly.

If the NIM broker, OpenCode provider integration, patch guard, or independent
verification behaves unexpectedly, disable this workflow only; do not weaken
branch protection or the existing review system. Preserve the failed run,
identify the trust boundary where the invariant broke, add a regression, and
restore the schedule after exact-head verification.

## Release boundary

An autonomous draft may update `[Unreleased]`, but task creation and PR creation
are not release authorization. A release may occur only after protected merge,
complete `main` verification, version and changelog reconciliation, signed
artifacts, SBOM, provenance, rollback evidence, and an explicit release decision.

## References

GitHub. (2026). *Workflow syntax for GitHub Actions*. GitHub Docs.
https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions

National Institute of Standards and Technology. (2022). *Secure software
development framework (SSDF) version 1.1: Recommendations for mitigating the
risk of software vulnerabilities* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2024). *Artificial
intelligence risk management framework: Generative artificial intelligence
profile* (NIST AI 600-1). https://doi.org/10.6028/NIST.AI.600-1

OpenCode. (2026). *Providers, permissions, and non-interactive run command*.
https://opencode.ai/docs/

NVIDIA. (2026). *NVIDIA NIM APIs: OpenAI-compatible inference endpoints*.
https://docs.nvidia.com/nim/

Supply-chain Levels for Software Artifacts. (2025). *SLSA specification,
version 1.2*. https://slsa.dev/spec/v1.2/
