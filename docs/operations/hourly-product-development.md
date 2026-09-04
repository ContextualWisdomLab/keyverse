# Centrally dispatched product development

Keyverse separates protected pull-request maintenance from autonomous product
development. The organization readiness loop owns the hourly cadence and
dispatches this repository workflow only when Keyverse has no open pull request
or active writer. The repository workflow exposes `workflow_dispatch` only; it
does not maintain a second timer or organization queue sweep.

The development workflow never approves or merges its own work and never
publishes a release. Review, repair, exact-head revalidation, and merge remain
owned by the normal protected PR path.

## Architecture

The workflow uses three jobs with different trust levels.

1. **Discover and package.** OpenCode runs as an unprivileged Unix user in a
   disposable archive of `main`. A central, commit-pinned
   contextual-orchestrator sidecar selects the `orchestrator/free` route and
   keeps upstream provider credentials outside the model process.
2. **Independently reverify.** A fresh checkout validates the textual patch,
   applies it to the exact base SHA, and runs the complete Keyverse quality,
   coverage, package, realm, Compose, and template gates without a model.
3. **Publish.** Another fresh checkout verifies the sealed patch hash and base
   SHA, then uses a dedicated publication credential to create one branch and
   one draft PR.

Only a sanitized text patch and bounded PR metadata cross job boundaries. The
model workspace has no `.git` directory, GitHub token, Actions OIDC token,
publication token, or upstream provider credential.

## Credentials

The sidecar bootstrap step may receive configured Bytez, NVIDIA NIM,
OpenRouter, and OpenAI repository secrets. The pinned central script chooses an
available upstream for `orchestrator/free`, starts a loopback-only proxy, and
writes a short-lived token to a mode-0600 file. OpenCode receives only the
loopback URL and token-file path; an isolated loader reads the token after the
process drops privileges. Raw upstream credentials never enter its environment,
command line, workspace, patch, or PR metadata.

The bootstrap step derives one-way fingerprints for every configured provider
credential and passes only those fingerprints to the patch scanner. The guard
rejects raw and commonly encoded credential forms from changed files, the
generated patch, and PR metadata. Cleanup kills sidecar descendants and removes
the token file and temporary central checkout.

`OPENCODE_PRODUCT_DEVELOPMENT_TOKEN` is a dedicated fine-grained token used
only by the final publication job. Scope it to
`ContextualWisdomLab/keyverse` with Contents read/write, Pull requests
read/write, and Metadata read. Do not reuse review or approval credentials.

## Eligibility gate

A run proceeds only when all of these statements are true:

- the central readiness loop selected Keyverse, or an operator dispatched it;
- no open pull request exists, including drafts and dependency updates;
- the current `main` SHA resolves unambiguously;
- the exact `main` SHA has successful `ci` and `CodeQL` push runs;
- the latest observed check for every app/name pair completed successfully;
- the invocation is not `dry_run`.

Failure to list or parse required GitHub evidence stops development. The
workflow does not infer health from older commits or similarly named checks on
another SHA.

## OpenCode isolation

OpenCode is installed from a versioned archive with a pinned SHA-256 digest.
Its local configuration enables only the central
`contextual-orchestrator/orchestrator/free` model. Provider discovery and
fallback stay inside contextual-orchestrator instead of repository YAML. There
is no local model-candidate loop or per-model timeout.

The agent runs under UID and GID `65532` with `env -i`. It may read, edit,
search, and run bounded local commands, but cannot use subagents, web access,
LSP, external directories, GitHub credentials, or publication authority.

## Patch boundary

The autonomous workspace may change only product source, tests, tools,
deployment templates, documentation, `README.md`, and `CHANGELOG.md`. The guard
rejects workflow and policy changes, dependencies, locks, secrets, deletions,
renames, links, executables, binary data, mode changes, unsafe paths, more than
12 files, more than 1,500 changed lines, files above 512 KiB, or a patch above
2 MiB.

The receipt records the exact base SHA, changed paths, title, body, and SHA-256
digest. Verification and publication compare that receipt with the downloaded
artifact before applying it.

## Independent verification

The fresh verification job confirms that the PR queue is still empty and that
`main` still equals the measured base SHA. It then runs the patch-guard
self-test, locked dependency sync, Ruff, Interrogate, compileall, complete
statement and branch coverage, package build, realm validation, Compose
validation, deployment-template JSON validation, and `git diff --check`.

No model or publication credential is present in this job.

## Publication and incidents

Immediately before publication, the workflow repeats the exact-base and
zero-open-PR checks. It creates one run-unique
`opencode-agent/product-dev-<run>-<attempt>` branch and one draft PR.

Repository concurrency serializes dispatches, but GitHub does not provide an
atomic compare-base-and-create-PR operation. If another actor opens a PR during
the final network interval, branch protection remains authoritative. Revoke the
publication token, preserve logs and artifacts, close duplicate drafts, add a
reproducing contract test, and restore dispatch only after exact-head
verification.

For first activation, merge through the protected path, configure at least one
central sidecar provider credential plus the publication token, verify the open
PR and dry-run gates, then perform one normal central or manual dispatch. A
missing provider route stops sidecar bootstrap; a missing publication token
prevents branch and PR creation.

## Release boundary

An autonomous draft may update `[Unreleased]`, but PR creation is not release
authorization. Release requires protected merge, complete `main` verification,
version and changelog reconciliation, signed artifacts, SBOM, provenance,
rollback evidence, and an explicit release decision.

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

Supply-chain Levels for Software Artifacts. (2025). *SLSA specification,
version 1.2*. https://slsa.dev/spec/v1.2/
