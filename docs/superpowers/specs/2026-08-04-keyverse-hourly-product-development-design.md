# Keyverse Hourly OpenCode Product Development Design

## Decision

When the protected PR queue is empty, run at most one bounded product-development
cycle at minute 41 UTC through OpenCode and NVIDIA NIM. The existing review,
repair, approval, and merge agents remain a separate trust domain.

The implementation has three jobs:

1. **Authoring** reads exact-main health, creates an immutable baseline, runs the
   model as UID/GID 65532 in a disposable archive, and emits only a bounded text
   patch plus sanitized PR metadata.
2. **Independent verification** starts from a fresh checkout, verifies the base
   SHA and patch digest, applies the patch, and executes all local acceptance
   gates without a model or publication credential.
3. **Publication** repeats the zero-PR, exact-base, and digest checks, then uses a
   dedicated token to create one run-unique branch and one draft PR.

## Credential boundary

Only the loopback broker receives `NVIDIA_NIM_API_KEY`. OpenCode receives a
non-secret placeholder and talks to `127.0.0.1`; the broker fixes the upstream
host, validates `/v1` routes, injects authorization, bounds request/response
sizes and concurrency, verifies TLS, and suppresses content logging. The model
process receives no GitHub token, OIDC token, publication token, or real NIM key.

The final job alone may read `OPENCODE_PRODUCT_DEVELOPMENT_TOKEN`. Review-agent
credentials are neither read nor changed.

## Patch and product boundary

The model may change account-unification app/tests/tools, provider templates,
documentation, `README.md`, and `CHANGELOG.md`. Every proposal must include
production code, changed tests, and `CHANGELOG.md`. The guard rejects workflow,
script, dependency, lock, realm, Docker, Helm, security-policy, and release
configuration changes, along with deletion, rename, links, executable or binary
content, unsafe paths, secret material, more than 12 files, more than 1,500
changed lines, or more than 2 MiB.

## Verification contract

The exact generated tree must pass Ruff, compileall, package build, realm and
Compose validation, provider-template JSON validation, `git diff --check`, 100%
production docstring coverage, and 100% production statement and branch
coverage. A changed base, newly opened PR, unavailable dependency source,
malformed GitHub response, model failure, boundary failure, or missing
publication token fails closed.

The immutable agent prompt requires Superpowers design, TDD, systematic
debugging, verification-before-completion, realistic identity-control-plane
tests, standalone and CWL/Naruon module compatibility, two-word-or-longer
snake_case database names, APA 7th standards traceability, and no autonomous
approval, merge, tag, or release.

## Standards traceability

The applied controls and limitations are recorded in
[`docs/doctoring/hourly-opencode-product-development.md`](../../doctoring/hourly-opencode-product-development.md).
This design uses current standards as engineering guidance and does not claim
formal NIST or SLSA conformance.
