# AGENTS.md

## Operating objective

Maintain Keyverse as a production-grade identity control plane that works both
standalone and as a CWL/Naruon module. Every development loop is:

```text
open PR inventory
  -> review threads and requested changes
  -> focused fixes
  -> exact-head Checks and coverage
  -> protected merge
  -> re-list PRs
  -> when zero, select one bounded buyer-visible product gap
```

Do not treat queued reviews or Checks as permission to stop. Continue with
non-conflicting investigation, documentation, test design, standards research,
or the next independent remediation while preserving one active product-change
queue owner.

## Mandatory engineering rules

- Read `CLAUDE.md`, `ARCHITECTURE.md`, the relevant specification, plan,
  operations guide, and doctoring record before changing behavior.
- Use test-driven development. Record a real failing behavior test before
  production code, then run focused and complete verification.
- Production docstring coverage, statement coverage, and branch coverage are
  100% on the exact final head.
- Tests use realistic identity-control-plane payloads, races, failures,
  migrations, and recovery—not only mocks of implementation details.
- Preserve passwordless-first authentication and the prohibition on password
  authenticators in the bound browser flow.
- Never link or merge on an unverified email.
- SAML/OIDC preflight performs no metadata/discovery fetch. LDAP preflight
  performs no DNS, socket, bind, search, storage, or Keycloak call.
- OIDC relying-party mapper support stays closed: one self-pinned audience plus
  only canonical `role`, `org`, and `workspace` hardcoded claims. Do not add
  scripts, user attributes, groups, regex, arbitrary claims, new audiences, or
  extra token destinations without a separately reviewed profile and RED test.
- Treat generated Keycloak mapper IDs and vendor ordering as normalization-only
  metadata. Unknown, malformed, duplicate, or semantically changed live mappers
  are drift and must not be silently discarded.
- Mapper configuration is issuer-side evidence, not proof that a relying party
  validates token signature, issuer, expiry, or audience. Keep controlled login
  acceptance as a separate runtime evidence boundary.
- Secrets do not appear in source, templates, responses, logs, command
  arguments, screenshots, issues, PR text, or artifacts. Hardcoded RP routing
  claim values are visible product data and must not carry credentials or
  personal secrets.
- Database objects use descriptive two-word-or-longer snake_case names.
- Preserve permissive licensing; do not add GPL/AGPL dependencies.
- Preserve standalone Compose/Helm operation and stable module boundaries for
  CWL, Naruon, and sibling repositories.
- Update `CHANGELOG.md`, beginner-readable docstrings, architecture/operations,
  and `docs/doctoring` APA 7th references whenever behavior changes.
- Raise a version and release only after exact-main regression, immutable image
  digest, SBOM/provenance, rollback evidence, and release criteria are complete.

## Standards and research

When behavior is ambiguous, use current primary standards, authoritative vendor
documentation, or peer-reviewed research. Record the interpretation and APA 7th
references under `docs/doctoring`. Distinguish standards requirements, vendor
behavior, measured evidence, policy choices, assumptions, and inference.

Do not introduce an LLM for deterministic identity validation. When an actual
LLM product path is necessary, use or improve `contextual-orchestrator`, route
model-backed tests through `NVIDIA_NIM_API_KEY`, keep provider-neutral and
offline failure contracts, and document test-time compute allocation and
ablation evidence. Never use `COPILOT_GITHUB_TOKEN`.

## Automation trust boundary

- The hourly development scheduler uses OpenCode through a vendored,
  pinned-SHA `contextual-orchestrator` gateway pointed at the fail-closed
  `orchestrator/free` pool (not a direct provider call); it does not use
  Copilot Agent Tasks.
- Existing review agents keep their current credential system. Do not repurpose,
  rename, or broaden those credentials while changing product-development
  automation.
- Generated model output is untrusted. It must remain bounded, digest-sealed,
  independently verified, and published only through a normal draft PR.
- Agents do not self-approve, bypass branch protection, force merge, tag, or
  publish a release.

## Code-owner review gates — disabled (on hold)

As of 2026-08-04, code-owner review requirements
(`require_code_owner_reviews` in branch protection,
`require_code_owner_review` in rulesets) are disabled across the
ContextualWisdomLab organization: there is a single maintainer, so a code-owner
approval gate cannot be satisfied. This is on hold until the organization has
multiple maintainers. Do not add CODEOWNERS-based merge gates or re-enable these
settings before then. Existing latest-pusher, independent-review, required
workflow, security, and unresolved-thread protections remain authoritative.
