# Coupled Dependabot security updates — doctoring record

## Status

Active pull-request evidence only. This record describes the dependency-update contract on the contributor branch and does not claim protected `main` ships it until normal protected integration completes.

## Problem

Keyverse deliberately keeps `pydantic` with `pydantic-core` and `httpx2` with `httpcore2` in atomic Dependabot version-update pull requests because each parent/child pair is resolved together in the reviewed lock graph. The existing `groups` entries used `applies-to: version-updates`, so a Dependabot security update could still raise one member of a coupled pair independently. The dual-lock CI gate would then fail closed, but the security-update path would create a preventable blocked pull request rather than proposing one coherent graph.

## Decision

Define a separately named security-update group for each exact-coupled pair while retaining the existing version-update group. GitHub documents that one group rule cannot apply to both version and security updates; matching criteria must be represented as separately named groups with `applies-to: security-updates` for the security path.

The executable regression requires all four groups and their exact package sets:

- `pydantic-runtime` — version updates for `pydantic` and `pydantic-core`;
- `httpx2-runtime` — version updates for `httpx2` and `httpcore2`;
- `pydantic-runtime-security` — security updates for `pydantic` and `pydantic-core`; and
- `httpx2-runtime-security` — security updates for `httpx2` and `httpcore2`.

This changes Dependabot proposal grouping only. It does not weaken the existing `uv.lock` / exported hash-lock equivalence check, vulnerability scanning, review requirements, or protected-branch merge gates.

## TDD traceability

RED commit `f30c9b272af07e9592397d9e46d700493aeebe2b` expanded `test_exact_coupled_dependencies_update_atomically` to require the two security-update groups while the configuration still contained only the two version-update groups. GREEN commit `c593f8de3ca534bd58ee88d5f7b1bbbf15002d22` added the missing security-update groups without changing their package boundaries.

Hosted exact-head CI remains the authoritative execution evidence. Queued, skipped, stale, predecessor-head, synthetic-only, author-only, or model-only evidence is not promoted to passing.

## Rollback

Rollback removes the two `*-security` group entries and this regression together. The operational consequence is not an unsafe merge: dual-lock CI remains fail-closed. Instead, Dependabot security updates for an exact-coupled parent/child pair may again arrive separately and become unnecessarily blocked.

## References — APA 7th

GitHub, Inc. (2026a). *Configuring Dependabot security updates*. GitHub Docs. Retrieved August 26, 2026, from https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-security-updates

GitHub, Inc. (2026b). *Dependabot errors*. GitHub Docs. Retrieved August 26, 2026, from https://docs.github.com/en/code-security/reference/supply-chain-security/troubleshoot-dependabot/dependabot-errors
