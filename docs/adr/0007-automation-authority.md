# ADR-0007: Separate autonomous development from review, merge, and release authority

**Status:** Accepted  
**Date:** 2026-08-09  
**Last expanded:** 2026-08-18

## Context

Keyverse may use scheduled automation to inspect exact repository state
and propose bounded product work. Generated model output is untrusted.
If the same credential that writes a patch can also approve, merge, tag,
or publish a release, a single compromised or hallucinated run becomes a
release path.

NIST SP 800-218 (SSDF 1.1) recommends defining roles and separating
duties across the software life cycle, reviewing changes before release,
and protecting the build and publication environment (Souppaya et al.,
2022). Those practices are used here as secure-development evidence, not
as a claim that Keyverse is a federal information system.

This decision is about **authority**. Operator procedures for the hourly
OpenCode loop live in
[`docs/operations/hourly-product-development.md`](../operations/hourly-product-development.md)
and are not restated in the buyer README.

## Decision

Autonomous development may inspect exact repository state, produce a
bounded patch, and submit ordinary reviewable work after independent
verification. It cannot create its own qualifying approval, bypass branch
protection, merge protected main, tag, or publish a release.
Model-provider credentials remain separate from reviewer, publication,
and release credentials. PR #74 refines the hourly implementation while
preserving this authority boundary.

Existing review-agent workflows and their credentials stay on their
current system. They must not be repurposed, renamed, or broadened as a
side effect of product-development automation.

## Consequences

- A draft PR from automation is ordinary reviewable work, not a merge
  grant.
- Independent verification (fresh checkout, complete quality gates) is
  required before publication of a generated patch.
- Release tagging, image digest, SBOM, and rollback evidence remain a
  human-owned release process after exact-main regression.
- Buyer-facing README does not describe the bot loop; operators follow
  the operations guide.
- This ADR does not authorize stacking documentation or product work onto
  unrelated open feature PRs.

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software
Development Framework (SSDF) version 1.1: Recommendations for mitigating
the risk of software vulnerabilities* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218
