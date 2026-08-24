# ADR-0007: Separate autonomous development from review, merge, and release authority

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

Keyverse allows scheduled or agent-assisted development to inspect exact
repository state and propose a bounded patch. NIST SP 800-218, Secure Software
Development Framework version 1.1, is the current final SSDF publication. It
requires organizations to protect the development environment, review changes,
and keep release authority separate from untrusted production of code
(Souppaya et al., 2022). NIST later published SP 800-218 Revision 1 as an
Initial Public Draft; this ADR does not treat that draft as a final standard.
SLSA version 1.2 is an approved specification for describing supply-chain
provenance and incremental integrity, not a license to skip review (Supply-chain
Levels for Software Artifacts, 2025).

Generated model output is untrusted. It may be digest-sealed and independently
verified, then published only through an ordinary draft pull request. Model-
provider credentials must stay separate from reviewer, publication, and release
credentials so a development loop cannot approve or merge its own work.

This ADR is an authority boundary. It does not claim NIST SSDF or SLSA
conformance. PR #74 refined the hourly implementation while preserving this
boundary.

## Decision

Autonomous development may inspect exact repository state, produce a bounded
patch, and submit ordinary reviewable work after independent verification. It
cannot create its own qualifying approval, bypass branch protection, merge
protected main, tag, or publish a release. Model-provider credentials remain
separate from reviewer, publication, and release credentials. PR #74 refines
the hourly implementation while preserving this authority boundary.

## Consequences

- Automation may open at most a normal draft pull request after independent
  verification. Draft is not Ready for review, not an approval, and not a
  merge instruction.
- Existing review agents keep their own credential system. Development
  automation must not repurpose, rename, or broaden those credentials.
- Branch protection, required checks, unresolved-thread gates, and human
  release criteria remain authoritative.
- A merged pull request is still not a release. Release requires exact-main
  regression, immutable image digest, SBOM/provenance, rollback evidence, and
  the documented release criteria.
- Agents do not self-approve, force merge, tag, or publish.

## References

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development
framework (SSDF) version 1.1: Recommendations for mitigating the risk of
software vulnerabilities* (NIST SP 800-218). National Institute of Standards
and Technology. https://doi.org/10.6028/NIST.SP.800-218

Supply-chain Levels for Software Artifacts. (2025). *SLSA specification,
version 1.2*. https://slsa.dev/spec/v1.2/
