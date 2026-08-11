# Hourly OpenCode Product Development — Doctoring Record

## Scope and decision evidence

This record covers the scheduled Keyverse development pipeline only. It does not
replace branch protection, independent review, security scanning, release
approval, or product validation. The design separates an untrusted model process
from credentials and publication authority, transfers only a digest-bound text
patch across jobs, and independently re-runs the repository acceptance suite.

## Applied engineering controls

| Control area | Repository implementation |
| --- | --- |
| Least privilege | Read-only default `GITHUB_TOKEN`; upstream NIM and draft-PR publication use separate, step-scoped credentials, and only broker-derived fingerprints cross the patch-scanning boundary. |
| Untrusted AI output | No `.git` or GitHub/OIDC credentials in the model workspace; bounded path and patch validation; secrets and common encodings rejected. |
| Supply-chain integrity | OpenCode and GitHub Actions are commit/digest pinned; generated patches are SHA-256 sealed and reverified on fresh checkouts. |
| Verification | Realistic regression tests, 100% production docstrings, 100% statement and branch coverage, package/deployment validation, and exact-base race checks. |
| Operational containment | One non-cancelling hourly decision; zero-open-PR and healthy-exact-main gates; one draft PR maximum; no approval, merge, tag, or release authority. |
| Modularity | Generated work must preserve standalone Keyverse operation and CWL/Naruon module contracts. |

## Standards interpretation

NIST SP 800-218 version 1.1 remains the final SSDF publication. NIST published
SP 800-218 Revision 1, SSDF version 1.2, as an Initial Public Draft on December
17, 2025; this implementation tracks that draft for new guidance but does not
treat it as a final standard. NIST SP 800-218A and NIST AI 600-1 provide AI- and
generative-AI-specific secure-development and risk-management guidance.

SLSA version 1.2 is the current approved specification. The workflow adopts
source identity, immutable input, digest, and provenance-oriented principles,
but no SLSA level or NIST conformance is claimed. Formal conformance would
require a separately scoped assessment and evidence package.

## Known limitations and residual risk

- GitHub does not provide one atomic compare-base-and-create-PR operation, so the
  workflow repeats queue and SHA checks immediately before publication and then
  relies on normal branch protection for any final network-window race.
- The model can execute bounded shell commands. It receives no private
  credentials, and final output is constrained to a verified patch, but the
  repository should still treat model behavior and dependency tools as
  untrusted.
- Hosted Actions availability, provider availability, and organization secret
  configuration remain operational dependencies.
- Scheduling and draft-PR creation are not release evidence.
- The post-model patch scanner intentionally receives only bounded
  `length:sha256` fingerprints for the raw/common encoded NIM credential; it
  must never be given the credential again merely to perform leak detection.

## References — APA 7th

Autio, C., Schwartz, R., Dunietz, J., Jain, S., Stanley, M., Tabassi, E., Hall,
P., & Roberts, K. (2024). *Artificial intelligence risk management framework:
Generative artificial intelligence profile* (NIST AI 600-1). National Institute
of Standards and Technology. https://doi.org/10.6028/NIST.AI.600-1

Booth, H., Souppaya, M., Vassilev, A., Ogata, M., Stanley, M., & Scarfone, K.
(2024). *Secure software development practices for generative AI and dual-use
foundation models: An SSDF community profile* (NIST SP 800-218A). National
Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218A

Booth, H., Ogata, M., Kent, K., Souppaya, M., & Dodson, D. (2025). *Secure
software development framework (SSDF) version 1.2: Recommendations for
mitigating the risk of software vulnerabilities* (NIST SP 800-218 Rev. 1,
Initial Public Draft). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-218r1.ipd

GitHub. (n.d.). *Workflow syntax for GitHub Actions*. GitHub Docs. Retrieved
August 5, 2026, from
https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions

National Institute of Standards and Technology. (2022). *Secure software
development framework (SSDF) version 1.1: Recommendations for mitigating the
risk of software vulnerabilities* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

NVIDIA. (n.d.). *NVIDIA NIM documentation*. Retrieved August 5, 2026, from
https://docs.nvidia.com/nim/

OpenCode. (n.d.). *Permissions*. Retrieved August 5, 2026, from
https://opencode.ai/docs/permissions/

OpenCode. (n.d.). *Providers*. Retrieved August 5, 2026, from
https://opencode.ai/docs/providers/

SLSA Community. (2025, November 24). *Announcing SLSA v1.2*.
https://slsa.dev/blog/2025/11/announce-slsa-v1.2

Supply-chain Levels for Software Artifacts. (2025). *SLSA specification,
version 1.2*. https://slsa.dev/spec/v1.2/
