#!/usr/bin/env python3
"""Idempotently finalize the NVIDIA NIM OpenCode product-development loop."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Final


ROOT: Final = Path(__file__).resolve().parents[2]
WORKFLOW: Final = ROOT / ".github" / "workflows" / "hourly-product-development.yml"
PYTHON_PACKAGE_ENDPOINTS: Final = (
    "files.pythonhosted.org:443",
    "pypi.org:443",
)


def _job_bounds(content: str, job_name: str) -> tuple[int, int]:
    """Return the start and exclusive end offsets of one top-level workflow job."""
    marker = f"  {job_name}:\n"
    start = content.index(marker)
    next_job = re.search(r"(?m)^  [a-z0-9-]+:\n", content[start + len(marker) :])
    if next_job is None:
        return start, len(content)
    return start, start + len(marker) + next_job.start()


def _ensure_job_endpoints(content: str, job_name: str) -> str:
    """Add exact Python package hosts to one job's harden-runner policy."""
    job_start, job_end = _job_bounds(content, job_name)
    job = content[job_start:job_end]
    marker = "          allowed-endpoints: |\n"
    endpoint_start = job.index(marker) + len(marker)
    endpoint_end = job.find("\n\n      - name:", endpoint_start)
    if endpoint_end == -1:
        raise RuntimeError(f"{job_name}: endpoint block terminator is missing")

    block = job[endpoint_start:endpoint_end]
    lines = block.rstrip("\n").splitlines()
    exact_endpoints = {line.strip() for line in lines if line.strip()}
    for endpoint in PYTHON_PACKAGE_ENDPOINTS:
        if endpoint not in exact_endpoints:
            lines.append(f"            {endpoint}")
    new_block = "\n".join(lines) + "\n"
    new_job = job[:endpoint_start] + new_block + job[endpoint_end:]
    return content[:job_start] + new_job + content[job_end:]


def _reconcile_workflow() -> None:
    """Make both dependency-installing jobs reliable under blocked egress."""
    content = WORKFLOW.read_text(encoding="utf-8")
    for job_name in ("develop-product-gap", "reverify-product-gap"):
        content = _ensure_job_endpoints(content, job_name)
    WORKFLOW.write_text(content, encoding="utf-8")


def _remove_markdown_section(content: str, heading: str) -> str:
    """Remove one Markdown level-two section when it exists."""
    marker = f"## {heading}\n"
    start = content.find(marker)
    if start == -1:
        return content
    next_heading = content.find("\n## ", start + len(marker))
    if next_heading == -1:
        return content[:start].rstrip() + "\n"
    return content[:start].rstrip() + "\n\n" + content[next_heading + 1 :]


def _reconcile_readme() -> None:
    """Replace stale scheduler prose with the protected OpenCode architecture."""
    target = ROOT / "README.md"
    content = target.read_text(encoding="utf-8")
    for heading in (
        "Protected autonomous loops",
        "Hourly OpenCode product development",
    ):
        content = _remove_markdown_section(content, heading)

    section = """## Hourly OpenCode product development

At minute 41 UTC, and only when no pull request exists and the exact `main` SHA
is healthy, Keyverse may run one bounded OpenCode development cycle through a
loopback NVIDIA NIM credential broker. The model works from a disposable
`git archive` without `.git`, GitHub credentials, Actions OIDC, publication
authority, or the upstream NIM credential.

A fresh job independently validates the sealed patch and re-runs the complete
100% production docstring, statement, and branch coverage gates plus package,
realm, Compose, and provider-template checks. Only then may a dedicated
`OPENCODE_PRODUCT_DEVELOPMENT_TOKEN` create one draft PR. Existing review-agent
workflows and credentials are unchanged; the development workflow cannot
approve, merge, tag, or release.

Operations are documented in
[`docs/operations/hourly-product-development.md`](docs/operations/hourly-product-development.md).
Standards traceability and APA 7th references are recorded in
[`docs/doctoring/hourly-opencode-product-development.md`](docs/doctoring/hourly-opencode-product-development.md).
"""
    target.write_text(content.rstrip() + "\n\n" + section, encoding="utf-8")


def _drop_stale_changelog_entry(content: str) -> str:
    """Remove the obsolete multi-line Agent Tasks scheduler bullet."""
    lines = content.splitlines()
    retained: list[str] = []
    skipping = False
    for line in lines:
        if line.startswith("- A fail-closed hourly product-development scheduler"):
            skipping = True
            continue
        if skipping and line.startswith("  "):
            continue
        skipping = False
        retained.append(line)
    return "\n".join(retained).rstrip() + "\n"


def _reconcile_changelog() -> None:
    """Record the final scheduler under Unreleased without claiming a release."""
    target = ROOT / "CHANGELOG.md"
    content = _drop_stale_changelog_entry(target.read_text(encoding="utf-8"))
    bullet = (
        "- An hourly fail-closed NVIDIA NIM OpenCode loop that isolates model "
        "credentials, requires a production-code/test/changelog vertical, "
        "independently verifies the sealed patch, and opens one draft PR through "
        "a dedicated publication token."
    )
    if bullet not in content:
        marker = "### Added\n"
        if marker not in content:
            raise RuntimeError("CHANGELOG is missing the Unreleased Added section")
        content = content.replace(marker, marker + "\n" + bullet + "\n", 1)
    target.write_text(content, encoding="utf-8")


def _write_design() -> None:
    """Write the authoritative architecture specification."""
    target = (
        ROOT
        / "docs"
        / "superpowers"
        / "specs"
        / "2026-08-04-keyverse-hourly-product-development-design.md"
    )
    target.write_text(
        """# Keyverse Hourly OpenCode Product Development Design

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
""",
        encoding="utf-8",
    )


def _write_plan() -> None:
    """Write the current implementation and protected-completion checklist."""
    target = (
        ROOT
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-08-04-keyverse-hourly-product-development.md"
    )
    target.write_text(
        """# Keyverse Hourly OpenCode Product Development Implementation Plan

**Goal:** Create one independently verified NVIDIA NIM OpenCode draft PR per
eligible hour without changing review-agent credentials or protected merge
criteria.

- [x] Replace cloud-agent task creation with a three-job OpenCode pipeline.
- [x] Broker `NVIDIA_NIM_API_KEY` outside the untrusted model environment.
- [x] Run OpenCode from a no-`.git`, UID/GID 65532, `env -i` workspace.
- [x] Bound paths, files, lines, bytes, modes, links, binary content, and secret
  representations in both worktree and patch validation.
- [x] Require each autonomous proposal to include production code, tests, and
  `CHANGELOG.md`.
- [x] Reverify the sealed patch on a fresh exact-main checkout.
- [x] Enforce 100% production docstring, statement, and branch coverage.
- [x] Permit exact PyPI package endpoints in both jobs that execute locked
  dependency installation.
- [x] Use exact parsed endpoint equality in workflow security contracts.
- [x] Publish only one draft PR through a dedicated development token.
- [x] Preserve standalone and CWL/Naruon module compatibility.
- [x] Add APA 7th standards traceability under `docs/doctoring`.
- [ ] Obtain successful exact-head CI, CodeQL, Semgrep, Security Scan, and
  current-head review evidence.
- [ ] Resolve every actionable review thread.
- [ ] Merge without administrative bypass.
- [ ] Confirm the schedule exists on `main`, configure the two dedicated
  development secrets, and re-list the PR queue.
- [ ] When the queue is empty, let the hourly loop select the next buyer-visible
  product gap and return it through the normal protected PR path.
""",
        encoding="utf-8",
    )


def _write_doctoring() -> None:
    """Record standards, evidence, control mapping, and explicit limitations."""
    target = ROOT / "docs" / "doctoring" / "hourly-opencode-product-development.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        """# Hourly OpenCode Product Development — Doctoring Record

## Scope and decision evidence

This record covers the scheduled Keyverse development pipeline only. It does not
replace branch protection, independent review, security scanning, release
approval, or product validation. The design separates an untrusted model process
from credentials and publication authority, transfers only a digest-bound text
patch across jobs, and independently re-runs the repository acceptance suite.

## Applied engineering controls

| Control area | Repository implementation |
| --- | --- |
| Least privilege | Read-only default `GITHUB_TOKEN`; upstream NIM and draft-PR publication use separate, step-scoped credentials. |
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
""",
        encoding="utf-8",
    )


def _audit_current_contract() -> None:
    """Fail when any final artifact still references the superseded token path."""
    audited = (
        WORKFLOW,
        ROOT / "README.md",
        ROOT / "CHANGELOG.md",
        ROOT / "docs" / "operations" / "hourly-product-development.md",
        ROOT
        / "docs"
        / "superpowers"
        / "specs"
        / "2026-08-04-keyverse-hourly-product-development-design.md",
        ROOT
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-08-04-keyverse-hourly-product-development.md",
        ROOT / "docs" / "doctoring" / "hourly-opencode-product-development.md",
    )
    for target in audited:
        content = target.read_text(encoding="utf-8")
        if "COPILOT_GITHUB_TOKEN" in content or "/agents/repos/" in content:
            raise RuntimeError(f"{target} retains the superseded scheduler contract")


def main() -> None:
    """Reconcile workflow and documentation, then audit the exact final contract."""
    _reconcile_workflow()
    _reconcile_readme()
    _reconcile_changelog()
    _write_design()
    _write_plan()
    _write_doctoring()
    _audit_current_contract()


if __name__ == "__main__":
    main()
