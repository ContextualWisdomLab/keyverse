# October 2026 HTTPX2 Transport Security Floor — Doctoring Record

## Scope

The `trivy-fs` security gate reported three HIGH findings in
`services/account_unification/uv.lock`. All of them were in the development
HTTP transport. That transport consists of the direct development requirement
`httpx2` and its exact-coupled dependency `httpcore2`, both at 2.9.1:

| Advisory | Affected | Fixed | Effect |
|---|---|---|---|
| CVE-2026-84381 / GHSA-7mj9-2mp8-4m2p | `httpcore2` < 2.10.0; `httpx2` 2.6.0–2.9.1 | 2.10.0 | A `wss` origin through a SOCKS5 proxy does not start TLS. The handshake, headers, cookies, and frames cross the proxy in cleartext without certificate verification. |
| CVE-2026-84382 / GHSA-8xx6-hgc6-gc2m | `httpx2` < 2.12.0 | 2.12.0 | Each compressed network chunk is fully inflated before bounded streaming, so a hostile server can force very large intermediate allocations. |

This change moves both packages to 2.12.0 on the three canonical dependency
surfaces in one resolver execution. `httpx2` 2.12.0 requires
`httpcore2==2.12.0`. The resolver also adds `httpx2-jsfetch` 1.0
(BSD-3-Clause), but only behind an `emscripten` platform marker. It is not
installed on Linux or macOS.

No application code, database schema, authentication policy, review
credential, or LLM integration changes. The account-unification runtime
requirement set (`requirements.lock`) does not contain `httpx2`. The packages
are test and development transport only. This lowers runtime exposure, but it
does not remove the need for a patched development graph, because the tests
and CI runners execute this transport.

## Separate Dependabot proposals

Dependabot opened separate drafts for each package (#122, #124, #149,
#150). `httpx2` pins `httpcore2` exactly, so a fragment that updates one
package without the other cannot resolve. A `requirements-dev.txt` edit
without the matching `uv.lock` change is also not reproducible. This change
replaces those fragments with one coupled update. The behavior is consistent
with the grouped-update rationale in
`2026-08-dependency-and-packaging-refresh.md`.

## Verification contract

`tests/test_dependency_security_floor.py` reads `pyproject.toml`, `uv.lock`,
and `requirements-dev.txt` directly. It fails when any surface resolves
`httpx2` or `httpcore2` below 2.12.0, and when the two lock representations
disagree. The test was recorded failing against the unpatched main lock
before the dependency surfaces were regenerated.

`uv sync --locked --extra dev`, Ruff, interrogate, documentation contracts,
and the complete suite with enforced 100% production statement and branch
coverage are the compatibility evidence. A local `trivy fs` scan with HIGH
and CRITICAL severity and `--exit-code 1` is the advisory evidence.

## Residual risk

A security floor proves that a known vulnerable release is not selected. It
does not prove that 2.12.0 has no other defects. Hosted `trivy-fs` and
dependency-review results on the exact pull request head remain
authoritative.

## References — APA 7th

Aqua Security. (2026a). *CVE-2026-84381*. Aqua Vulnerability Database.
Retrieved October 6, 2026, from https://avd.aquasec.com/nvd/cve-2026-84381

Aqua Security. (2026b). *CVE-2026-84382*. Aqua Vulnerability Database.
Retrieved October 6, 2026, from https://avd.aquasec.com/nvd/cve-2026-84382

Astral Software, Inc. (2026). *Locking and syncing*. Retrieved August 6,
2026, from https://docs.astral.sh/uv/concepts/projects/sync/

Pydantic. (2026a). *HTTPX2 2.10.0* [Software release]. GitHub.
https://github.com/pydantic/httpx2/releases/tag/v2.10.0

Pydantic. (2026b). *HTTPX2 2.12.0* [Software release]. GitHub.
https://github.com/pydantic/httpx2/releases/tag/v2.12.0
