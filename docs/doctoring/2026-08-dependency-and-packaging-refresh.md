# August 2026 Dependency and Packaging Refresh — Doctoring Record

## Scope

This change consolidates the open account-unification dependency updates
into one reproducible graph. It updates the direct runtime, transport,
certificate, testing, linting, and build-backend surfaces together rather
than merging independently generated requirement fragments that disagree
with `pyproject.toml` or `uv.lock`.

The bounded package targets are:

| Package | Previous | Target | Surface |
|---|---:|---:|---|
| AnyIO | 4.14.1 | 4.14.2 | transitive runtime and development |
| Certifi | 2026.6.17 | 2026.7.22 | transitive runtime and development |
| Coverage | 7.14.3 | 7.15.2 | direct development |
| FastAPI | 0.140.13 | 0.141.1 | direct runtime |
| HTTPCore2 | 2.5.0 | 2.9.1 | transitive development transport |
| HTTPX2 | 2.5.0 | 2.9.1 | direct development transport |
| Ruff | 0.16.0 lock state | 0.16.1 | direct development; main already declares 0.16.1 |
| Uvicorn | 0.52.0 | 0.52.1 | direct runtime |
| Setuptools | unbounded `>=68` build requirement | 83.0.0 | build backend and direct development |

No application behavior, database schema, authentication policy, review
credential, or LLM integration is changed by this refresh.

## Canonical dependency surfaces

`pyproject.toml` is the reviewed direct-requirement source. `uv.lock` is
the universal exact resolution. `requirements.lock` is the generated
runtime installation surface, and `requirements-dev.txt` is the generated
development installation surface. They are regenerated from one resolver
execution and must not be edited independently.

The verifier requires every target version to appear on its correct
surface and rejects the superseded exact versions. `uv lock --check` and
`uv sync --locked --extra dev` prove that the reviewed declarations and
universal lock remain mutually consistent.

## PEP 639 license metadata

The legacy TOML table form `license = { text = "Apache-2.0" }` is
deprecated. The package now uses the standardized SPDX expression
`license = "Apache-2.0"` and declares `license-files = ["LICENSE"]`.
The service-local license bytes are copied from the repository's canonical
Apache License 2.0 text. Distribution verification requires the wheel
metadata to contain `License-Expression: Apache-2.0`, exactly one
`.dist-info/licenses/LICENSE` entry, and an identical license file in the
source distribution.

## Verification contract

Exact completion requires:

- immutable-main ancestry;
- exact target and stale-version checks across all dependency surfaces;
- locked installation with Setuptools 83.0.0;
- Ruff, Python compilation, and production docstrings at 100%;
- full pytest with production statement and branch coverage at 100%;
- non-isolated wheel and source-distribution build with no legacy-license
  deprecation warning;
- wheel metadata and packaged-license byte validation;
- Keycloak realm, Docker Compose, and deployment-template validation;
- current-head CI, CodeQL, Semgrep, Security Scan, independent review,
  and protected merge policy.

## Residual risk

A dependency version being current does not prove application
compatibility. Repository behavior and security tests remain the evidence
for this bounded graph. A later release still requires exact-main image,
SBOM, provenance, rollback, and operational acceptance evidence.

## References — APA 7th

Astral Software, Inc. (2026a). *Locking and syncing*. Retrieved August 6,
2026, from https://docs.astral.sh/uv/concepts/projects/sync/

Astral Software, Inc. (2026b). *Structure and files*. Retrieved August 6,
2026, from https://docs.astral.sh/uv/concepts/projects/layout/

Ombredanne, P., Gerlach, C. A. M., & Surma, K. (2025). *PEP 639—Improving
license clarity with better package metadata*. Python Software Foundation.
https://peps.python.org/pep-0639/

Python Packaging Authority. (2026a). *Pyproject.toml specification*.
Retrieved August 6, 2026, from
https://packaging.python.org/en/latest/specifications/pyproject-toml/

Python Packaging Authority. (2026b). *Setuptools 83.0.0*. Retrieved August
6, 2026, from https://pypi.org/project/setuptools/83.0.0/

Python Packaging Authority. (2026c). *Writing your pyproject.toml*.
Retrieved August 6, 2026, from
https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
