# Keyverse protected bootstrap: source and control evidence

Date: 2026-09-09. Status: focused legacy-adapter repair; no release claim.

## Primary-source interpretation

OWASP's secrets-management guidance supports centralized policy, least
privilege, lifecycle/rotation, auditing and explicit bootstrap choices. Avoiding
`.env` by moving the root credential into plaintext configuration does not meet
those goals. The child separates the root locator from its protected transport;
it does not claim that a file provides hardware key custody.

GitHub's OIDC reference documents workload token claims and reusable-workflow
identity. The future Keyverse verifier must cryptographically validate them and
bind them to approved repository, environment and immutable workflow identity.
This bootstrap child does not implement JWT validation or change Actions tokens.

Keycloak documents vault providers for supported Keycloak credential settings.
That integration is a downstream adapter concern, not evidence of a complete
CWL secret-management service.

## Exact evidence

Parent: `0f10ac556a318c3c3f5ce7eab0802573ecce0c4c` in canonical PR #129.
Implementation: `4caafd0fa56b9ca377c93d78299bfe82dbec8faf`.

Original bootstrap/config/kv_store blobs were reconstructed exactly and verified
with Git blob hashes. Tests first observed absent protected-reader behavior,
plaintext config acceptance and credential-bearing repr. Additional regressions
caught read-time mutation and false-positive atime detection before repair.

Reproduction from the full repository:

```sh
cd services/account_unification
uv sync --locked --extra dev
uv run pytest -q tests/test_keyvault_bootstrap_credentials.py
uv run ruff check app tests tools
uv run interrogate .
uv run coverage run --branch --source=app -m pytest -q
uv run coverage report --show-missing --fail-under=100
```

Only the first focused test command's equivalent was executed in the
reconstructed local environment: 42 passed. Python compilation and diff
whitespace checks passed. Changed executable statements are 61/61 covered;
no missing branch arcs originate on changed executable lines. Full repository
coverage, Ruff, locked installation, independent review and hosted gates must
still execute; historical parent results are not reused for this child.

## Residual risks and nonclaims

The Python adapter cannot guarantee secret zeroization. Host/root access can
read mounted credentials. Other legacy configuration credentials are not yet
migrated. Namespace/key context binding, immutable secret versions, workload
reads, revocation, no-store metadata, managed identity/KMS/HSM, durable rewrap and
organization-wide rollout remain in the gap register. Deleting a SQLite row
cannot prove erasure from WAL, pages or backups.

## References — APA 7th

OWASP Foundation. (n.d.). *Secrets management cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

GitHub. (n.d.). *OpenID Connect reference*. https://docs.github.com/en/actions/reference/security/oidc

Keycloak. (n.d.). *Using a vault*. https://www.keycloak.org/server/vault
