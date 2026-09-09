# ADR-0017: Keyverse self-bootstrap uses protected secret mounts, not dotenv

**Status:** Proposed
**Date:** 2026-09-10
**Related:** Key Vault foundation #129, protected root bootstrap #151, CWL migration ContextualWisdomLab/.github#2063

## Context

CWL is moving application credentials away from `.env` and toward Keyverse as
the canonical secret-lifecycle authority. Keyverse itself cannot obtain the
credentials required to start its database and Keycloak engine from a Keyverse
API that is not running yet. That is a genuine self-bootstrap cycle, not a
reason to keep dotenv as a parallel secret authority.

The protected `main` Compose profile previously instructed operators to copy
`.env.example` to `.env` and placed the PostgreSQL password and one-time
Keycloak bootstrap administrator credentials into Compose interpolation. This
made the repository-local dotenv file an operational credential source even
though comments described it as temporary transport.

The Helm profile already consumes pre-created Kubernetes Secret objects. That
is closer to the intended boundary, but the mechanism that populates those
objects still belongs to the deployment platform and must not be confused with
Keyverse's runtime workload secret API.

## Decision

Keyverse has exactly one narrow bootstrap exception for secrets needed before
its own secret service can be available. In standalone Compose, a trusted host
supervisor, credential agent, or KMS/HSM adapter materializes these files
outside the repository:

```text
/run/keyverse-bootstrap/idp_database_password
/run/keyverse-bootstrap/idp_bootstrap_admin_username
/run/keyverse-bootstrap/idp_bootstrap_admin_password
```

Compose mounts them as service secrets. PostgreSQL consumes its password via
the image's `POSTGRES_PASSWORD_FILE` contract. Keycloak consumes bootstrap
values through native process-environment options, so a small container
entrypoint reads only those mounted files immediately before `exec` of
`kc.sh`. It neither discovers dotenv files nor provides a general-purpose
secret resolver.

The account-unification service keeps `CWL_IDP_BOOTSTRAP` only as a non-secret
locator for `bootstrap.yaml`. The descriptor itself contains configuration and
opaque secret references, never secret values. Application credentials,
provider keys, database credentials of ordinary CWL consumers, and user secrets
do not qualify for the root-bootstrap exception.

The repository-local `.env.example` credential template is removed. Non-secret
ports, hostname, cache mode, and database name/user may remain explicit
operator/deployment configuration; they are not promoted into the Key Vault
merely to eliminate a filename.

## Security invariants

- No Keyverse or CWL runtime may fall back from a failed Keyverse lookup to a
  dotenv file, plaintext config DB, shared administrator token, or second local
  vault.
- Root-bootstrap files are materialized outside the source checkout and are not
  committed, copied into YAML, logged, attached to CI artifacts, passed as
  command arguments, or sent to a model.
- The Keycloak adapter handles only the three declared bootstrap files and
  immediately replaces itself with Keycloak using `exec`.
- Production orchestration is responsible for protecting and rotating the
  source material and for deleting the one-time bootstrap administrator once
  passkey/operator provisioning is complete.
- Helm Secret objects remain bootstrap transport, not a second product-owned
  secret system. Their source should converge on managed workload identity plus
  external KMS/HSM custody.
- Ordinary CWL applications adopt only an immutable released Keyverse workload
  contract with tenant/environment/namespace/key/version/operation scope,
  lease/revocation, audit, and fail-closed outage behavior.

## Consequences

Standalone startup is no longer a one-command operation after creating `.env`;
an operator or deployment controller must first provide the explicit bootstrap
files. This extra step is intentional because the trust boundary is now visible
and independently governable.

This ADR does not claim that a host file is equivalent to HSM custody, nor that
Keyverse's workload read API is already released. It only removes dotenv from
Keyverse's own bootstrap path and narrows the unavoidable bootstrap secret
surface. PR #129/#151 and their successors still own encrypted custody,
protected vault-root loading, workload resolution, versioning, rotation,
revocation, KMS/HSM integration, and immutable release evidence.

## Alternatives rejected

### Keep `.env` because it is only bootstrap transport

Rejected. A repository-local file holding reusable bootstrap passwords remains
a credential authority in practice and becomes an easy fallback path for other
services.

### Put bootstrap passwords in `bootstrap.yaml`

Rejected. Renaming the plaintext container does not create a new trust boundary
and couples locators/configuration to secret backup and access semantics.

### Make Keyverse fetch its own startup secrets from Keyverse

Rejected as circular. The data plane cannot serve credentials before the
identity/database/key material required to start it is available.

### Give every CWL service the same supervisor-file exception

Rejected. The exception exists only to break Keyverse's own bootstrap cycle.
Once Keyverse is available, consumers must use its released workload contract.

## References

Barker, E. (2020). *Recommendation for key management: Part 1 – General*
(NIST SP 800-57 Part 1 Rev. 5). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-57pt1r5

OWASP Foundation. (n.d.). *Secrets management cheat sheet*.
https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
