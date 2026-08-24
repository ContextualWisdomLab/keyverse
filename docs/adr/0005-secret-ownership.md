# ADR-0005: Separate portable configuration from deployment-private values

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

The portable realm and public desired-state templates must be reusable across
tenants and reviewable in this repository. OAuth 2.0 client credentials and
refresh or access tokens are confidential protocol values (Hardt, 2012). Bearer
tokens can be used by any party that possesses them and must be protected in
storage and transport (Jones & Hardt, 2012). OAuth 2.0 security BCP 240
requires deployments to keep client secrets and tokens out of unauthorized
channels and to treat leakage as a credential-compromise event (Lodderstedt et
al., 2025). Keycloak's Server Administration Guide stores client secrets,
identity-provider client secrets, and LDAP bind credentials in the engine's
private configuration, not in a portable realm export intended for source
control (Keycloak, n.d.).

Copying those values into templates, ordinary API responses, logs, command
arguments, or screenshots would make the portable tree tenant-specific and
would disclose credentials. Hardcoded relying-party routing claims such as
`role`, `org`, and `workspace` are visible product data and must not carry
credentials or personal secrets.

This ADR is a secret-ownership boundary. It does not replace encryption,
purpose-bound operator access, or audit of privileged reads.

## Decision

Portable realm configuration and ordinary desired-state records contain only
the fields needed for reproducible identity policy. Deployment-specific
confidential values remain owned by the deployment controller and its approved
configuration store. Public repository artifacts, ordinary responses, and
routine logs do not copy those private values. This keeps the portable realm
reusable across tenants and supports controlled rotation and rollback.

## Consequences

- Templates keep `{{placeholders}}`. Resolved secrets stay in the deployment
  controller and KV/secret store.
- Confidential relying-party credentials are placed through a separate
  secret-management port after secret-free client reconciliation.
- Operator and SCIM responses redact unknown and secret-bearing fields.
- Rotation and rollback can replace a secret without rewriting portable
  policy.
- Reviewers can read the public tree without receiving tenant credentials.
- Putting a live secret into the portable realm, a desired-state template, or
  a changelog is a boundary violation, not an onboarding shortcut.

## References

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
Internet Engineering Task Force. https://doi.org/10.17487/RFC6749

Jones, M., & Hardt, D. (2012). *The OAuth 2.0 authorization framework: Bearer
token usage* (RFC 6750). Internet Engineering Task Force.
https://doi.org/10.17487/RFC6750

Keycloak. (n.d.). *Server Administration Guide*. Retrieved August 24, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (BCP 240, RFC 9700). Internet Engineering
Task Force. https://doi.org/10.17487/RFC9700
