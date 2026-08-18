# ADR-0005: Separate portable configuration from deployment-private values

**Status:** Accepted  
**Date:** 2026-08-09  
**Last expanded:** 2026-08-18

## Context

The portable `cwl` realm and ordinary desired-state records must be
reusable across tenants. Bind credentials, operator bearers, confidential
client secrets, and signing material must not travel with those records
into git, operator JSON, or routine logs.

OAuth 2.0 defines client authentication and client secrets as
confidential-client credentials held by the client and the authorization
server (Hardt, 2012, §2.3). The OAuth 2.0 Security BCP updates that
threat model: secrets in front-channel URLs, leaked redirectors, and
weak client authentication remain first-class failures (Lodderstedt et
al., 2025). PKCE protects the authorization code for public clients; it
does not replace confidential-client secret handling (Sakimura, Bradley,
& Agarwal, 2015).

NIST SP 800-63C-4 treats federation and assertion protection as a
deployment concern between an IdP and separately administered RPs
(Temoshok, Richer, et al., 2025). LDAP bind credentials are directory
authentication secrets (Harrison, 2006). SCIM endpoints are
bearer-protected HTTP resources (Hunt, Grizzle, Ansari, et al., 2015).
None of those standards require publishing those secrets in a realm
export.

## Decision

Portable realm configuration and ordinary desired-state records contain
only the fields needed for reproducible identity policy.
Deployment-specific confidential values remain owned by the deployment
controller and its approved configuration store. Public repository
artifacts, ordinary responses, and routine logs do not copy those private
values. This keeps the portable realm reusable across tenants and
supports controlled rotation and rollback.

Environment variables are bootstrap transport to reach that store
(`CWL_IDP_BOOTSTRAP`), not the runtime source of truth.

## Consequences

- RP desired-state PUT is secret-free; confidential credential placement
  is a separate secret-management port.
- Preflight and status responses redact `bindDn`, `bindCredential`,
  client secrets, and other known secret fields.
- Hardcoded RP routing claim values (`role`, `org`, `workspace`) are
  visible product data and must not carry credentials or personal
  secrets.
- Rotation and rollback are controller/KV operations; Keyverse receipts
  record observed public client or provider state, not the secret itself.
- Authorized identity attributes remain usable under purpose-bound access
  control, encryption, and audit. This decision does not prescribe
  display masking.

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
https://doi.org/10.17487/RFC6749

Harrison, R. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Authentication methods and security mechanisms* (RFC 4513).
https://doi.org/10.17487/RFC4513

Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015).
*System for Cross-domain Identity Management: Protocol* (RFC 7644).
https://doi.org/10.17487/RFC7644

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best
current practice for OAuth 2.0 security* (RFC 9700).
https://doi.org/10.17487/RFC9700

Sakimura, N., Bradley, J., & Agarwal, N. (2015). *Proof key for code
exchange by OAuth public clients* (RFC 7636).
https://doi.org/10.17487/RFC7636

Temoshok, D., Richer, J. P., Choong, Y.-Y., Fenton, J. L., Lefkovitz, N.,
Regenscheid, A., & Galluzzo, R. (2025). *Digital identity guidelines:
Federation and assertions* (NIST SP 800-63C-4).
https://doi.org/10.6028/NIST.SP.800-63C-4
