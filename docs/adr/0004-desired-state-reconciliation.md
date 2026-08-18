# ADR-0004: Use side-effect-free preflight and re-observed desired-state reconciliation

**Status:** Accepted  
**Date:** 2026-08-09  
**Last expanded:** 2026-08-18

## Context

Operators must register SAML/OIDC identity providers, LDAP/AD user-storage
components, and OIDC relying-party clients without turning a validation
call into a live bind, metadata fetch, or silent Keycloak write.

OpenID Connect Core assumes the RP already has issuer, authorization,
token, and related endpoint locations. Those values are normally obtained
via Discovery **or may be obtained via other mechanisms** (Sakimura et
al., 2023, §1). Keyverse chooses the latter for preflight: the operator
supplies pinned HTTPS endpoints. OAuth 2.0 Security BCP requires exact
redirect matching, PKCE for code flows, and rejects patterns that leak
codes or tokens (Lodderstedt et al., 2025; Sakimura, Bradley, & Agarwal,
2015). Native-app redirect guidance is recorded in RFC 8252; this
product's first RP profile does not accept loopback or private-use
schemes without a separate review (Denniss & Bradley, 2017).

LDAP protocol operations include bind and search over a directory
connection (Sermersheim, 2006). LDAP authentication and StartTLS are
specified separately (Harrison, 2006). Distinguished-name strings used in
configuration must follow RFC 4514 syntax (Zeilenga, 2006). A local
preflight that only checks those syntactic and policy constraints is not
an LDAP session.

SCIM 2.0 defines create, replace, patch, and delete as distinct protocol
operations whose success is determined by the resource server after the
request (Hunt, Grizzle, Ansari, et al., 2015). The same lesson applies to
Keycloak mutations: a local schema check is not an apply receipt.

## Decision

Federation, directory, and relying-party onboarding separate deterministic
local preflight from external apply. Where Keyverse owns desired state,
intent is persisted before remote mutation, duplicate remote matches fail
closed, and a canonical apply receipt is written only after exact live
re-observation. Delete uses remote-first ordering where local-first
deletion could create false success. Preflight success never means
external login, bind, or provisioning success.

SAML and OIDC preflight perform no metadata or discovery fetch. LDAP
preflight performs no DNS lookup, socket, bind, search, storage write, or
Keycloak call.

## Consequences

- `POST ...:validate` routes stay pure functions of the submitted payload
  and closed policy.
- `PUT` routes store intent, classify zero / one / many live objects, and
  refuse to pick an arbitrary duplicate.
- Receipts are not written from the request body alone; operators compare
  redacted live status to the original private file.
- Controlled login, bind, or SCIM evidence remains a later acceptance
  step, not a preflight field.
- Mapper configuration on an RP client is issuer-side evidence only; it
  does not prove the RP validated signature, issuer, expiry, or audience.

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Denniss, W., & Bradley, J. (2017). *OAuth 2.0 for native apps* (RFC 8252).
https://doi.org/10.17487/RFC8252

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

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C.
(2023). *OpenID Connect Core 1.0 incorporating errata set 2*.
https://openid.net/specs/openid-connect-core-1_0.html

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol
(LDAP): The protocol* (RFC 4511). https://doi.org/10.17487/RFC4511

Zeilenga, K. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
String representation of distinguished names* (RFC 4514).
https://doi.org/10.17487/RFC4514
