# ADR-0004: Use side-effect-free preflight and re-observed desired-state reconciliation

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

Federation, LDAP/AD, and relying-party onboarding accept hostile or incomplete
deployment payloads. Applying those payloads directly to Keycloak would create
live identity-provider, directory, or client objects before Keyverse could
prove they meet the closed local policy. OAuth 2.0 security BCP 240 updates
RFC 6749 and RFC 6750 and requires authorization servers and clients to reject
unsafe redirect, token, and client configurations rather than discovering them
at runtime (Lodderstedt et al., 2025; Hardt, 2012). OpenID Connect Core 1.0
assumes the relying party already has provider configuration; it does not
require a preflight validator to fetch discovery or metadata (Sakimura et al.,
2023). LDAP distinguished-name strings must follow RFC 4514 before any bind or
search is attempted (Zeilenga, 2006).

Keycloak's Admin REST and Server Administration Guide execute the remote apply
after an operator or controller decides to mutate (Keycloak, n.d.). Keyverse
therefore splits deterministic local validation from that remote mutation.
SAML and OIDC preflight perform no metadata or discovery fetch. LDAP preflight
performs no DNS, socket, bind, search, storage write, or Keycloak call.

This ADR is a control-plane lifecycle choice. Preflight success is not login,
bind, or provisioning success.

## Decision

Federation, directory, and relying-party onboarding separate deterministic
local preflight from external apply. Where Keyverse owns desired state, intent
is persisted before remote mutation, duplicate remote matches fail closed, and
a canonical apply receipt is written only after exact live re-observation.
Delete uses remote-first ordering where local-first deletion could create
false success. Preflight success never means external login/bind/provisioning
success.

## Consequences

- Operators can reject a payload without creating a live Keycloak object.
- Desired-state rows exist before network I/O so a crash during apply is
  recoverable from stored intent.
- Duplicate remote clients, identity providers, or directory components fail
  closed instead of being silently merged.
- Receipts record only what live re-observation returned. They are not a
  promise that a user can log in.
- Remote-first delete prevents a local row from disappearing while the live
  object remains.
- Expanding preflight to fetch metadata, resolve DNS, or bind LDAP would
  contradict this decision and needs a separate ADR.

## References

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
Internet Engineering Task Force. https://doi.org/10.17487/RFC6749

Keycloak. (n.d.). *Server Administration Guide*. Retrieved August 24, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (BCP 240, RFC 9700). Internet Engineering
Task Force. https://doi.org/10.17487/RFC9700

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2023).
*OpenID Connect Core 1.0 incorporating errata set 2*. OpenID Foundation.
https://openid.net/specs/openid-connect-core-1_0.html

Zeilenga, K. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
String representation of distinguished names* (RFC 4514). Internet Engineering
Task Force. https://doi.org/10.17487/RFC4514
