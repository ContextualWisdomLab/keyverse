# ADR-0001: Keep Keycloak and Keyverse as the ecosystem identity hub

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

ContextualWisdomLab products need one identity control plane that can run
standalone and also be called by composition hubs such as Naruon and CWL.
OpenID Connect Core 1.0 is an identity layer on OAuth 2.0: a relying party
verifies the end user from authentication performed by an authorization server
and receives interoperable claims (Sakimura et al., 2023; Hardt, 2012). SAML 2.0
defines XML assertions and protocols for the same federation role when the
upstream source is an employer ADFS or similar SAML identity provider (OASIS
Security Services Technical Committee, 2005). NIST SP 800-63C-4 describes
federation as a credential service provider that supplies authentication and
optional subscriber attributes to separately administered relying parties
(Temoshok, Richer, et al., 2025).

Keycloak is the Apache-2.0 engine that already executes OIDC, OAuth, SAML
brokering, WebAuthn, LDAP user storage, and client lifecycle. Keycloak's Server
Administration Guide documents identity brokering so an external IdP
authenticates the user and Keycloak issues its own tokens to applications
(Keycloak, n.d.). Treating each employer directory or ADFS farm as a peer hub
would force every CWL relying party to administer those systems, duplicate
trust policy, and lose a portable realm.

This ADR records a product and deployment-boundary choice. It does not claim
NIST, OASIS, or OpenID conformance.

## Decision

Keyverse uses Keycloak as the standards-based identity engine and adds CWL-owned
control services around it. Employer/customer ADFS, LDAP/AD, external OIDC, and
HR/IGA are federation/provisioning sources rather than peer hubs. CWL relying
parties trust the Keyverse/Keycloak boundary instead of administering those
external systems directly. Customer-specific federation remains deployment data,
not portable realm code.

## Consequences

- Ecosystem applications obtain tokens from Keyverse/Keycloak. They do not
  become identity hubs for sibling products.
- The portable `cwl` realm stays free of employer-specific SAML, OIDC, LDAP, or
  application client registrations.
- Keyverse remains a leaf that must start independently and remain callable from
  Naruon or CWL. Composition does not transfer hub ownership to the caller.
- Identity matching, desired-state onboarding, secret ownership, and downstream
  authorization stay in later ADRs; this decision only names the hub.

## References

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
Internet Engineering Task Force. https://doi.org/10.17487/RFC6749

Keycloak. (n.d.). *Server Administration Guide*. Retrieved August 24, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

OASIS Security Services Technical Committee. (2005). *Assertions and protocols
for the OASIS Security Assertion Markup Language (SAML) V2.0* (OASIS Standard).
OASIS. https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2023).
*OpenID Connect Core 1.0 incorporating errata set 2*. OpenID Foundation.
https://openid.net/specs/openid-connect-core-1_0.html

Temoshok, D., Richer, J., Choong, Y.-Y., Fenton, J., Lefkovitz, N.,
Regenscheid, A., & Galluzzo, R. (2025). *Digital identity guidelines:
Federation and assertions* (NIST SP 800-63C-4). National Institute of Standards
and Technology. https://doi.org/10.6028/NIST.SP.800-63C-4
