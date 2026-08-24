# ADR-0002: Keep ecosystem-local accounts passwordless-first

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

Ecosystem-local accounts authenticate at Keyverse rather than at an employer
IdP. Ordinary passwords are reusable, resettable, and phishable. Web
Authentication Level 2 defines scoped public-key credentials created by
authenticators with user consent, which is the protocol basis for passkeys
(Hodges et al., 2021). NIST SP 800-63B-4 is the current final authentication
and authenticator-management volume of the Digital Identity Guidelines; it
supersedes the withdrawn 2017 SP 800-63B and defines authenticator assurance
for phishing-resistant authenticators (Temoshok, Fenton, et al., 2025). OAuth
2.0 bearer tokens can be used by any party that possesses them, so local login
must not add a password that can be stolen and replayed beside a short-lived
bearer (Jones & Hardt, 2012).

Keycloak's Server Administration Guide documents WebAuthn passwordless
credentials and required actions that enroll those credentials without a
password form (Keycloak, n.d.). External federated users may still follow their
upstream authentication policy. This ADR is a Keyverse policy choice for the
portable `cwl` browser flow. It does not claim a NIST authenticator-assurance
level.

## Decision

The portable local browser flow uses WebAuthn/passkeys and does not include an
ordinary password authenticator. Registration creates no password and uses a
controlled enrollment action. External federation may rely on its upstream
authentication policy, but Keyverse does not silently add a local password
fallback for ecosystem-local accounts. Changing this boundary requires explicit
security/product review and migration evidence.

## Consequences

- The bound browser flow and realm validator reject `auth-password-form`,
  `auth-username-password-form`, and other password authenticators.
- Headless registration accepts identity and profile data only, then uses a
  bounded Keycloak action email for address verification and passkey enrollment.
- A local password reset surface is not part of the portable realm.
- Federated authentication remains an upstream policy. Linking still requires
  the evidence rules in ADR-0003.
- Reintroducing a password authenticator is a new architecture change, not a
  configuration toggle.

## References

Hodges, J., Jones, J. C., Jones, M. B., Kumar, A., & Lundberg, E. (Eds.).
(2021, April 8). *Web authentication: An API for accessing public key
credentials Level 2*. World Wide Web Consortium.
https://www.w3.org/TR/webauthn-2/

Jones, M., & Hardt, D. (2012). *The OAuth 2.0 authorization framework: Bearer
token usage* (RFC 6750). Internet Engineering Task Force.
https://doi.org/10.17487/RFC6750

Keycloak. (n.d.). *Server Administration Guide*. Retrieved August 24, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

Temoshok, D., Fenton, J., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A.,
Galluzzo, R., & Richer, J. (2025). *Digital identity guidelines: Authentication
and authenticator management* (NIST SP 800-63B-4). National Institute of
Standards and Technology. https://doi.org/10.6028/NIST.SP.800-63B-4
