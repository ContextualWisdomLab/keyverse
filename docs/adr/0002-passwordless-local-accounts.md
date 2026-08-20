# ADR-0002: Keep ecosystem-local accounts passwordless-first

**Status:** Accepted  
**Date:** 2026-08-09
**Last expanded:** 2026-08-18

## Context

Local Keyverse accounts are created and used inside the `cwl` realm, not at
an employer IdP. A reusable password in that flow would be phishable,
resettable, and leakable independently of any federated authenticator.

W3C Web Authentication Level 2 is a Recommendation. It defines
origin-scoped public-key credentials for registration and authentication
ceremonies, with authenticators providing cryptographic proof of user
presence and consent (Hodges et al., 2021). WebAuthn Level 3 was opened as
a Candidate Recommendation Snapshot (26 May 2026) and is not treated as a
Recommendation here.

NIST SP 800-63B-4 sets authenticator-assurance requirements for remote
authentication and covers phishing-resistant authenticators, including
syncable passkeys, as the current Digital Identity Guidelines
authentication volume (Temoshok, Fenton, et al., 2025). Those guidelines
are written for U.S. federal systems and are used here as authoritative
authenticator-management evidence, not as a claim that Keyverse is a
federal CSP.

OpenID Connect Core treats authentication context as information an RP may
require before an entitlement decision; it does not require a password
authenticator at the OpenID Provider (Sakimura et al., 2023). Keycloak
already implements a WebAuthn passwordless authenticator that the portable
realm can bind as the only credential execution in the browser flow
(Keycloak, n.d.).

## Decision

The portable local browser flow uses WebAuthn/passkeys and does not include
an ordinary password authenticator. Registration creates no password and
uses a controlled enrollment action. External federation may rely on its
upstream authentication policy, but Keyverse does not silently add a local
password fallback for ecosystem-local accounts. Changing this boundary
requires explicit security/product review and migration evidence.

## Consequences

- The bound `browser-passwordless` flow and realm validator must keep
  rejecting `auth-password-form` and related password authenticators.
- Headless registration sends `VERIFY_EMAIL` plus
  `webauthn-register-passwordless` and rolls back the account if
  enrollment initialization fails.
- Self-service password reset stays off (`resetPasswordAllowed:false`).
- Federated users authenticate at their upstream IdP; this decision does
  not rewrite that upstream policy.
- A later move to WebAuthn Level 3 features needs a separate review after
  that document becomes a Recommendation.

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Hodges, J., Jones, J. C., Jones, M. B., Kumar, A., & Lundberg, E. (Eds.).
(2021, April 8). *Web Authentication: An API for accessing Public Key
Credentials Level 2* (W3C Recommendation).
https://www.w3.org/TR/2021/REC-webauthn-2-20210408/

Keycloak. (n.d.). *Server administration guide* (Version 26.7.1).
https://www.keycloak.org/docs/latest/server_admin/

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C.
(2023). *OpenID Connect Core 1.0 incorporating errata set 2*.
https://openid.net/specs/openid-connect-core-1_0.html

Temoshok, D., Fenton, J. L., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A.,
Galluzzo, R., & Richer, J. P. (2025). *Digital identity guidelines:
Authentication and authenticator management* (NIST SP 800-63B-4).
https://doi.org/10.6028/NIST.SP.800-63B-4
