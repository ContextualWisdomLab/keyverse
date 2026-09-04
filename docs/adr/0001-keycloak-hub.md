# ADR-0001: Keep Keycloak and Keyverse as the ecosystem identity hub

**Status:** Accepted  
**Date:** 2026-08-09
**Last expanded:** 2026-08-18

## Context

ContextualWisdomLab products need one identity leaf that can run on its own
and still be called by relying parties. OpenID Connect Core defines an
OpenID Provider as an OAuth 2.0 authorization server that authenticates the
end-user and issues claims to a relying party (Sakimura et al., 2023).
OAuth 2.0 is the official authorization-framework record (Hardt, 2012).
SAML 2.0 defines assertions and protocols that a service provider uses to
accept authentication from an external asserting party (Cantor et al.,
2005; OASIS Open, 2005). LDAP is a directory-access protocol, not an
identity hub (Sermersheim, 2006). SCIM 2.0 is an HTTP protocol for
cross-domain user lifecycle (Hunt, Grizzle, Ansari, et al., 2015).

NIST SP 800-63C-4 describes federation as one credential service provider
supplying authentication attributes to separately administered relying
parties, and those relying parties using one or more providers (Temoshok,
Richer, et al., 2025). That model fits a single Keyverse issuer with
external employer ADFS, LDAP/AD, optional personal OIDC, and HR/IGA SCIM
as inbound sources.

Keycloak's published administration guide documents OpenID Connect, OAuth
2.0, SAML, identity brokering, and LDAP/Active Directory user federation
in one Apache-2.0 engine (Keycloak, n.d.). Building the portable `cwl`
realm and Keyverse control plane on that engine avoids a second protocol
stack and keeps customer federation out of committed realm JSON.

Composition hubs such as naruon and gyeot may call this leaf. Orgmetra
owns employment and org-tree truth; Keyverse does not copy those tables.

## Decision

Keyverse uses Keycloak as the standards-based identity engine and adds
CWL-owned control services around it. Employer/customer ADFS, LDAP/AD,
external OIDC, and HR/IGA are federation or provisioning sources rather
than peer hubs. CWL relying parties trust the Keyverse/Keycloak boundary
instead of administering those external systems directly.
Customer-specific federation remains deployment data, not portable realm
code.

This repository must boot from its own Compose or Helm artifacts. Optional
parent include of this repo's Compose or Helm chart is allowed. A Keyverse
checkout must not require naruon, gyeot, Orgmetra, or any other sibling
repository.


## Compose and Helm realm-import invariant

Keycloak directory import discovers a realm only when its target is named
`<realm>-realm.json`. The portable file is therefore `cwl-realm.json`. Compose
packages that file in a derivative of the pinned Keycloak image instead of
bind-mounting a leaf below `/opt/keycloak/data`; Docker Desktop can present such
a leaf mount as a directory and make the import fail. Helm maps its ConfigMap
key to the same filename. A container health check alone is insufficient: it can
be healthy while the intended realm was never imported. Deployment acceptance
therefore verifies the realm discovery endpoint, and a static deployment contract
locks the filename mapping in both packaging paths.

## Keycloak runtime-user invariant

The derivative image must explicitly run as the non-root UID supplied by the
pinned Keycloak base image. Build-time file copies remain readable and
executable by that runtime user, while the Keycloak server and the post-import
profile reconciliation script do not receive root authority. The deployment
contract locks `USER 1000`, and acceptance also inspects a locally built image
before it can satisfy the image-security gate.

## Consequences

- Ecosystem RPs implement OIDC client behavior against one issuer rather
  than each administering ADFS, LDAP, or SCIM themselves.
- External IdP metadata, bind credentials, and RP client secrets stay in
  the deployment KV/controller, so the portable realm stays reusable.
- Protocol coverage is bounded by what Keycloak already executes: OIDC and
  OAuth 2.0 outbound, SAML and OIDC brokering inbound, LDAP/AD user
  storage, plus the Keyverse SCIM shim and account-unification API.
- OAuth 2.1 is not treated as a final RFC; see
  [`docs/REFERENCES.md`](../REFERENCES.md) for the current Internet-Draft
  label.
- Authorization after a verified token remains an RP obligation
  ([ADR-0008](0008-keyverse-rp-authorization-boundary.md)).

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Cantor, S., Kemp, J., Philpott, R., & Maler, E. (Eds.). (2005).
*Assertions and protocols for the OASIS Security Assertion Markup Language
(SAML) V2.0*. OASIS.
https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
https://doi.org/10.17487/RFC6749

Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015).
*System for Cross-domain Identity Management: Protocol* (RFC 7644).
https://doi.org/10.17487/RFC7644

Keycloak. (n.d.). *Server administration guide* (Version 26.7.1).
https://www.keycloak.org/docs/latest/server_admin/

OASIS Open. (2005). *Security Assertion Markup Language (SAML) v2.0*.
https://www.oasis-open.org/standard/saml/

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C.
(2023). *OpenID Connect Core 1.0 incorporating errata set 2*.
https://openid.net/specs/openid-connect-core-1_0.html

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol
(LDAP): The protocol* (RFC 4511). https://doi.org/10.17487/RFC4511

Temoshok, D., Richer, J. P., Choong, Y.-Y., Fenton, J. L., Lefkovitz, N.,
Regenscheid, A., & Galluzzo, R. (2025). *Digital identity guidelines:
Federation and assertions* (NIST SP 800-63C-4).
https://doi.org/10.6028/NIST.SP.800-63C-4
