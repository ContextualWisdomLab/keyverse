# ADR-0003: Use exact external subject, then verified email, then explicit link

**Status:** Accepted  
**Date:** 2026-08-09
**Last expanded:** 2026-08-18

## Context

The same human can arrive through a federated SAML or OIDC IdP, an LDAP
user-storage component, inbound SCIM, and a local passkey account. Those
paths must share one matching rule so a weaker path cannot link or merge
accounts that a stronger path would refuse.

OpenID Connect Core defines a subject identifier as a locally unique and
never-reassigned identifier within the issuer for the end-user (Sakimura
et al., 2023). An exact `(identity_provider, subject)` pair is therefore
stronger evidence than an email string that may be unverified, recycled,
or typed by an operator.

NIST SP 800-63C-4 requires federation participants to treat assertion
attributes according to the federation assurance and attribute-validation
rules of the deployment; an RP or hub must not treat an unvalidated
attribute as proof of the same subscriber (Temoshok, Richer, et al.,
2025). SAML 2.0 likewise carries subject and attribute statements from an
asserting party; those statements are only as trustworthy as the
configured signature, issuer, and attribute contract (Cantor et al.,
2005). SCIM 2.0 can create or replace a User resource, including emails,
without proving mailbox control (Hunt, Grizzle, Ansari, et al., 2015;
Hunt, Grizzle, Wahlstroem, & Mortimore, 2015).

## Decision

Account matching precedence is exact `(identity_provider, subject)`, then
verified email under policy, then explicit operator link. Unverified email
never authorizes automatic linking or merge. Merged duplicate accounts
remain disabled tombstones with survivor lineage. This decision is shared
by account unification, federation, and SCIM so one path cannot weaken
another's identity evidence.

## Consequences

- Auto-link and merge APIs reject an unverified-email coincidence even
  when a caller sets `explicit_link=true` unless a stronger rule also
  holds; `allow_unverified_email_link` remains audit evidence and must
  stay false at startup.
- `trustEmail` on external IdP and LDAP sources defaults to false until
  the upstream verification contract is independently reviewed.
- SCIM provisioning must honor tombstone and survivor pointers so a later
  replace cannot resurrect a merged duplicate as a second live account.
- Email remains usable identity data under purpose-bound access control,
  encryption, and audit. This decision does not prescribe display masking.
- Orgmetra employment or org-tree identifiers are out of scope for this
  matcher; Keyverse does not copy those tables to invent a fourth
  precedence key.

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Cantor, S., Kemp, J., Philpott, R., & Maler, E. (Eds.). (2005).
*Assertions and protocols for the OASIS Security Assertion Markup Language
(SAML) V2.0*. OASIS.
https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015).
*System for Cross-domain Identity Management: Protocol* (RFC 7644).
https://doi.org/10.17487/RFC7644

Hunt, P., Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System for
Cross-domain Identity Management: Core schema* (RFC 7643).
https://doi.org/10.17487/RFC7643

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C.
(2023). *OpenID Connect Core 1.0 incorporating errata set 2*.
https://openid.net/specs/openid-connect-core-1_0.html

Temoshok, D., Richer, J. P., Choong, Y.-Y., Fenton, J. L., Lefkovitz, N.,
Regenscheid, A., & Galluzzo, R. (2025). *Digital identity guidelines:
Federation and assertions* (NIST SP 800-63C-4).
https://doi.org/10.6028/NIST.SP.800-63C-4
