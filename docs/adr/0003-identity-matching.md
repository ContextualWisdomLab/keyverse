# ADR-0003: Use exact external subject, then verified email, then explicit link

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

One human can arrive through several sources: an employer SAML subject, an
external OIDC `sub`, a SCIM provisioned user, and a local passkey account.
OpenID Connect Core 1.0 requires a unique, never-reassigned `sub` issuer
subject and treats `email_verified` as a boolean that is true only when the
OpenID provider has verified control of the address (Sakimura et al., 2023).
SAML 2.0 name identifiers likewise identify a subject in a given issuer
namespace rather than a shared email string (OASIS Security Services Technical
Committee, 2005). NIST SP 800-63C-4 requires relying parties to treat
federation assertions as evidence about a specific federated identifier and
not to infer a new identity from an unverified attribute (Temoshok, Richer, et
al., 2025). SCIM's protocol and core schema identify users by a resource `id`
and optional external identifiers, not by an unconfirmed email coincidence
(Hunt, Grizzle, Ansari, et al., 2015; Hunt, Grizzle, Wahlstroem, & Mortimore,
2015).

Automatic merge on an unverified email would let an attacker bind a victim
account to an address they do not control. Identity fields used for matching
are therefore handled through purpose-bound access, encryption in transit and
at rest, and audit of privileged outcomes. They are not masked in a way that
would hide the exact subject or verified-email evidence required to decide a
link.

This ADR is a Keyverse evidence-precedence policy. It does not claim NIST
federation-assurance conformance.

## Decision

Account matching precedence is exact `(identity_provider, subject)`, then
verified email under policy, then explicit operator link. Unverified email
never authorizes automatic linking or merge. Merged duplicate accounts remain
disabled tombstones with survivor lineage. This decision is shared by account
unification, federation, and SCIM so one path cannot weaken another's identity
evidence.

## Consequences

- Exact external subject wins even when emails differ or are missing.
- Verified email may suggest a candidate only when both sides hold the same
  verified address and policy allows it.
- An operator link is an explicit privileged action and is audited.
- Unverified email never authorizes link or merge, including when a caller
  supplies an explicit-link flag.
- Tombstoned duplicates stay disabled and retain survivor lineage so later
  SCIM or login events cannot revive the wrong account.
- Account unification, federation onboarding, and inbound SCIM share this
  order. A later path cannot add a weaker automatic rule.

## References

Hunt, P. (Ed.), Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C.
(2015). *System for Cross-domain Identity Management: Protocol* (RFC 7644).
Internet Engineering Task Force. https://doi.org/10.17487/RFC7644

Hunt, P. (Ed.), Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System
for Cross-domain Identity Management: Core schema* (RFC 7643). Internet
Engineering Task Force. https://doi.org/10.17487/RFC7643

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
