# References for ADR 0001–0007

This file is the APA 7th bibliography for the expansions of the accepted
architecture decisions [`0001`](adr/0001-keycloak-hub.md)–[`0007`](adr/0007-automation-authority.md).
Every entry was opened on an official catalog (RFC Editor, OpenID Foundation,
W3C TR, OASIS, NIST CSRC / nvlpubs) before citation. Feature-specific
doctoring records under [`docs/doctoring/`](doctoring/) keep their own
bibliographies; do not treat this file as a rewrite of those records.

Internet-Drafts and W3C Candidate Recommendations are labeled as such and
are not treated as final RFCs or Recommendations.

## Official records

Cantor, S., Kemp, J., Philpott, R., & Maler, E. (Eds.). (2005, March 15).
*Assertions and protocols for the OASIS Security Assertion Markup Language
(SAML) V2.0* (OASIS Standard, document identifier saml-core-2.0-os).
Organization for the Advancement of Structured Information Standards.
https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

Denniss, W., & Bradley, J. (2017). *OAuth 2.0 for native apps* (BCP 212,
RFC 8252). Internet Engineering Task Force.
https://doi.org/10.17487/RFC8252

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
Internet Engineering Task Force. https://doi.org/10.17487/RFC6749

Harrison, R. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Authentication methods and security mechanisms* (RFC 4513). Internet
Engineering Task Force. https://doi.org/10.17487/RFC4513

Hodges, J., Jones, J. C., Jones, M. B., Kumar, A., & Lundberg, E. (Eds.).
(2021, April 8). *Web Authentication: An API for accessing Public Key
Credentials Level 2* (W3C Recommendation). World Wide Web Consortium.
https://www.w3.org/TR/2021/REC-webauthn-2-20210408/

Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015).
*System for Cross-domain Identity Management: Protocol* (RFC 7644).
Internet Engineering Task Force. https://doi.org/10.17487/RFC7644

Hunt, P., Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System for
Cross-domain Identity Management: Core schema* (RFC 7643). Internet
Engineering Task Force. https://doi.org/10.17487/RFC7643

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (BCP 240, RFC 9700). Internet Engineering
Task Force. https://doi.org/10.17487/RFC9700

OASIS Open. (2005, March 1). *Security Assertion Markup Language (SAML)
v2.0* [Standards catalog entry].
https://www.oasis-open.org/standard/saml/

Sakimura, N., Bradley, J., & Agarwal, N. (2015). *Proof key for code
exchange by OAuth public clients* (RFC 7636). Internet Engineering Task
Force. https://doi.org/10.17487/RFC7636

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C.
(2023, December 15). *OpenID Connect Core 1.0 incorporating errata set 2*.
OpenID Foundation. https://openid.net/specs/openid-connect-core-1_0.html

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol
(LDAP): The protocol* (RFC 4511). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4511

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software
Development Framework (SSDF) version 1.1: Recommendations for mitigating
the risk of software vulnerabilities* (NIST Special Publication 800-218).
National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-218

Temoshok, D., Fenton, J. L., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A.,
Galluzzo, R., & Richer, J. P. (2025). *Digital identity guidelines:
Authentication and authenticator management* (NIST Special Publication
800-63B-4). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-63B-4

Temoshok, D., Richer, J. P., Choong, Y.-Y., Fenton, J. L., Lefkovitz, N.,
Regenscheid, A., & Galluzzo, R. (2025). *Digital identity guidelines:
Federation and assertions* (NIST Special Publication 800-63C-4). National
Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-63C-4

Zeilenga, K. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
String representation of distinguished names* (RFC 4514). Internet
Engineering Task Force. https://doi.org/10.17487/RFC4514

## Vendor documentation (engine)

Keycloak. (n.d.). *Server administration guide* (Version 26.7.1). Retrieved
August 18, 2026, from https://www.keycloak.org/docs/latest/server_admin/

## Work in progress (not final)

Hardt, D., Parecki, A., & Lodderstedt, T. (2026, March 2). *The OAuth 2.1
authorization framework* (Internet-Draft draft-ietf-oauth-v2-1-15).
Internet Engineering Task Force.
https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/

World Wide Web Consortium. (2026, May 26). *Web Authentication: An API for
accessing Public Key Credentials Level 3* (W3C Candidate Recommendation
Snapshot). https://www.w3.org/TR/webauthn-3/

OAuth 2.1 remains an IETF Working Group Internet-Draft (IESG state:
I-D Exists; intended RFC status unset). WebAuthn Level 3 is a Candidate
Recommendation Snapshot, not a W3C Recommendation. Neither is cited as a
normative final record in ADR 0001–0007.

## Catalog notes

NIST SP 800-63B and SP 800-63C (June 2017; updated 2 March 2020) were
withdrawn on 1 August 2025 and superseded by SP 800-63B-4 and SP 800-63C-4
(Final 31 July 2025). This bibliography cites the current finals opened at
https://csrc.nist.gov/pubs/sp/800/63/b/4/final,
https://csrc.nist.gov/pubs/sp/800/63/c/4/final,
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf,
and
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63C-4.pdf.
Offline attachments under [`docs/papers/`](papers/README.md) may still
hold the withdrawn 2017 texts; ADR 0001–0007 use the 2025 finals.
