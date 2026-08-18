# Reference papers & standards

Primary sources the cwl-idp design leans on for **identity federation**,
**account linking**, and **SCIM provisioning**. Both are attached here for
offline reference.

## Attached

1. **NIST SP 800-63C — Digital Identity Guidelines: Federation and Assertions**
   (`nist-sp-800-63c-federation.pdf`). The normative reference for federated
   assertions, federation assurance levels (FAL), and identity-proofing vs.
   authentication separation. Grounds our decision to (a) federate the employer
   ADFS as an external assertion source rather than the hub, and (b) only
   auto-link on a *verified* attribute.

2. **RFC 7644 — System for Cross-domain Identity Management: Protocol**
   (`rfc7644-scim-protocol.txt`). The SCIM 2.0 protocol implemented by our
   Apache-2.0 SCIM v2 server shim (`/scim/v2/Users`) for inbound provisioning
   into Keycloak. Defines the resource operations (create/replace/patch/delete)
   upstream HR/IGA systems use to provision users.

## Citations

Full BibTeX in [`citations.bib`](./citations.bib).

- Grassi, P. A., Nadeau, E. M., Richer, J. P., et al. (2017). *Digital Identity
  Guidelines: Federation and Assertions.* NIST Special Publication 800-63C.
  National Institute of Standards and Technology.
  https://doi.org/10.6028/NIST.SP.800-63c
- Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015).
  *System for Cross-domain Identity Management: Protocol.* RFC 7644, IETF.
  https://doi.org/10.17487/RFC7644
- Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2014).
  *OpenID Connect Core 1.0.* OpenID Foundation. (Relying-party issuance;
  `account linking` via verified `email`/`sub` claims.)
- OASIS (2005). *Assertions and Protocols for the OASIS Security Assertion
  Markup Language (SAML) V2.0.* (Employer ADFS federation via SAML/WS-Fed.)
- Hu, V. C., Ferraiolo, D., Kuhn, R., Schnitzer, A., Sandlin, K., Miller, R.,
  & Scarfone, K. (2014). *Guide to Attribute Based Access Control (ABAC)
  Definition and Considerations.* NIST Special Publication 800-162.
  https://doi.org/10.6028/NIST.SP.800-162
- Grassi, P. A., Garcia, M. E., & Fenton, J. L. (2017). *Digital Identity
  Guidelines: Authentication and Lifecycle Management.* NIST Special
  Publication 800-63B. https://doi.org/10.6028/NIST.SP.800-63b
- Jones, M. B., & Hardt, D. (2012). *The OAuth 2.0 Authorization Framework:
  Bearer Token Usage.* RFC 6750, IETF. https://doi.org/10.17487/RFC6750

## How these map to the build

| Source | Where it shows up |
| --- | --- |
| NIST SP 800-63C | `docs/passwordless-policy.md`, verified-email auto-link rule in `app/matching.py` |
| RFC 7644 (SCIM) | SCIM v2 server shim `services/account_unification/app/scim.py` |
| OIDC Core | `deploy/templates/oidc-rp-client.json`, `docs/rp-onboarding.md`, start-login helper |
| SAML V2.0 | `deploy/templates/saml-idp-employer-adfs.json`, `docs/topology.md` |
| NIST SP 800-162 | hierarchical menu ABAC in `app/org_authorization.py` |
| NIST SP 800-63B / RFC 6750 | programmable application tokens in `app/application_tokens.py` |
