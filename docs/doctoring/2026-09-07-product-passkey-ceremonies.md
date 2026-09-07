# Product-rendered passkey ceremonies: proposal evidence

## Observed boundary, 2026-09-07

Protected Keyverse `main` was
`7d9151cd2da260e118020c938c7358e2ee75d541`. PR #128 was a draft at
`e1cf0807d6b15e8d8300eb252533aa05b20b93c9`, stacked on
`codex/keyverse-orchestrator-free-development` at
`e6da5dd3762b45acf4e0a70b672327f38f4ba04b`. Its unavailable password route
does not implement product-rendered authentication. The existing passwordless
registration initializes issuer-rendered email verification and WebAuthn
required actions. No product ceremony API or provider module was found in
that source tree.

Read-only `kc.sh --version` inside the existing Colima services reported
Keyverse's owner engine as **26.3.2** and the separate LineageWeave engine as
**26.0.8**. No service was restarted or reconfigured for this research. A
running version is not immutable release, authenticated acceptance, or proof
that the two deployments may be consolidated safely. Docker could not inspect
the image at the running owner's recorded image ID; a rebuild or restart
therefore also needs a reproducible image/rollback receipt first.

## Numbering and acceptance correction

A complete open-PR file inventory found that PR #129 proposes ADRs
0014–0016 and PR #130 separately proposes another ADR 0014. PR #128's
password proposals therefore move from 0014/0015 to **0017/0018**, with
cross-references updated and original history retained. ADR **0019** records
the product-rendered passkey direction. These numbers were unused in the
observed open-PR inventory; recheck before integration. The separate
#129/#130 numbering conflict remains outside this PR's correction.

The former Accepted labels did not prove owner acceptance: all these PR #128
records remain **Proposed**. The historical proposals and their standards
corrections are retained; no password grant or credential-issuance capability
is enabled by changing documentation.

## Standards and vendor evidence

| Source | What it establishes | What it does not establish |
|---|---|---|
| RFC 9700 §2.4 and RFC 10017 §7.3 | Password grants must not be used for this browser OAuth path; a redirect-based code flow is the selected alternative. | That a product's custom ceremony extension is secure or implemented. |
| WebAuthn Level 2 §4 and §7 | Credential scope and origin/RP-ID checks constrain where a product can invoke a credential. | Automatic portability of issuer-scoped credentials to unrelated product domains. |
| Keycloak server development guide | REST, Authentication, Required Action, and Action Token extension points exist; extensions are version-coupled. | A released JSON challenge/completion API or compatibility between the current guide and 26.3.2. |
| Keycloak 26.3.2 source | `WebAuthnAuthenticator` prepares authentication input and delegates validation to the credential manager; `WebAuthnRegister` performs registration validation and storage. | A supported way to replace the expected issuer origin merely by wrapping the HTML flow. |
| NIST SP 800-63B-4 §4.2 | Recovery methods, proof combinations, throttling, consumption, and notifications must be designed explicitly. | Keyverse certification, an existing lost-only-passkey recovery service, or approval to recover from email matching alone. |

The new provider is an engineering inference from those interfaces. Its first
acceptance experiment must prove native-verifier reuse at the actual product
origin and normal authorization-code issuance. If that experiment requires
new credential-scope persistence or a missing engine extension point, record
that owner decision before implementation instead of copying a verifier or
weakening origin checks.

Context7 returned a quota error; it supplied no documentation evidence.
Primary sources and the versioned engine source were used instead. No live
credential, account body, or private source record was captured.

## Verification status and next executable work

This change only renumbers/corrects proposals and records the contract in
[ADR 0019](../adr/0019-product-owned-passkey-ceremonies.md). The authoritative
negative cases and release sequence live in its Confirmation section.
There is no ceremony implementation, runtime login, recovery, consumer UI,
coverage improvement, protected merge, or release result to report here.

The next owner implementation is a version-pinned provider with one real
login start/complete experiment, followed by signup and recovery. Keep every
existing runtime and disabled password route unchanged until those gates pass.
Consumer delivery remains required in LineageWeave and Naruon after owner
release; a proposal or a successful issuer-page redirect is insufficient.

## References (APA 7th)

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current practice for
OAuth 2.0 security* (RFC 9700). https://www.rfc-editor.org/rfc/rfc9700.html

Parecki, A., De Ryck, P., & Waite, D. (2026). *OAuth 2.0 for browser-based
applications* (RFC 10017). https://www.rfc-editor.org/rfc/rfc10017.html

Hodges, J., Jones, J. C., Jones, M. B., Kumar, A., & Lundberg, E. (Eds.).
(2021). *Web Authentication: An API for accessing Public Key Credentials
Level 2*. World Wide Web Consortium. https://www.w3.org/TR/webauthn-2/

Keycloak. (n.d.). *Server developer guide* (26.7.3; retrieved September 7,
2026). https://www.keycloak.org/docs/latest/server_development/index.html

Keycloak. (n.d.). *WebAuthnAuthenticator* [Source code, version 26.3.2].
https://github.com/keycloak/keycloak/blob/26.3.2/services/src/main/java/org/keycloak/authentication/authenticators/browser/WebAuthnAuthenticator.java

Keycloak. (n.d.). *WebAuthnRegister* [Source code, version 26.3.2].
https://github.com/keycloak/keycloak/blob/26.3.2/services/src/main/java/org/keycloak/authentication/requiredactions/WebAuthnRegister.java

Temoshok, D., Fenton, J. L., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A.,
Galluzzo, R., & Richer, J. P. (2025). *Digital identity guidelines:
Authentication and authenticator management* (NIST SP 800-63B-4).
https://doi.org/10.6028/NIST.SP.800-63B-4
