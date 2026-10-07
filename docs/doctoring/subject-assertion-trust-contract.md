# Subject-assertion trust contract — doctoring record

## Scope

This record supports ADR-0020 and issue #155. It explains how the
`keyverse.subject-assertion/v1` verifier maps primary standards and Keycloak
behavior to rules. It covers an offline verifier for one signed OpenID Connect
ID token. It does not claim OpenID Certification, live Keycloak token
acceptance, or a released artifact.

## Evidence categories

- **Standard**: normative text in a primary standard.
- **Vendor**: documented or source-code behavior of Keycloak.
- **Policy**: a Keyverse choice that a standard permits but does not require.
- **Inference**: a conclusion derived from the sources above.
- **Unverified**: a claim that the retrieval could not confirm.

## Rule map

| Verifier rule | Class | Basis |
|---|---|---|
| Exactly three base64url segments, strict JSON objects, no duplicate member names | Standard | RFC 7515 §5.2 step 4 |
| `alg` is in the pinned subset of `ES256`/`RS256`; each key is bound to one algorithm; `none` and HMAC are refused | Standard + Policy | RFC 8725 §3.1, §3.2; RFC 7518 §3.6 |
| Only `alg`, `typ`, and `kid` header members are accepted; `crit`, `jku`, `x5u`, `jwk`, and `x5c` reject | Standard + Policy | RFC 7515 §4.1.11 and App. E; OIDC Core §2 ("SHOULD NOT use"); RFC 8725 §3.10 |
| `typ` is absent or the `application/jwt` media type, compared case-insensitively with an implied `application/` prefix | Standard + Inference | RFC 7515 §4.1.9; RFC 8725 §3.11–§3.12; RFC 9068 §2.1, §4 |
| Keycloak payload `typ`, when present, must be `ID` | Vendor | Keycloak `TokenUtil.TOKEN_TYPE_ID = "ID"` |
| ES256 signature is exactly 64 octets (R‖S) | Standard | RFC 7518 §3.4 |
| `iss` equals the pinned issuer exactly | Standard | OIDC Core §3.1.3.7 |
| `aud` contains the RP; every other audience must be explicitly trusted by the profile; several audiences require `azp`; `azp`, when present, equals the RP | Standard + Policy | OIDC Core §2, §3.1.3.7; RFC 8725 §3.9 |
| `exp` and `iat` required as integer NumericDates; optional `nbf`; one leeway of 0–300 s (default 60 s) | Standard + Policy | RFC 7519 §4.1.4–§4.1.6; OIDC Core §2 |
| `sub` is a non-empty string of at most 255 characters with no control characters | Standard + Policy | OIDC Core §2 |
| Durable identity key covers `(iss, sub)` plus audience and tenant | Standard + Inference | OIDC Core §5.7, §8 |
| `public`/`pairwise` → `durable`; `ephemeral` → `session_only` | Standard + Inference | OIDC Core §8; OIDC Ephemeral Subject Identifier 1.0 Draft 03 §1, §4, §7 |

## Interpretation notes

### Audience

OIDC Core §3.1.3.7 says the ID token "MUST be rejected if the ID Token does
not list the Client as a valid audience, or if it contains additional
audiences not trusted by the Client." The first candidate accepted any extra
audience when `azp` named the RP. That was a false admission. The verifier now
accepts an extra audience only when the deployment lists it in
`trusted_additional_audiences`. Strict `azp` equality is a policy choice:
Core says the client "SHOULD verify" it.

### Token type

RFC 7515 §4.1.9 states that media type values are case-insensitive and that a
recipient "MUST treat it as if "application/" were prepended to any "typ" value
not containing a '/'". The verifier therefore accepts `JWT`, `jwt`, and
`application/jwt`. Keycloak 26 source (`DefaultTokenManager`) writes `JWT` for
ID tokens and, by default, for access tokens too; `at+jwt` appears only when the
26.2.0 client flag is enabled. So `typ` cannot separate the token kinds alone
(RFC 8725 §3.11 makes the same point). The audience pin and the Keycloak
payload `typ` value `ID` are the stronger separators.

### Subject stability and correlation

OIDC Core §5.7 says `iss` and `sub` "used together, are the only Claims that an
RP can rely upon as a stable identifier". §8 defines `public` and `pairwise`
subjects as locally unique and never reassigned; a pairwise `sub` is stable
only for one client, so the correlation key includes the audience. The
Ephemeral Subject Identifier draft (§4) defines `ephemeral` as a `sub` that
"is different for every authentication request" and warns (§7) that a
collision can cause "account mix-up". The verifier therefore never returns a
durable key for an ephemeral profile. The subject type is declared by the
deployment profile, because the verifier does not read discovery.

### Status of the Ephemeral Subject Identifier specification

The retrieved specification is Draft 03 (10 July 2026). The OpenID Foundation
public review ran from 17 July to 15 September 2026 and the final vote from 16
to 30 September 2026. **Unverified:** no retrieved primary source announced the
vote result. Cite Draft 03 until an approval notice is retrieved. The verifier
rule does not depend on the result.

### Keycloak algorithm support

Keycloak 26.8.0 source sets `DEFAULT_SIGNATURE_ALGORITHM = RS256`, and
`GeneratedEcdsaKeyProviderFactory` maps P-256 to `ES256`. **Unverified:** no
prose documentation sentence states the ID-token `typ` value; the evidence is
source code at tag 26.8.0.

### Independent adversarial review

An independent reviewer ran hostile probes against the candidate. Each
confirmed finding was reproduced first as a failing repository test and then
repaired:

| Finding | Class | Repair |
|---|---|---|
| A signed lone-surrogate `nonce` raised `UnicodeEncodeError` | Inference | Decoded JSON is re-encoded as strict UTF-8; failure is `malformed_token` |
| A NaN `now` turned off every time check | Inference | `now` must be a non-boolean integer, else `TypeError` |
| Editing `trusted_keys` after construction did not revoke a key | Policy | The profile stores a read-only deep copy; rotation builds a new profile |
| UTF-16 and BOM payloads were accepted | Standard + Policy (RFC 8259 §8.1: JSON exchanged between systems "MUST be encoded using UTF-8"; a parser "MAY ignore" a byte order mark, so rejecting it is policy) | Strict `bytes.decode("utf-8")` before parsing |
| Invisible or padded `sub`/`org` characters were accepted | Policy | Unicode categories Cc, Cf, Cs, Zl, and Zp and edge whitespace are refused |
| Several base64url spellings verified as one token | Standard (RFC 4648 §3.5: "decoders MAY chose to reject an encoding if the pad bits have not been set to zero") | Canonical re-encoding is required |
| Unbounded or inverted NumericDates were accepted | Policy | 0..2^53-1 and `exp >= iat` |
| Profile gaps: list algorithm, issuer whitespace or bad port, unchecked extra audiences, RSA e=3 or very large n, padded EC coordinates, non-verify `key_ops` | Policy (the 2048–8192-bit and e≥65537 bounds are Keyverse choices; RFC 7518 §3.3 sets only the 2048-bit minimum) | Construction raises `ValueError` |
| Schema accepted a 64-hex key with a trailing newline | Inference | `minLength`/`maxLength` 64 |
| Fixtures lacked the audience and `typ` rules | Inference | New catalog cases and the `trusted_additional_audiences` profile member |

The reviewer also confirmed correct behavior for deep JSON nesting, very large
integers, malformed ECDSA/RSA signatures, off-curve EC keys, invalid RSA
exponents, unhashable header values, and the audience and `typ` rules. The
reviewer's probes are evidence for this candidate only; they are not a
substitute for a hosted security scan.

## Residual assumptions

- A deployment supplies the realm public JWK Set out of band and rotates it by
  profile change.
- The verifier is evaluated against synthetic tokens. A controlled Keycloak
  login that produces a real ID token for this verifier is still required.

## Retrieval ledger

| Source | URL | Retrieved | SHA-256 prefix |
|---|---|---|---|
| OIDC Core 1.0 (errata set 2) | https://openid.net/specs/openid-connect-core-1_0.html | 2026-10-06 | 4d016752a645e8a3 |
| OIDC ESID 1.0 Draft 03 (HTML) | https://openid.net/specs/openid-connect-ephemeral-subject-identifier-1_0.html | 2026-10-06 | 918ed24e90e661c3 |
| OIDC ESID 1.0 Draft 03 (MD) | https://openid.net/specs/openid-connect-ephemeral-subject-identifier-1_0.md | 2026-10-06 | bba8881b5fa77d5e |
| OIDF public review notice | https://openid.net/public-review-period-for-proposed-openid-connect-ephemeral-subject-identifier-1-0-final-specification/ | 2026-10-06 | 61740a02e5f894e6 |
| OIDF notice of vote | https://openid.net/notice-of-vote-for-proposed-openid-connect-ephemeral-subject-identifier-1-0-final-specification/ | 2026-10-06 | 8c58791f4e1b161c |
| OIDF news list | https://openid.net/news/ | 2026-10-06 | 091e52a52abf7f9f |
| OIDF spec directory | https://openid.net/specs/ | 2026-10-06 | bcf3535c410bdb41 |
| OIDF tag / category pages | https://openid.net/tag/spec-announcement/ ; https://openid.net/category/final-specification/ | 2026-10-06 | — |
| RFC 7515 | https://www.rfc-editor.org/rfc/rfc7515.txt | 2026-10-06 | ecbf84674118e625 |
| RFC 7517 | https://www.rfc-editor.org/rfc/rfc7517.txt | 2026-10-06 | 681c19b92a850687 |
| RFC 7518 | https://www.rfc-editor.org/rfc/rfc7518.txt | 2026-10-06 | 9a9ae524b09ea700 |
| RFC 7519 | https://www.rfc-editor.org/rfc/rfc7519.txt | 2026-10-06 | fecd930e9ccf2276 |
| RFC 7638 | https://www.rfc-editor.org/rfc/rfc7638.txt | 2026-10-06 | 98b29ab9652070e6 |
| RFC 8725 | https://www.rfc-editor.org/rfc/rfc8725.txt | 2026-10-06 | 737b7013a2495dcf |
| RFC 9068 | https://www.rfc-editor.org/rfc/rfc9068.txt | 2026-10-06 | 68d3ff3910c0f234 |
| RFC 8259 | https://www.rfc-editor.org/rfc/rfc8259.txt | 2026-10-06 | 61a5378f4255c720 |
| RFC 4648 | https://www.rfc-editor.org/rfc/rfc4648.txt | 2026-10-06 | 84e14418f795d503 |
| Keycloak Server Admin Guide | https://www.keycloak.org/docs/latest/server_admin/index.html | 2026-10-06 | 4c751f93f7fb9e6d |
| Keycloak Release Notes | https://www.keycloak.org/docs/latest/release_notes/index.html | 2026-10-06 | 8500c2e4f82b9c77 |
| Keycloak DefaultTokenManager @26.8.0 | https://raw.githubusercontent.com/keycloak/keycloak/26.8.0/services/src/main/java/org/keycloak/jose/jws/DefaultTokenManager.java | 2026-10-06 | 12c92e247041db96 |
| Keycloak GeneratedEcdsaKeyProviderFactory @26.8.0 | https://raw.githubusercontent.com/keycloak/keycloak/26.8.0/services/src/main/java/org/keycloak/keys/GeneratedEcdsaKeyProviderFactory.java | 2026-10-06 | 67c8aff25c6a9cc6 |
| Keycloak TokenUtil @main | https://raw.githubusercontent.com/keycloak/keycloak/main/core/src/main/java/org/keycloak/util/TokenUtil.java | 2026-10-06 | 8d7cfc6d5892a8db |
| Keycloak Constants @26.8.0 | https://raw.githubusercontent.com/keycloak/keycloak/26.8.0/server-spi-private/src/main/java/org/keycloak/models/Constants.java | 2026-10-06 | (grep only) |


## References

Bertocci, V. (2021). *JSON Web Token (JWT) profile for OAuth 2.0 access tokens* (RFC 9068). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9068

Bray, T. (Ed.). (2017). *The JavaScript Object Notation (JSON) data interchange format* (RFC 8259; STD 90). Internet Engineering Task Force. https://doi.org/10.17487/RFC8259

Josefsson, S. (2006). *The Base16, Base32, and Base64 data encodings* (RFC 4648). Internet Engineering Task Force. https://doi.org/10.17487/RFC4648

Jones, M. (2015a). *JSON Web Algorithms (JWA)* (RFC 7518). Internet Engineering Task Force. https://doi.org/10.17487/RFC7518

Jones, M. (2015b). *JSON Web Key (JWK)* (RFC 7517). Internet Engineering Task Force. https://doi.org/10.17487/RFC7517

Jones, M., Bradley, J., & Sakimura, N. (2015a). *JSON Web Signature (JWS)* (RFC 7515). Internet Engineering Task Force. https://doi.org/10.17487/RFC7515

Jones, M., Bradley, J., & Sakimura, N. (2015b). *JSON Web Token (JWT)* (RFC 7519). Internet Engineering Task Force. https://doi.org/10.17487/RFC7519

Jones, M., & Sakimura, N. (2015). *JSON Web Key (JWK) thumbprint* (RFC 7638). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc7638

Keycloak. (n.d.-a). *Release notes* [Keycloak 26.2.0 section: "New client configuration for access token header type"]. Retrieved October 6, 2026, from https://www.keycloak.org/docs/latest/release_notes/index.html

Keycloak. (n.d.-b). *Server administration guide* (Version 26.8.0). Retrieved October 6, 2026, from https://www.keycloak.org/docs/latest/server_admin/index.html

Keycloak. (2026). *DefaultTokenManager.java* (Version 26.8.0) [Source code]. GitHub. https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/jose/jws/DefaultTokenManager.java

Keycloak. (2026). *GeneratedEcdsaKeyProviderFactory.java* (Version 26.8.0) [Source code]. GitHub. https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/keys/GeneratedEcdsaKeyProviderFactory.java

OpenID Foundation. (2026a, July 17). *Public review period for proposed OpenID Connect Ephemeral Subject Identifier 1.0 Final Specification*. https://openid.net/public-review-period-for-proposed-openid-connect-ephemeral-subject-identifier-1-0-final-specification/

OpenID Foundation. (2026b, September 2). *Notice of vote for proposed OpenID Connect Ephemeral Subject Identifier 1.0 Final Specification*. https://openid.net/notice-of-vote-for-proposed-openid-connect-ephemeral-subject-identifier-1-0-final-specification/

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2023). *OpenID Connect Core 1.0 incorporating errata set 2*. OpenID Foundation. https://openid.net/specs/openid-connect-core-1_0.html

Sakimura, N., & Jay, E. (2026). *OpenID Connect Ephemeral Subject Identifier 1.0 – Draft 03*. OpenID Foundation. https://openid.net/specs/openid-connect-ephemeral-subject-identifier-1_0.html

Sheffer, Y., Hardt, D., & Jones, M. (2020). *JSON Web Token best current practices* (RFC 8725; BCP 225). Internet Engineering Task Force. https://doi.org/10.17487/RFC8725
