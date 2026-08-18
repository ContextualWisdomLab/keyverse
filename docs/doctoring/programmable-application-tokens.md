# Programmable Application Tokens — Evidence and Standards Doctoring

## Scope

This record documents the evidence used to define Keyverse programmable
application tokens. It does not claim OAuth access-token profile conformance
and does not treat a PAT as an OpenID Connect access token.

## Normative and authoritative evidence

RFC 6750 describes bearer credentials presented to a resource server (Jones
& Hardt, 2012). Keyverse stores only a SHA-256 hash and verifies equality
with a compare-digest so the secret is not reconstructed from storage.

NIST SP 800-63B distinguishes authenticators used to prove a subscriber
account from other secrets (Grassi et al., 2017). Password and WebAuthn
purposes are therefore forbidden. A PAT is a machine credential for a
software unit and API capability set, not a browser authenticator
(ADR-0002).

RFC 8725 warns against leaking tokens in logs and responses (Jones et al.,
2020). Issue returns plaintext once; list, get, verify, and revoke omit
both plaintext and hash.

## Stricter Keyverse policy

1. Closed purposes: `machine_api`, `integration_sync`, `operator_export`.
2. Lifetime bounded to 60 seconds–90 days.
3. At least one API capability is required.
4. Verification ignores org-tree grants; tokens never inherit.
5. Rotation revokes the previous hash and issues a replacement.

## Measured repository evidence

`services/account_unification/tests/test_application_tokens.py` covers issue,
verify, revoke, rotate, expiry, capability denial, software-unit mismatch,
password-purpose rejection, and secret omission.

## Assumptions and limitations

This slice does not replace confidential OIDC client-secret placement
(ADR-0005). Production API acceptance at each RP remains a separate
evidence boundary.

## References

Grassi, P. A., Garcia, M. E., & Fenton, J. L. (2017). *Digital identity
guidelines: Authentication and lifecycle management* (NIST Special
Publication 800-63B). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-63b

Jones, M. B., & Hardt, D. (2012). *The OAuth 2.0 authorization framework:
Bearer token usage* (RFC 6750). RFC Editor.
https://www.rfc-editor.org/rfc/rfc6750

Jones, M. B., Hardt, D., & Campbell, B. (2020). *JSON Web Token best current
practices* (BCP 225, RFC 8725). RFC Editor.
https://www.rfc-editor.org/rfc/rfc8725
