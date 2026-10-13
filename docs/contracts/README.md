# Keyverse consumer contracts

This directory holds versioned contracts that relying parties may consume
without copying Keyverse source.

## `keyverse.subject-assertion/v1`

Use this contract when your application wants to store a Keyverse user's
`(issuer, subject)` as a long-lived link to one of your records.

| File | Purpose |
|---|---|
| `subject-assertion-v1.schema.json` | JSON Schema 2020-12 for the verifier receipt. |
| `subject-assertion-v1.fixtures.json` | Signed conformance cases with expected receipts. The signing key is throwaway test material. |

The reference verifier is
`services/account_unification/app/subject_assertion.py`. Decision record:
[ADR-0020](../adr/0020-subject-assertion-trust-contract.md).

### How to consume

1. Configure a profile with the exact issuer, your client ID as audience, the
   allowed algorithms, the realm's public JWK Set, the subject type, and
   `org` when your application is tenant-scoped. List any other audience you
   accept in `trusted_additional_audiences`; every unlisted extra audience is
   rejected (OIDC Core §3.1.3.7). Load the JWK Set from your
   deployment configuration. The verifier does not fetch it.
2. Verify each ID token after the authorization-code exchange. Pass the
   `nonce` you sent in the authorization request as `expected_nonce`.
3. Persist a binding only when `outcome == "verified"` and
   `correlation == "durable"`. Use `correlation_key` as the lookup key.
4. When `correlation == "session_only"`, authenticate the session but do not
   store the subject.
5. Treat every `rejected` receipt as no authentication. Use `reason` for
   metrics and support, not for authorization.
6. Apply your own tenant membership, resource, and role checks after
   verification (ADR-0008). A verified receipt is not authorization.

### Conformance in another language

Load `subject-assertion-v1.fixtures.json`, build the profile from its
`profile` member, verify each `token` at time `now`, and compare your receipt
with `expected_receipt`. Every case must match exactly.

### Current limits

- `v1` is published from repository source only. No immutable release,
  digest, SBOM, or provenance exists yet (#155, #158).
- The fixtures prove decision equivalence. They do not prove that a live
  Keycloak deployment issues tokens with this exact shape.
