# Federation Desired-State Reconciliation — Doctoring Record

## Decision

Keyverse reports a federation provider as applied only after a fresh Keycloak
identity-provider representation matches every desired observable field. The
one deliberate non-observable exception is the known `clientSecret` field when
Keycloak returns its fixed mask. This accepts the vendor read-back boundary but
does not claim plaintext secret equality. A missing secret, a different mask, an
unknown secret-bearing key, or any changed observable field remains drift.

## Evidence and limits

The repository regression test simulates the live read-back mask after a
successful OIDC provider mutation and verifies `applied_to_keycloak: true`.
Negative drift tests continue to reject missing providers, changed fields, and
unrecognized configuration. The Keycloak Admin REST contract identifies the
identity-provider instance representation used by this comparison; the mask
behavior is recorded here as measured adapter evidence, not as a broader
Keycloak conformance claim.

The comparison never logs or returns the configured secret. It only recognizes
the fixed mask for the single validated key, so the secret-management system
remains responsible for provisioning, rotation, and equality evidence.

## Reference — APA 7th

Keycloak. (n.d.). *Keycloak Admin REST API*. Retrieved August 22, 2026, from
https://www.keycloak.org/docs-api/latest/rest-api/index.html
