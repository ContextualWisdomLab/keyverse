# Programmable Application Tokens — Evidence and Standards Doctoring

## Scope

This record documents the evidence used to define Keyverse programmable
application tokens. It does not claim OAuth access-token profile conformance
and does not treat a PAT as an OpenID Connect access token.

## Normative and authoritative evidence

RFC 6750 describes bearer credentials presented to a resource server (Jones
& Hardt, 2012). Keyverse stores only a SHA-256 hash and verifies equality
with a compare-digest so the secret is not reconstructed from storage.

NIST SP 800-63B-4 distinguishes authenticators used to prove a subscriber
account from other secrets (Temoshok et al., 2025). Password and WebAuthn
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
5. Rotation accepts only an active, unexpired predecessor, validates the
   replacement settings before revoking its hash, and issues a replacement
   bound to the same software unit. The replacement and rotated predecessor
   are persisted through an exact-state conditional KV batch, requiring an
   absent replacement. Audit failure restores only the still-current written
   generation, never an independent retirement. Unique lifecycle generation
   IDs prevent same-clock retirement ABA. Revoked, rotated, expired, and stale
   predecessors fail closed with a conflict response.

SQLite permits only one writer transaction and `BEGIN IMMEDIATE` starts that
writer before expected-state reads (SQLite, n.d.). The adapter uses that short
transaction with the existing busy timeout; no audit callback runs under its
writer lock. Memory uses one store lock. This is a repository policy and
measured local storage boundary, not atomic database-plus-external-audit commit.

## Measured repository evidence

`services/account_unification/tests/test_application_tokens.py` covers issue,
verify, revoke, rotate, expiry, capability denial, software-unit mismatch,
password-purpose rejection, secret omission, preservation of the active token
after invalid rotation settings, and compensation after injected KV or audit
failure, including one atomic store write for rotation. Management and runtime
router authentication are tested separately. The SQLite adapter also covers
atomic replacement of one record and deletion of another.
Tenant mismatch, direct router embedding, and retired-predecessor rejection are
also covered. `test_pat_lifecycle_concurrency.py` adds shared-memory and two-real-
SQLite-connection rotation/rotation barriers, completed revoke before commit,
independent revoke/rotation during audit, same-clock ABA, expected-absent ID
collisions, legacy row compatibility, and original-error preservation.
`test_pat_conditional_storage.py` adds exact-state conflicts and actual SQLite
trigger-abort rollback. First-GREEN boundary controls are not credited as RED.

### Request-validation confidentiality repair (private PR103 candidate)

FastAPI documents `RequestValidationError` for invalid request data and notes
that the exception retains the received body (FastAPI, n.d.-a). Its supported
`APIRoute.get_route_handler` wrapper can contain validation around the original
handler (FastAPI, n.d.-b). These are framework behavior references, not proof of
Keyverse deployment acceptance.

Keyverse policy for `POST /application-tokens:verify` is stricter: every request
schema failure returns HTTP 422 with only the fixed detail string
`Invalid application token verification request`. The runtime router owns this
boundary, including direct and prefix-nested embedding; the application factory
needs no global exception handler. The wrapper never reads, formats, logs, or
serializes exception errors or the body. It does not expose `input`, `loc`,
`msg`, `ctx`, or arbitrary submitted keys. Authentication HTTP errors, semantic
policy failures, unreadable-body HTTP 400, service failures, response validation,
and unrelated routers retain their existing behavior. This does not redact
caller/host middleware that independently records raw requests.

`test_application_token_validation.py` uses actual SQLite and TestClient at
both factory and embedded boundaries. It pairs a minted-token active/secret-free
positive with container/length/null failures, missing fields, unknown names and
secret-bearing unknown keys, arbitrary tenant/software/capability values, and
malformed JSON. It also characterizes authentication, nested embedding, host
exception-handler isolation, and service/response-error preservation. The
original reviewer assertion failed before the route repair and passed after it.
This boundary requires whole-candidate execution and independent review;
local results are not deployment or protected-merge acceptance.

## Assumptions and limitations

This slice does not replace confidential OIDC client-secret placement
(ADR-0005). Production API acceptance at each RP remains a separate
evidence boundary. Audit and KV remain separate durable systems. If every
conditional cleanup attempt fails due to a storage outage, an undisclosed new
hashed row may remain active; its plaintext is not returned. Wait until both
KV writes and audit appends recover before revoking a stranded ID through the
existing operator route. If the audit append still fails, revoke compensation
can restore the active row. After a successful revoke, re-observe the persisted
lifecycle and its audit event before declaring recovery. Do not reissue or rotate
to hide unresolved state. Storage-only recovery does not establish retirement.
No crash-safe audit outbox or
cross-system atomicity is claimed. Mixed old/new lifecycle writers are unsafe;
all writers must use this conditional contract before concurrent service use.

## References

The three undated framework/storage pages below were rechecked on October 5, 2026 (KST).
This is a successor source check, not attestation of the original candidate's retrieval chronology.

FastAPI. (n.d.-a). *Handling errors*. Retrieved October 5, 2026, from
https://fastapi.tiangolo.com/tutorial/handling-errors/

FastAPI. (n.d.-b). *Custom request and APIRoute class*. Retrieved October 5,
2026, from https://fastapi.tiangolo.com/how-to/custom-request-and-route/

Jones, M. B., & Hardt, D. (2012). *The OAuth 2.0 authorization framework:
Bearer token usage* (RFC 6750). RFC Editor.
https://www.rfc-editor.org/rfc/rfc6750

Jones, M. B., Hardt, D., & Campbell, B. (2020). *JSON Web Token best current
practices* (BCP 225, RFC 8725). RFC Editor.
https://www.rfc-editor.org/rfc/rfc8725

SQLite. (n.d.). *Transaction*. Retrieved October 5, 2026, from
https://www.sqlite.org/lang_transaction.html

Temoshok, D., Fenton, J., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A.,
Galluzzo, R., & Richer, J. (2025). *Digital identity guidelines:
Authentication and authenticator management* (NIST Special Publication
800-63B-4). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-63b-4
