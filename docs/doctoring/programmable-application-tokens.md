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

### One-event rotation metadata (private PR103 candidate)

Keyverse policy retains one successor-correlated `application_token_rotated`
event. The existing successor ID and active lifecycle fields remain unchanged.
`replaced_token_id` and `replaced_token_lifecycle_status_code` come from the
captured updated predecessor row already persisted by the successful conditional
cutover, rather than a later independent read. These IDs and state codes are
non-secret product data; no plaintext or hash is added. Both states describe
that historical cutover, not later lifecycle changes. This is a repository
policy, not an additional standards requirement; the existing confidentiality
and SQLite references above remain applicable.

`test_pat_rotation_audit_metadata.py` covers memory and real SQLite KV/audit
close/reopen, nonempty machine-capability positives, one-event cardinality,
unchanged issue/revoke shapes, exact predecessor-query limits, captured state
after independent retirement, and failed append with original-error and
conditional-compensation controls. The existing lifecycle/concurrency cohort
retains its schedules and assertions with only optional-keyword hook
compatibility. Generic `events_for` still selects only exact `audit_id`; adding
payload lineage does not repair predecessor lookup. Audit/KV non-atomicity and
append-then-error uncertainty are unchanged. Local evidence does not establish
whole-candidate review, protected integration, or deployed acceptance.

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

Python Software Foundation. (n.d.-a). *Built-in exceptions: Exception context*
(Python 3.12 documentation).
https://docs.python.org/3.12/library/exceptions.html#exception-context

Python Software Foundation. (n.d.-b). *Simple statements: The raise statement*
(Python 3.12 documentation).
https://docs.python.org/3.12/reference/simple_stmts.html#the-raise-statement

SQLite. (n.d.). *Transaction*. Retrieved October 5, 2026, from
https://www.sqlite.org/lang_transaction.html

Temoshok, D., Fenton, J., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A.,
Galluzzo, R., & Richer, J. (2025). *Digital identity guidelines:
Authentication and authenticator management* (NIST Special Publication
800-63B-4). National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-63b-4

## Explicit tenant-required PAT rotation lineage (private PR103 candidate)

`ApplicationTokenService.rotation_audit_for(token_id, tenant_deployment_id=tenant)`
reads historical rotations through a separate optional typed audit capability.
Both inputs are required exact strings: token IDs are `tok-` plus 16 lowercase
hex digits and tenants use the issuing service's slug grammar. The service does
not consult KV, mint credentials, append events, or expose an HTTP route.
Tenant scope restricts data; the shared operator boundary is not per-tenant
membership authorization. Stored actor metadata is not an authenticated human
principal. Future HTTP exposure requires a separately reviewed privileged route,
never runtime verification or the generic merge audit route.

Memory copies rotation rows under one lock. SQLite captures them with one bound
SELECT in physical append order. Both validate **every captured rotation before
selecting tenant or token**, deliberately failing all reads on a corrupt rotation
in any tenant. This is an explicit availability tradeoff, not per-tenant corruption
isolation. Malformed nonrotation JSON stays opaque under generic exact correlation.
Unknown keys, partial/null lineage, duplicate JSON keys, nonfinite constants and
scalar exponent overflow, invalid types and contradictory metadata fail closed.

Results are closed frozen DTOs with an ordered tuple of secret-free events and
an exact Boolean `predecessor_lookup_complete`. The current six-key legacy payload
projects as `legacy_missing` with null predecessor fields; any requested-tenant
legacy row makes completeness false, including on an empty/unrelated lookup.
Other-tenant legacy rows do not affect that flag. A modern row projects recorded
successor-active/predecessor-rotated historical states. Prefix, hash, plaintext,
capabilities and raw payload JSON are not projected. Allowed opaque actor/identifier
metadata is not a guarantee against a malicious caller placing secrets there.

Successor OR recorded predecessor matches once per physical row. A→B→C gives B
its two adjacent events, A and C only their adjacent event; no transitive walk or
correlation-ID deduplication occurs. Physical duplicates remain visible. Generic
`AuditSink` enumeration and `AuditLogger.events_for` exact bytes/semantics are
unchanged; rotation still appends only one successor-correlated event.

Custom reader output is revalidated at logger and service boundaries for exact
shape, event semantics, tenant, ID match and contradictory legacy completeness.
Those facades cannot prove a custom reader captured all unseen storage rows.
Unsupported readers and unavailable storage raise fixed typed errors, never empty
success. Errors omit raw driver/validation details and raw cause/context; this does
not claim erasure of temporary interpreter memory or traceback locals. BaseException
interruption is not caught.

A post-capture independent append appears on the next read, not the current one.
Instance locks do not lock independent connections/processes. Reads scan and
validate all stored rotations, O(rotation rows), without JSON1, DDL/index changes,
pagination, truncation, cache or a resource-bound promise. Completeness describes
legacy coverage of that captured set, not retention, audit loss, current validity,
or authenticated evidence. KV and audit remain non-atomic; a read between cutover
and append can return no row. Audit append-then-error and crash uncertainty remain.

The repository-discoverable `test_pat_rotation_audit_read.py` covers real memory
and SQLite close/reopen, actual service issue/rotate, query-before-access, strict
JSON/metadata, legacy/cross-tenant/facade controls, secret/error containment and
independent committed append barriers without sleeps. First-GREEN characterization
of already working boundaries is distinguished from reader behavioral RED→GREEN.
Local private results do not establish independent whole-union review, protected
integration, issuer acceptance or deployment readiness.

### Malformed reader-error and stored-envelope containment (F1/F2 successor)

The Python references describe exception semantics. This repair does not
assert a retrieval date or authenticate earlier handoff lookup claims. Those
claims are excluded. The measured local runtime is Python 3.12.13; the
regressions independently test the promised error containment.

A custom typed failure's code is read once inside an ordinary-Exception boundary.
Only an exact builtin string in the existing closed vocabulary is preserved;
missing, list/dict, str-subclass, unknown or failing-property codes become
`storage_unavailable`. The boundary does not inspect raw args, str or repr.
It constructs the fixed error only after the relevant handlers have exited,
with no original cause/context; `raise ... from None` alone would only suppress
context display, not erase that reference (Python Software Foundation, n.d.-a).
BaseException interruptions remain uncaught.

Memory validates exact AuditEvent class and exact-string event discriminator
before filtering; missing/failing/malformed discriminators fail as
`corrupt_rotation_event`, never a silently discarded row. The shared rotation
decoder acquires all seven stored envelope fields under a bounded shape guard
before strict payload/metadata validation. Missing fields and ordinary property
failures use the same fixed corruption error. Nonrotation payload JSON remains
opaque and generic audit enumeration is unchanged. Deliberate frozen-memory
object corruption is the tested boundary, not a claim of physical SQLite
corruption. Global rotation-before-tenant/token validation remains unchanged.

`test_pat_rotation_containment.py` retains direct logger/injected-service failure
regressions and valid-before-corrupt stored-memory controls. This successor does
not change service delegation, schema, KV, HTTP, issuer or PDP policy and requires
fresh independent whole-source review; local GREEN does not clear the retained
predecessor NONPASS or establish deployment/integration acceptance.
