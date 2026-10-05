# Authorization-plane operations

## When to use this runbook

Use this procedure after Orgmetra assignment data is available and the
Keyverse operator token is in the deployment secret store. It covers grant
changes, start-login troubleshooting, and PAT rotation. It does not replace
federation or RP desired-state apply.

The authorization router enforces the operator bearer and privileged path
checks at its own module boundary. A parent application may embed the router,
but must still provide the configured operator token; `actor_identity_id` in a
grant is administrative policy metadata, not a caller identity derived from a
shared operator bearer.

## PAT verification schema errors

The runtime verification router returns a fixed HTTP 422 detail for invalid
request schemas. The response does not echo submitted keys, values, token
material, or validation locations. Direct router embedding retains this boundary.
An outer caller must still avoid recording raw request bodies in its middleware.
Authentication errors and semantic service errors keep their existing meaning.

## Persist grants

1. Confirm the org path is contiguous from `group_company`.
2. Put the explicit `tenant_deployment_id` on the snapshot and every grant.
3. PUT the software-unit grant, then any menu grants.
4. Decide with a current Orgmetra snapshot. If the effect is unexpected,
   inspect winning_org_path, winning_menu_path, `inherited`, and whether a
   more-specific deny exists. `inherited=true` means the winning org path or
   menu path is a strict ancestor of the requested path. For menu decisions,
   menu-path specificity is evaluated before org-path specificity.
5. Do not persist Orgmetra organization units into Keyverse.

When the same grant key or combination name exists in more than one tenant,
include `tenant_deployment_id` as the GET/DELETE query parameter; an ambiguous
administration operation fails closed. The query value is validated before the
tenant-qualified KV record is selected.

## Menu and SSO read coherence

A menu decision captures both grant namespaces in one read before validation.
An SSO-combination decision captures combination definitions and software-unit
grants together through the same coherent read seam. All captured rows are
validated before the unchanged PDP, including unrelated names and tenants;
do not bypass corrupt rows by filtering them first. Validated name/tenant
selection retains HTTP 404 for missing and HTTP 409 for ambiguous combinations.
An independent SQLite writer can commit during a read without mixing new rows
with old rows from the other requested namespace. An already captured coherent
allow can still be returned after a concurrent revocation; the next fresh read
sees the committed revocation. Do not treat this as operation cancellation.

Separate PUT requests remain separate transactions: this read seam does not
make a multi-request grant rollout atomic or supply a monotonic revision.
Custom KV implementations must implement `get_all_namespaces` as one coherent
read, not a loop over independently visible `get_all` calls. Restore corrupt
rows rather than dropping them to obtain an allow. Current Orgmetra membership,
issuer validation, RP enforcement, and durable write-intent remain separate.

## Start-login failures

- Empty `identity_providers`: the local federation registry has no enabled
  IdP. Register one through desired state; do not point the helper at a
  discovery URL.
- HTTP 404 on `provider_alias_hint`: the alias is missing or disabled.
- Multiple providers and a null `start_login_url`: supply an explicit hint.
- Never treat a green start-login response as production login acceptance.

## PAT rotation

Rotation is a server-side credential cutover: after a successful rotate
response, the predecessor is already retired and the replacement plaintext is
the only usable new secret. The application secret manager therefore has to be
ready before the request is sent.

1. Preflight the target secret-manager entry and confirm the operator can write
   and immediately read back a non-sensitive probe or otherwise use the secret
   manager's supported readiness check. Do not rotate while the destination is
   unavailable or read-only.
2. POST `/application-tokens/{id}:rotate` with the same software unit and
   explicit tenant. If validation returns HTTP 400, correct the replacement
   settings; the old token remains active and must not be discarded.
3. On success, capture the returned replacement `application_token_id` and
   plaintext in a protected process-local response and write the plaintext to
   the application secret manager immediately. A successful server response
   means the predecessor has already transitioned to the rotated state; do not
   describe or operate this as a client-side "store then retire" sequence.
4. If the first secret-manager write fails but the protected response is still
   available, retry the write without logging or reprinting the plaintext. If
   the plaintext is lost or cannot be placed safely, issue a **new** token with
   the same reviewed tenant/software-unit/purpose/capabilities, store that new
   plaintext, verify it, and revoke the stranded replacement by its returned
   token ID. Do not attempt to rotate the already retired predecessor again.
5. Confirm the predecessor verifies as `revoked_token` and the credential now
   stored by the application verifies as active. Rotation persists predecessor
   and replacement through one conditional KV-store transaction. A stale
   snapshot returns HTTP 409 before audit. Audit failure restores only the
   exact current written generation; a concurrent retirement instead keeps
   the predecessor retired and conditionally removes the owned replacement.
   Re-observe token IDs after an error, rather than assuming restoration.
   Wait until both KV writes and audit appends recover before revoking stranded
   IDs. If the audit append still fails, revoke compensation can restore the
   active row. After a successful revoke, re-observe the persisted lifecycle and
   its audit event before declaring recovery. Do not reissue or rotate to hide
   unresolved state. Storage-only recovery does not establish retirement.
   The original audit error remains authoritative and no plaintext is returned.
6. Revoke unused tokens instead of extending them as login credentials. An
   expired or retired predecessor is not rotatable.

The single rotation audit event is correlated to the returned successor ID.
Its `application_token_id` and `lifecycle_status_code` describe that successor
at cutover (active); `replaced_token_id` and
`replaced_token_lifecycle_status_code` record the predecessor ID and the captured
persisted retired state (rotated). These non-secret IDs/state codes are historical
evidence, not a current-state read. Generic `events_for(predecessor)` remains an
exact-correlation query and does not retrieve the successor-correlated rotation
merely because its payload names that predecessor. No second event is emitted;
audit and KV are still not atomic.

A future deployment integration may wrap Keyverse rotation and the application
secret manager in a stronger transactional handoff, but this runbook does not
claim cross-system atomicity that the current HTTP API does not provide.

## Recovery

Corrupt grant or token rows fail closed with HTTP 500. Restore the KV/DB
namespace from backup and re-apply reviewed grants. Do not reconstruct
plaintext PATs from hashes.

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

### F1/F2 containment successor (private, pending whole-source review)

The custom typed-error code is acquired once under an ordinary-Exception guard;
only exact builtin strings in the existing vocabulary survive. Malformed,
missing or failing-property codes become fixed `storage_unavailable`, without
formatting raw args/str/repr. Fixed errors are raised after handlers exit and
carry no original cause/context; BaseException interruptions remain uncaught.
Memory checks exact AuditEvent/discriminator shape before filtering and the
rotation decoder guards acquisition of all seven stored fields. Missing fields
or ordinary descriptor failures produce fixed `corrupt_rotation_event`, never
silent row loss. Nonrotation JSON, global rotation-before-selection policy,
generic enumeration and service delegation remain unchanged. These controls
cover deliberately malformed stored-memory objects, not physical SQLite damage.
Permanent regressions are in `test_pat_rotation_containment.py`; historical
NONPASS remains retained until fresh independent accumulated-source review.
