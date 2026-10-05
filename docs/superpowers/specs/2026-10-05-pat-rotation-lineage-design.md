# Accepted PAT rotation-lineage read contract

Status: owner-adopted repository policy; private candidate, not deployed.

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
