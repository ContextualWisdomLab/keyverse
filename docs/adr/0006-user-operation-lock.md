# ADR-0006: Share one user-operation lock across merge and SCIM full replacement

**Status:** Accepted  
**Date:** 2026-08-09  
**Updated:** 2026-08-24

## Context

Account merge/link operations and a SCIM full user replacement can target the
same Keycloak user. The full replacement path reads tombstone state and then
writes the user representation, so it must not race a merge that creates the
tombstone between those operations.

SCIM Protocol RFC 7644 defines HTTP `PUT` as a full resource replacement and
`PATCH` as a partial modification (Hunt, Grizzle, Ansari, et al., 2015). SCIM
Core Schema RFC 7643 defines the user representation being replaced (Hunt,
Grizzle, Wahlstroem, & Mortimore, 2015). Those documents specify resource
semantics; they do not specify a cross-process lock. Keyverse therefore adds a
product concurrency boundary so replacement cannot observe a user, lose a
merge, and rewrite the pre-merge representation.

Protected `main` also supports the narrower `PATCH active=false` deprovisioning
path. That PATCH path currently performs its read/deactivate/read sequence
outside the shared cross-process lock. This ADR therefore must not imply that
every SCIM mutation is serialized with merge.

## Decision

Keyverse uses one cross-process user-operation lock boundary for account
merge/link and SCIM `PUT /Users/{id}` full replacement. Those operations
serialize consistently, preserve tombstone/survivor invariants, and can be
retried or recovered from observed durable state.

The current SCIM `PATCH active=false` path is explicitly outside this Accepted
shared-lock guarantee. If PATCH or any future SCIM read-modify-write operation
can affect tombstone, survivor, or reactivation invariants, it must join the
same lock boundary and add a concurrency regression before documentation may
claim equivalent serialization.

## Consequences

- Merge and SCIM full replacement share one documented concurrency authority.
- The protected-main PATCH behavior remains usable but must not be described as
  transactionally serialized with merge.
- Expanding the lock guarantee requires a source/test change, not a
  documentation-only promotion.
- Clustered deployments must provide the same shared-lock semantics for every
  operation included in this boundary.

## References

Hunt, P. (Ed.), Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C.
(2015). *System for Cross-domain Identity Management: Protocol* (RFC 7644).
Internet Engineering Task Force. https://doi.org/10.17487/RFC7644

Hunt, P. (Ed.), Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System
for Cross-domain Identity Management: Core schema* (RFC 7643). Internet
Engineering Task Force. https://doi.org/10.17487/RFC7643
