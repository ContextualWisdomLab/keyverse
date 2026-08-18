# ADR-0006: Share one user-operation lock across merge and SCIM full replacement

**Status:** Accepted  
**Date:** 2026-08-09  
**Last expanded:** 2026-08-18

## Context

Account merge/link operations and a SCIM full user replacement can target
the same Keycloak user. The full replacement path reads tombstone state
and then writes the user representation, so it must not race a merge that
creates the tombstone between those operations.

SCIM 2.0 defines HTTP `PUT` as replace of the entire resource and `PATCH`
as a partial modification protocol with its own operation list (Hunt,
Grizzle, Ansari, et al., 2015, §§3.5.1–3.5.2). The core User schema
includes `active` and multi-valued emails but does not define merge or
tombstone semantics (Hunt, Grizzle, Wahlstroem, & Mortimore, 2015).
Keyverse therefore has to impose a product lock around the replace path
that can observe or overwrite survivor/tombstone attributes.

Protected `main` also supports the narrower `PATCH active=false`
deprovisioning path. That PATCH path currently performs its
read/deactivate/read sequence outside the shared cross-process lock. This
ADR therefore must not imply that every SCIM mutation is serialized with
merge.

## Decision

Keyverse uses one cross-process user-operation lock boundary for account
merge/link and SCIM `PUT /Users/{id}` full replacement. Those operations
serialize consistently, preserve tombstone/survivor invariants, and can
be retried or recovered from observed durable state.

The current SCIM `PATCH active=false` path is explicitly outside this
Accepted shared-lock guarantee. If PATCH or any future SCIM
read-modify-write operation can affect tombstone, survivor, or
reactivation invariants, it must join the same lock boundary and add a
concurrency regression before documentation may claim equivalent
serialization.

## Consequences

- Merge and SCIM full replacement share one documented concurrency
  authority.
- The protected-main PATCH behavior remains usable but must not be
  described as transactionally serialized with merge.
- Expanding the lock guarantee requires a source/test change, not a
  documentation-only promotion.
- Clustered deployments must provide the same shared-lock semantics for
  every operation included in this boundary.
- Durable lock state uses `user_operation_lock_state`; merge audit uses
  `account_merge_audit`.

## References

See [`docs/REFERENCES.md`](../REFERENCES.md) for the full APA 7th entries
and official URLs/DOIs opened for this expansion.

Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015).
*System for Cross-domain Identity Management: Protocol* (RFC 7644).
https://doi.org/10.17487/RFC7644

Hunt, P., Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System for
Cross-domain Identity Management: Core schema* (RFC 7643).
https://doi.org/10.17487/RFC7643
