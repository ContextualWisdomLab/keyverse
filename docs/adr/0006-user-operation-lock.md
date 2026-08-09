# ADR-0006: Share one user-operation lock across merge and SCIM full replacement

**Status:** Accepted  
**Date:** 2026-08-09

## Context

Account merge/link operations and a SCIM full user replacement can target the same Keycloak user. The full replacement path reads tombstone state and then writes the user representation, so it must not race a merge that creates the tombstone between those operations.

Protected `main` also supports the narrower `PATCH active=false` deprovisioning path. That PATCH path currently performs its read/deactivate/read sequence outside the shared cross-process lock. This ADR therefore must not imply that every SCIM mutation is serialized with merge.

## Decision

Keyverse uses one cross-process user-operation lock boundary for account merge/link and SCIM `PUT /Users/{id}` full replacement. Those operations serialize consistently, preserve tombstone/survivor invariants, and can be retried or recovered from observed durable state.

The current SCIM `PATCH active=false` path is explicitly outside this Accepted shared-lock guarantee. If PATCH or any future SCIM read-modify-write operation can affect tombstone, survivor, or reactivation invariants, it must join the same lock boundary and add a concurrency regression before documentation may claim equivalent serialization.

## Consequences

- Merge and SCIM full replacement share one documented concurrency authority.
- The protected-main PATCH behavior remains usable but must not be described as transactionally serialized with merge.
- Expanding the lock guarantee requires a source/test change, not a documentation-only promotion.
- Clustered deployments must provide the same shared-lock semantics for every operation included in this boundary.