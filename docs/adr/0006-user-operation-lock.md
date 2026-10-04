# ADR-0006: Share one user-operation lock across merge and SCIM mutations

**Status:** Accepted  
**Date:** 2026-08-09

## Context

Account merge/link operations and SCIM user mutations can target the same Keycloak user. The replacement and deprovisioning paths read user state and then write it, so they must not race a merge that creates the tombstone between those operations.

## Decision

Keyverse uses one cross-process user-operation lock boundary for account merge/link, SCIM `PUT /Users/{id}` full replacement, SCIM `PATCH /Users/{id}` with `active=false`, and SCIM `DELETE /Users/{id}`. These operations serialize consistently, preserve tombstone/survivor invariants, and can be retried or recovered from observed durable state. A lock timeout returns retryable SCIM `503` without entering the mutation sequence.

Future SCIM read-modify-write operations that can affect tombstone, survivor, or reactivation invariants must join the same lock boundary and add a concurrency regression before documentation may claim equivalent serialization.

## Consequences

- Merge, SCIM full replacement, and both supported deprovisioning paths share one documented concurrency authority.
- SCIM deprovisioning lock contention is a retryable service-unavailable outcome; it is not evidence that a partial mutation occurred.
- Expanding the lock guarantee requires a source/test change, not a documentation-only promotion.
- Clustered deployments must provide the same shared-lock semantics for every operation included in this boundary.
