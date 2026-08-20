# SCIM deactivation lock boundary

**Date:** 2026-08-20  
**Status:** Implementation evidence for the active PR; not protected-main or live Keycloak acceptance

## Scope

This record documents the supported `PATCH /scim/v2/Users/{id}`
`active=false` path joining the existing `UserOperationLocks` boundary used by
account merge and SCIM full replacement. The change is deliberately limited to
the existing mutation path; it adds no database schema, UI, mapper, tenant
claim, or external provider behavior.

## Interpretation

- **Standards requirement:** RFC 7644 defines SCIM protocol operations and the
  PATCH operation used for resource updates.
- **HTTP behavior:** lock contention is represented as HTTP `503 Service
  Unavailable`, a retryable service-boundary result under the RFC 9110 status
  semantics; the response does not claim that the remote mutation started.
- **Policy choice:** the request is linearized by the shared lock. If PATCH
  deactivation acquires the lock first, a concurrent merge observes the
  disabled duplicate and fails rather than creating a contradictory tombstone.
- **Implementation behavior:** the lock covers the existing read, deactivate,
  and final read sequence. A lock timeout exits before that sequence and maps to
  the existing SCIM error shape.

## Evidence

- **RED:** before the source change, a deterministic two-thread regression
  allowed merge to reach duplicate deactivation while PATCH was blocked in its
  deactivation call.
- **GREEN:** after the source change, the same regression completes PATCH first,
  makes merge observe the inactive account, and leaves no merge tombstone.
- **Measured boundary:** focused and complete account-unification tests passed;
  production coverage measured 2,738 statements and 738 branches at 100%;
  Interrogate reported 100% docstring quality; Ruff, compileall, and `uv build`
  passed on this branch.
- **Not claimed:** this is not live Keycloak, PostgreSQL, clustered deployment,
  browser login, or downstream authorization acceptance evidence. The SQLite
  backend remains a conservative global lock; per-account locking is a future
  throughput optimization only if measured contention justifies it.

## References

Fielding, R., Nottingham, M., & Reschke, J. (Eds.). (2022). *HTTP semantics*
(RFC 9110). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc9110.html

Hunt, P., Grizzle, K., Ansari, M., Wahlström, E., & Mortimore, C. (2015).
*System for Cross-domain Identity Management: Protocol* (RFC 7644). Internet
Engineering Task Force. https://www.rfc-editor.org/rfc/rfc7644.html
