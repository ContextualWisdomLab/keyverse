# Keyverse Technical Requirements Document

**Status:** Accepted cross-cutting technical baseline for protected main  
**Last reviewed:** 2026-08-11

## 1. Architecture objective

Keyverse separates portable Keycloak realm policy, Keyverse-owned identity control logic, customer/deployment secrets, remote apply/reconciliation, and downstream relying-party authorization so that each trust boundary can be tested and recovered independently.

## 2. Runtime components

- **Keycloak engine:** OIDC/OAuth, SAML brokering, WebAuthn, users/sessions/roles/groups, external IdP and LDAP component execution, RP clients.
- **Account-unification FastAPI service:** merge/link, SCIM, federation/directory/RP validation and desired-state/reconciliation, audit/locking boundaries.
- **PostgreSQL/KV:** Keycloak state plus Keyverse configuration, intent, receipts, merge audit, and user-operation locks.
- **Deployment controller:** private configuration rendering, egress/TLS policy, explicit apply, controlled acceptance, rollback.
- **Compose/Helm:** standalone deployment topology and probes.

## 3. Trust/authority rules

- Portable realm policy may contain public client/scope/authentication definitions but no tenant/customer federation private values.
- Deterministic preflight never performs network, DNS, Keycloak, bind/search, file, or store mutation.
- Apply/reconciliation endpoints use exact remote identity lookup and fail on zero/multiple states according to operation semantics.
- Desired-state intent is persisted before external mutation where recovery requires it; receipt is persisted only after exact re-observation and binds the desired-state hash/version acted on.
- RP desired state remains separate from confidential client material.
- Deployment controller, not public API, owns private bind/client and certificate material.
- Each non-fork RP is a separate authorization boundary: verified Keyverse token validation, tenant/resource ABAC, and role/scope RBAC must be proven in the RP repository before production routing.

## 4. Identity evidence

Identity matching precedence is exact `(identity_provider, subject)` → verified email → explicit operator link. Unverified email is never sufficient. Merged users become disabled tombstones pointing to the survivor, preventing accidental resurrection/reprovisioning as independent people.

## 5. Concurrency and transactions

User merge, SCIM full replacement (`PUT`), and supported `PATCH active=false` deprovisioning share one cross-process operation-lock boundary. Lock contention returns retryable SCIM `503` before the mutation sequence. Any future SCIM read-modify-write operation that can affect tombstone/survivor invariants must join the same lock boundary and add a concurrency regression before the stronger guarantee is promoted. Desired-state records and apply receipts require deterministic keys, transaction-safe update semantics, exact desired-version binding, and reconciliation after crash/retry. Remote deletion precedes local desired-state removal when local-first deletion could falsely report success.

## 6. Federation requirements

### SAML / external OIDC

Closed validated payload; no metadata/discovery fetch during preflight; strict issuer/entity/redirect/trust-email policy; explicit apply through Keyverse; redacted status.

### LDAP / AD

Current accepted profile is LDAPS-only, read-only, Kerberos-disabled, `trustEmail=false`, bounded timeouts, closed Keycloak component shape, RFC-valid DN values, no network side effect during preflight. Controlled bind/search/login acceptance occurs only after deployment apply.

### RP clients

Authorization code + PKCE S256, exact HTTPS redirect/origin/logout rules, exact scope policy, secret-free desired state, exact client lookup and UUID integrity, post-mutation re-observation, separate confidential-material provisioning, and downstream token/audience/tenant authorization acceptance. Native loopback redirects are not part of the protected-main RP profile; introducing them requires a separately accepted trust-policy change plus synchronized product, threat, test, and traceability evidence.

The PR #72 claim mapper profile is integrated in protected main. Downstream
authorization acceptance remains deployment-specific and is not implied by
Keycloak client reconciliation.

The per-application authorization matrix and remediation directions are governed
by ADR-0008. Keyverse client reconciliation does not imply downstream
authorization readiness.

## 7. API/error boundary

Authenticated operator APIs accept closed versioned schemas. Errors must not echo private values, raw provider responses, or arbitrary Keycloak Location/header content. Remote resource IDs parsed from Keycloak are validated before use in privileged paths.

## 8. Persistence/data model

Current architecture owns PostgreSQL/KV state for configuration, desired-state sources, apply receipts, merge audit, and operation locks. Database objects use descriptive two-word-or-longer `snake_case` names. `docs/ERD.md` defines tenant-scoped uniqueness, receipt identity/version binding, relationships, and lifecycle; migrations must preserve tenant/identity/audit integrity.

## 9. Security and privacy

Use standards-backed OIDC/OAuth/SAML/SCIM/LDAP/WebAuthn/JWT validation, least privilege, encrypted stores/transport, bounded retention/export, controlled admin egress, and auditable privileged outcomes. Do not mask identity fields in ways that break identity matching; protect them through access and lifecycle controls.

## 10. Quality gates

- Ruff / compile;
- Interrogate/public docstrings 100%;
- production statement and branch coverage 100%;
- realistic merge/SCIM/federation/RP concurrency and hostile-input tests;
- package, realm, deployment template, Compose/Helm validation;
- exact-current-head CodeQL/Semgrep/security/review evidence;
- no queued/cancelled/skipped/stale evidence counted as passing.

## 11. Operability

Readiness is component/lifecycle specific. Preflight success does not imply Keycloak apply, bind/search, login, logout, token audience, SCIM provisioning, or downstream authorization success. `docs/OPERABILITY.md` defines acceptance and recovery.

## 12. Automation boundary

Autonomous development uses NVIDIA NIM/OpenCode through an isolated model phase. Model execution has no publication/reviewer/release authority. PR #74 is integrated in protected main; its operational boundary must still be proven by a protected-main scheduled or manual run.

## 13. Change control

Changes to identity matching, passwordless policy, federation trust, private-value ownership, desired-state/reconciliation order, persistence, external admin authority, or automation authority require an ADR plus PRD/TRD/Architecture/UML/ERD/Threat/Test/Operability/Traceability reconciliation.
