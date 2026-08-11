# Keyverse Requirements and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-09

| Requirement / decision | Standards / authoritative basis | Source/evidence boundary | Maturity |
|---|---|---|---|
| passwordless local accounts | WebAuthn/FIDO2 + Keycloak supported flow; research/standards records | realm validator + deployment tests | implemented-main |
| exact subject then verified-email match | OIDC federation / NIST federation guidance; merge documentation | account-unification matching/merge tests | implemented-main |
| unverified email never auto-links | security/product invariant | merge/federation tests | implemented-main |
| SCIM inbound lifecycle | RFC 7643/7644; protocol documentation | SCIM service/lifecycle tests | implemented-main |
| SAML/OIDC federation desired state | SAML/OIDC/Keycloak docs | preflight/reconciliation/receipt tests | implemented-main |
| LDAPS directory profile | LDAP RFC 4511–4515 + Keycloak component docs | directory preflight/reconciliation tests | implemented-main |
| secret-free RP desired state | OAuth/OIDC/PKCE/Keycloak client docs | RP preflight/reconciliation/integrity tests | implemented-main |
| RP audience/role/org/workspace mapper profile | OIDC/JWT audience + Keycloak mapper docs | PR #72 research/tests | active-PR |
| merge/SCIM PUT shared operation lock | concurrency/data-integrity decision; ADR-0006 | merge + full-replacement lock/concurrency tests | implemented-main |
| SCIM PATCH active=false shared-lock parity | ADR-0006 boundary | current PATCH source has no shared-lock proof | gap-not-claimed |
| intent before mutation, receipt after re-observation | desired-state/recovery decision | federation/directory/RP reconciliation tests | implemented-main |
| receipt bound to exact desired-state version/hash | threat/recovery contract; ERD | persistence/migration/idempotency evidence required | accepted-contract |
| remote-first deletion | consistency/recovery decision | delete/reconciliation tests | implemented-main |
| secrets from KV/DB, env bootstrap only | architecture/security decision | config/bootstrap/template validation | implemented-main |
| work-conserving fail-closed hourly API gate | automation safety decision | PR #74 workflow tests/exact-head evidence | active-PR |
| non-fork RP Keyverse authorization boundary | ADR-0008; OIDC/JWT recipient validation and least-privilege policy | six-app audit, per-RP issuer/audience/tenant/ABAC/RBAC evidence required | accepted-contract |
| 100% production statement/branch/docstring | CWL quality contract | CI/pytest/interrogate | implemented-main |

## Research, standards, and operations records

`docs/doctoring/`, `docs/papers/`, and `docs/operations/` are the authoritative research/standards/runbook record for OIDC/OAuth/JWT, SCIM, SAML, LDAP, WebAuthn/passkeys, Keycloak behavior, relying-party lifecycle, and automation changes. This matrix does not duplicate full bibliographic entries.

## Maturity rules

- `implemented-main`: source and representative tests exist on protected main.
- `active-PR`: source/evidence exists only on an open PR; do not advertise as released/current behavior.
- `accepted-contract`: architecture/data contract is accepted, but physical migration/runtime evidence is still required before claiming enforcement.
- `gap-not-claimed`: a known boundary is intentionally documented as not guaranteed by protected-main behavior.
- Architecture diagrams/plans/PR bodies alone cannot promote maturity.
- Queued, cancelled, stale, skipped-required, predecessor-head, or rate-limited checks/reviews are historical/non-passing evidence.

## Change rule

Every material identity/federation/SCIM/RP/security/automation PR should update affected rows and link its research/standards/operations evidence. If a decision is superseded, preserve historical ADR/research records and point to the replacement.
