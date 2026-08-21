# Keyverse Requirements and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-12

| Requirement / decision | Standards / authoritative basis | Source/evidence boundary | Maturity |
|---|---|---|---|
| passwordless local accounts | WebAuthn/FIDO2 + Keycloak supported flow; research/standards records | realm validator + deployment tests | implemented-main |
| exact subject then verified-email match | OIDC federation / NIST federation guidance; merge documentation | account-unification matching/merge tests | implemented-main |
| unverified email never auto-links | security/product invariant | merge/federation tests | implemented-main |
| SCIM inbound lifecycle | RFC 7643/7644; protocol documentation | SCIM service/lifecycle tests | implemented-main |
| SAML/OIDC federation desired state | SAML/OIDC/Keycloak docs | preflight/reconciliation/receipt tests | implemented-main |
| LDAPS directory profile | LDAP RFC 4511–4515 + Keycloak component docs | directory preflight/reconciliation tests | implemented-main |
| secret-free RP desired state | OAuth/OIDC/PKCE/Keycloak client docs | RP preflight/reconciliation/integrity tests | implemented-main |
| RP audience/role/org/workspace mapper profile | OIDC/JWT audience + Keycloak mapper docs | PR #72 protected-main source/tests; downstream RP acceptance remains required | implemented-main |
| merge/SCIM PUT/PATCH shared operation lock | concurrency/data-integrity decision; ADR-0006 | merge + full-replacement + active=false PATCH lock/concurrency tests | active-PR |
| intent before mutation, receipt after re-observation | desired-state/recovery decision | federation/directory/RP reconciliation tests | implemented-main |
| receipt bound to exact desired-state version/hash | threat/recovery contract; ERD | persistence/migration/idempotency evidence required | accepted-contract |
| remote-first deletion | consistency/recovery decision | delete/reconciliation tests | implemented-main |
| secrets from KV/DB, env bootstrap only | architecture/security decision | config/bootstrap/template validation | implemented-main |
| work-conserving fail-closed hourly API gate | automation safety decision | PR #74 protected-main workflow tests/exact-head evidence; scheduled/manual run remains required | implemented-main |
| non-fork RP Keyverse authorization boundary | ADR-0008; OIDC/JWT recipient validation and least-privilege policy | six-app audit, per-RP issuer/audience/tenant/ABAC/RBAC evidence required | accepted-contract |
| naruon Keyverse OIDC acceptance boundary | ADR-0008; exact issuer/audience/JWKS validation and required OIDC NumericDate claims | naruon PR #1321 `ca6ccba` names the Keyverse issuer and `naruon-web` audience, requires verified `iat`, tests explicit org/workspace/role acceptance plus missing-`iat` denial, strips orphaned HTML comment terminators, and resolves the `develop` CHANGELOG conflict; protected-branch Checks/review remain required | active-PR |
| semantic-data-portal Keyverse claim boundary | ADR-0008; bounded claim mapping and fail-closed tenant/role/JWT-header validation | semantic-data-portal PR #58 `47e2215` aliases `org`/`role`, validates every present tenant alias, rejects malformed/conflicting aliases before `ActorContext`, explicitly rejects unsupported JWT `crit` headers, and keeps the cryptography floor; protected-branch approval remains required | active-PR |
| pg-erd-cloud Keyverse organization boundary | ADR-0008; verified tenant binding before project authorization | pg-erd-cloud PR #855 `e4b4771` exact `org`/audience/`iat` checks, single-tenant profile, API-key bypass denial; shared multi-tenant persistence remains unimplemented | active-PR |
| contextual-orchestrator Keyverse identity and tenant boundary | ADR-0008; deployment-owned OIDC validation plus downstream scope RBAC and org/workspace ABAC | PR #109 `32ba3a9` adds the injected verifier seam; stacked PR #110 `8607eba` requires `VerifiedIdentity`, rejects boolean-only authorization, binds workflow/evaluation/batch resources to secret-free tenant context, and denies cross-tenant or ownerless reads; main remains unchanged until both protected PRs merge | active-PR |
| sidecar anonymous-access boundary | ADR-0008; private service-boundary and least-privilege policy | newsdom-api protected `develop` `3d0426b` (PR #595) fail-closed token gate, startup credential registry, explicit anonymous opt-in, review-fixed authenticated examples/healthcheck/401 contract, and pypdf Trivy remediation; Keyverse-aware gateway evidence remains required for exposure | implemented-main |
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
