# Keyverse Requirements and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-09

| Requirement / decision | Standards / authoritative basis | Source/evidence boundary | Maturity |
|---|---|---|---|
| passwordless local accounts | WebAuthn/FIDO2 + Keycloak supported flow; doctoring records | realm validator + deployment tests | implemented-main |
| exact subject then verified-email match | OIDC federation / NIST federation guidance; merge doctoring | account-unification matching/merge tests | implemented-main |
| unverified email never auto-links | security/product invariant | merge/federation tests | implemented-main |
| SCIM inbound lifecycle | RFC 7643/7644; doctoring | SCIM service/lifecycle tests | implemented-main |
| SAML/OIDC federation desired state | SAML/OIDC/Keycloak docs | preflight/reconciliation/receipt tests | implemented-main |
| LDAPS directory profile | LDAP RFC 4511–4515 + Keycloak component docs | directory preflight/reconciliation tests | implemented-main |
| secret-free RP desired state | OAuth/OIDC/PKCE/Keycloak client docs | RP preflight/reconciliation/integrity tests | implemented-main |
| RP audience/role/org/workspace mapper profile | OIDC/JWT audience + Keycloak mapper docs | PR #72 doctoring/tests | active-PR |
| merge/SCIM shared operation lock | concurrency/data-integrity decision | lock/concurrency tests | implemented-main |
| intent before mutation, receipt after re-observation | desired-state/recovery decision | federation/directory/RP reconciliation tests | implemented-main |
| remote-first deletion | consistency/recovery decision | delete/reconciliation tests | implemented-main |
| secrets from KV/DB, env bootstrap only | architecture/security decision | config/bootstrap/template validation | implemented-main |
| work-conserving fail-closed hourly API gate | automation safety decision | PR #74 workflow tests/exact-head evidence | active-PR |
| 100% production statement/branch/docstring | CWL quality contract | CI/pytest/interrogate | implemented-main |

## Doctoring and standards

`docs/doctoring/` and `docs/papers/` are the authoritative APA 7th standards/research record for OIDC/OAuth/JWT, SCIM, SAML, LDAP, WebAuthn/passkeys, Keycloak behavior, relying-party lifecycle, and automation changes. This matrix does not duplicate full bibliographic entries.

## Maturity rules

- `implemented-main`: source and representative tests exist on protected main.
- `active-PR`: source/evidence exists only on an open PR; do not advertise as released/current behavior.
- Architecture diagrams/plans/PR bodies alone cannot promote maturity.
- Queued, cancelled, stale, skipped-required, predecessor-head, or rate-limited checks/reviews are historical/non-passing evidence.

## Change rule

Every material identity/federation/SCIM/RP/security/automation PR should update affected rows and link its doctoring/operations evidence. If a decision is superseded, preserve historical ADR/doctoring and point to the replacement.