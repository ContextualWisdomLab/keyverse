# ADR-0009: Bind LineageWeave relying-party claims to Keyverse accounts

**Status:** Accepted
**Date:** 2026-08-13

## Context

LineageWeave requires real Keyverse accounts. Its company and PU dimensions are
authorization attributes, not substitute login identities. The existing
Keyverse relying-party mapper profile can emit only static routing claims, which
cannot prove that a current session belongs to the account represented by its
`sub` claim.

Keycloak documents separate built-in mappers for a user's client roles and for
custom user attributes. A generic mapper editor would expose unnecessary
issuer-side authority, including cross-client roles, arbitrary user attributes,
groups, scripts, claim names, and token destinations. That conflicts with the
closed desired-state boundary and with the downstream ABAC-before-RBAC contract
in ADR-0008.

## Decision

Keyverse accepts one separately reviewed confidential relying-party profile for
`lineageweave-web`. The profile contains exactly these four ordered mappers:

1. `keyverse-audience`: an audience mapper self-pinned to `lineageweave-web`.
2. `keyverse-account-role`: a client-role mapper pinned to the same client,
   with no role prefix and a multivalued `role` claim.
3. `keyverse-account-org`: a scalar user-attribute mapper from `org` to `org`.
4. `keyverse-account-workspace`: a scalar user-attribute mapper from
   `workspace` to `workspace`.

All four mappers use the exact reviewed access-token, ID-token,
introspection-token, and UserInfo destinations. The three account-derived
claims are atomic: they must all be present, must not mix with hardcoded claims,
and cannot be extended by configuration. The desired-state representation has
no client-secret field; confidential-secret placement remains a separate
approved secret-management operation.

The receiving application must validate issuer, signature/algorithm, expiry,
subject, and audience before reading these claims. It must bind `org` and
`workspace` to the requested resource before applying recognized client roles.
A green Keyverse preflight or apply receipt is not controlled login or
authorization evidence.

```mermaid
flowchart LR
    A["Verified Keyverse account"] --> B["Same-client role assignment"]
    A --> C["org account attribute"]
    A --> D["workspace account attribute"]
    B --> E["Closed LineageWeave mapper profile"]
    C --> E
    D --> E
    E --> F["Verified token claims"]
    F --> G["Tenant and resource ABAC"]
    G --> H["Bounded role RBAC"]
```

## Options considered

1. Keep static `role`, `org`, and `workspace` claims. Rejected because they do
   not bind the current authenticated account to company or PU attributes.
2. Permit generic Keycloak user/role/group mappers. Rejected because arbitrary
   issuer-side mappings expand authorization authority and cannot be reviewed
   from a stable desired-state contract.
3. Use the exact four-mapper account-derived profile. Accepted because it binds
   the needed claims to one Keyverse account and one client while retaining
   deterministic validation and reconciliation.

## Consequences

- Identity operators must provision a real Keyverse account with the two named
  attributes and an allowed `lineageweave-web` client role before user routing.
- Account and role changes take effect through Keycloak session/token lifecycle;
  operators must test downgrade and revocation behavior in controlled runtime
  acceptance.
- The profile does not authorize a resource on its own. LineageWeave must retain
  tenant/resource ABAC and only then apply its bounded role map.
- Any extra attribute, group, mapper type, audience, claim name, or token
  destination requires a new ADR, RED regression, and downstream acceptance
  evidence.

## Acceptance evidence

The implementation has local RED-to-GREEN validation, mapper-observation, and
secret-free-template tests. Before production use, record authenticated Keyverse
preflight and reconciliation receipts, private credential placement, a real
account authorization-code/PKCE exchange, token claim shape, cross-tenant
denial, role downgrade, logout, and rollback evidence. Until then the profile
is an accepted contract, not a deployed-login claim.

## References

Keycloak Project. (2026). *Protocol mappers*. Retrieved August 13, 2026, from
https://www.keycloak.org/admin-api/protocol-mappers

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (RFC 9700). Internet Engineering Task Force.
https://doi.org/10.17487/RFC9700
