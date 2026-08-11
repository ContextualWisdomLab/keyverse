# ADR-0008: Make Keyverse RP authorization explicit across non-fork applications

**Status:** Accepted  
**Date:** 2026-08-11

## Context

Keyverse is the ContextualWisdomLab identity hub, but an application does not
inherit that trust merely because it is listed in the Keyverse README or lives
in the same GitHub organization. The ecosystem RPs are separate, non-fork
repositories. Each one must explicitly configure the Keyverse issuer, client
audience, signing-key trust, claim mapping, tenant boundary, and authorization
policy. Authentication success alone is not authorization success.

The application audit below was performed against the non-fork repositories
listed as Keyverse RPs in `README.md` on 2026-08-11. Repository paths are
evidence pointers, not copied implementations.

| Application | Keyverse recognition | Current authorization | Finding and required direction |
|---|---|---|---|
| `naruon` | Generic OIDC/JWKS configuration accepts an issuer, audience, and `role`/`org`/`workspace`-shaped claims; no explicit Keyverse profile or acceptance fixture is named | RBAC plus ABAC exists in `backend/services/access_policy.py`; organization/workspace, ownership, delegation, consent, and capability checks precede role allows | Add an explicit Keyverse issuer/audience/JWKS deployment profile and exact-token acceptance test. Continue to reject issuer/audience/signature failures and never treat a hardcoded claim as proof of entitlement. |
| `pg-erd-cloud` | Generic OIDC/JWKS verification is present in `backend/app/auth.py`; Keyverse claim-to-tenant mapping is absent | Project-member RBAC (`viewer`/`editor`/`owner`) exists in `backend/app/permissions.py`; organization/workspace ABAC is not enforced | Map verified Keyverse `sub` to the local account and `org` to a tenant boundary before project lookup. Add tenant-qualified membership queries and cross-tenant denial tests. |
| `semantic-data-portal` | OIDC verification exists, but the mapper recognizes `tenant_id`/`tid`/`organization` and plural `roles`, not Keyverse `org` and singular `role` | RBAC and ABAC/purpose/sensitivity/evidence policy exists in `src/sdp/policy.py` | Add the bounded Keyverse aliases and regression tests in the app repository; preserve tenant, purpose, row-filter, masking, and evidence checks. This is an immediate application fix, not a documentation-only exception. |
| `clearfolio` | No production OIDC/JWT verifier; current runtime is a gateway/header tenant scaffold documented in `docs/security/2026-07-02-auth-tenant-model.md` | Permission checks and tenant ownership are implemented, with optional gateway HMAC; the caller identity is not yet a Keyverse-verified token | Keep production fail-closed. Replace public header trust with Keyverse issuer/audience/JWKS verification at the service or a cryptographically trusted gateway, then map `org`/`sub`/roles/scopes and retain same-tenant checks. |
| `contextual-orchestrator` | Bearer-token configuration distinguishes `admin` and `inference` scopes but has no OIDC/JWT Keyverse validation | Coarse token-scope RBAC exists; resource/tenant ABAC is not established | Add a user-facing Keyverse OIDC resource-server boundary or a separately authenticated service-token/mTLS boundary for internal calls. Keep admin and inference scopes separate and add tenant/resource ownership conditions before exposing multi-tenant work. |
| `newsdom-api` | Optional local `NEWSDOM_API_TOKEN` bearer auth exists; no Keyverse OIDC integration | No application RBAC/ABAC; it is a PDF-to-DOM sidecar | Treat it as private infrastructure only while it has no user authorization model. If reachable beyond a trusted internal gateway, require a Keyverse-aware gateway or add a verified service boundary; never leave the default-open development mode on an exposed deployment. |

Keyverse itself also has two boundaries that must not be confused with
downstream application authorization:

- the portable realm currently contains the reviewed `naruon-web` claim shape
  (`role`, `org`, and `workspace`), but those values are deployment/profile
  data and do not grant privilege by themselves; user/tenant role derivation
  and downstream authorization remain separate acceptance obligations;
- the account-unification inbound admin/SCIM surface currently has one
  deployment-owned operator bearer gate. That is a coarse service boundary,
  not per-operation RBAC or ABAC. Multi-operator production use requires
  endpoint scopes, tenant/resource authorization, and audit evidence.

## Decision

1. Every RP is an explicit Keyverse integration. A client ID, repository
   relationship, email address, UUID, or README entry never establishes trust.
2. Every RP must validate a signed token's issuer, signature/algorithm, expiry,
   subject, and audience before reading authorization claims. It must establish
   the tenant from a verified claim or an independently verified mapping, then
   apply resource/ownership/purpose constraints (ABAC), and only then apply
   roles/scopes/groups (RBAC). A role cannot bypass a failed tenant boundary.
3. The interoperable Keyverse claim contract is `iss`, `sub`, `aud`, `exp`,
   `iat`, `org`, `workspace`, and a bounded `role` value; `groups` and
   application-specific scopes are opt-in, typed, and separately documented.
   The contract is not a promise that every application supports every claim.
4. Keyverse's closed RP mapper profile remains least-privilege. Hardcoded
   `role`, `org`, and `workspace` values may identify the reviewed deployment
   profile, but they must not be used as an unverified privilege escalation
   channel. Moving them to user/tenant-derived Keycloak roles or groups requires
   a separate mapper and downstream authorization design with tests.
5. The account-unification operator token remains deployment-only and
   coarse-grained until per-operation RBAC/ABAC is implemented. No downstream
   application receives Keycloak Admin credentials to compensate for that gap.
6. Each finding in the audit table becomes a tracked application change or an
   explicit deployment restriction. A green Keyverse client reconciliation,
   mapper unit test, or app login test cannot promote an app to
   `authorization-ready` without cross-tenant and resource-policy evidence.

## Required implementation gates

- invalid issuer, signature, algorithm, expiry, audience, and subject are
  rejected before authorization;
- missing or mismatched `org`/tenant and `workspace` values cannot cross a
  resource boundary;
- role/scope/group mappings are closed, least-privilege, and tested for
  elevation and downgrade;
- resource ownership, delegation, purpose, sensitivity, and masking/row-filter
  rules are evaluated where the application has those concepts;
- trusted service-to-service calls use a separate service identity and scope,
  not a browser user's token or a shared admin token;
- production defaults fail closed, while local demo/open modes are explicit,
  isolated, and never represented as Keyverse authorization evidence.

## Consequences

- Keyverse onboarding must include a per-app token-validation and authorization
  acceptance record, not only a client registration receipt.
- Some applications can use their existing policy engines after adding the
  Keyverse claim mapping; others need a production identity boundary before
  their current permission scaffolds are safe for external exposure.
- A separate PR is required in each application repository for runtime changes.
  This ADR records the central contract and the direction; it does not claim
  that an unmodified application has been fixed.
- Cross-tenant persistence constraints are part of the identity boundary. The
  ERD therefore requires tenant-qualified composite foreign keys for external
  identity links and merge audit references.

## Acceptance evidence

The Keyverse repository must keep the claim mapper, realm, ERD, threat, test,
operability, and traceability records synchronized. Each RP repository must
link its exact issuer/audience/JWKS configuration, claim mapping, ABAC/RBAC
tests, cross-tenant denial tests, and production-mode configuration. Until
that evidence exists, the app's status is `planned`, `gap-not-claimed`, or
`deployment-restricted`, never `authorization-ready`.

