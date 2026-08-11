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
evidence pointers, not copied implementations. This table is a dated audit
snapshot and cannot by itself promote an RP to `authorization-ready`.

The snapshot is reproducible from the Keyverse README at immutable revision
`4d2841071e9a8136298bb7198229d47ff406284d` and these audited application refs:

- `naruon`: `develop` at `da16757b78341de372c3fbd4d9c525dd9812bd1d`;
- `pg-erd-cloud`: PR #855 at `e4b4771fa0c46cbbcbd9ca7e777e20b5179b0bcd` (open; based on `main` at `72afe6db712b145baaba084f64a1ff4fb36d9fd0`);
- `semantic-data-portal`: PR #58 at `46b9fdb4480c665f6f513acfef4edfdb5848ca64`;
- `clearfolio`: `main` at `55d7ae8647208e301f282350f076eeddaba61d11`;
- `contextual-orchestrator`: `main` at `6841b71935e0b7cb98fb52bcb4709cc5100c8d87`;
- `newsdom-api`: PR #595 at `3025be1518a78f469d686644bde8b82f5f7bed05` (open; based on `develop` at `2f29e69c99a1201ce6b4e43370a463701efdc81c`).

| Application | Keyverse recognition | Current authorization | Finding and required direction |
|---|---|---|---|
| `naruon` | Generic OIDC/JWKS configuration accepts an issuer, audience, and `role`/`org`/`workspace`-shaped claims; no explicit Keyverse profile or acceptance fixture is named | RBAC plus ABAC exists in `backend/services/access_policy.py`; organization/workspace, ownership, delegation, consent, and capability checks precede role allows | Add an explicit Keyverse issuer/audience/JWKS deployment profile and exact-token acceptance test. Continue to reject issuer/audience/signature failures and never treat a hardcoded claim as proof of entitlement. |
| `pg-erd-cloud` | Generic OIDC/JWKS verification is present; PR #855 adds an opt-in `OIDC_ORGANIZATION` profile that requires an exact typed Keyverse `org`, audience, and `iat` after token verification | Project-member RBAC (`viewer`/`editor`/`owner`) exists in `backend/app/permissions.py`; the profile adds deployment-level single-tenant `org` ABAC and rejects `pgerd_` API-key bypasses | Use the profile for one-tenant-per-database deployments. A shared multi-tenant database still needs a persisted tenant key, tenant-qualified membership/resource queries, composite constraints, and cross-tenant denial tests before authorization-ready status. |
| `semantic-data-portal` | OIDC verification exists, but the mapper recognizes `tenant_id`/`tid`/`organization` and plural `roles`, not Keyverse `org` and singular `role` | RBAC and ABAC/purpose/sensitivity/evidence policy exists in `src/sdp/policy.py` | Add the bounded Keyverse aliases and regression tests in the app repository; preserve tenant, purpose, row-filter, masking, and evidence checks. This is an immediate application fix, not a documentation-only exception. Keep the repo-wide security gate green: `cryptography` must be pinned at `50.0.0` or newer in the source and every hash-locked requirements artifact after CVE-2026-69247. |
| `clearfolio` | No production OIDC/JWT verifier; current runtime is a gateway/header tenant scaffold documented in `docs/security/2026-07-02-auth-tenant-model.md` | Permission checks and tenant ownership are implemented, with optional gateway HMAC; the caller identity is not yet a Keyverse-verified token | Keep production fail-closed. Replace public header trust with Keyverse issuer/audience/JWKS verification at the service or a cryptographically trusted gateway, then map `org`/`sub`/roles/scopes and retain same-tenant checks. |
| `contextual-orchestrator` | Bearer-token configuration distinguishes `admin` and `inference` scopes but has no OIDC/JWT Keyverse validation | Coarse token-scope RBAC exists; resource/tenant ABAC is not established | Add a user-facing Keyverse OIDC resource-server boundary or a separately authenticated service-token/mTLS boundary for internal calls. Keep admin and inference scopes separate and add tenant/resource ownership conditions before exposing multi-tenant work. |
| `newsdom-api` | No Keyverse OIDC integration; PR #595 makes the local bearer boundary fail closed by default and permits anonymous parsing only through explicit `NEWSDOM_ALLOW_ANONYMOUS=true` | No application RBAC/ABAC; it is a PDF-to-DOM sidecar | Keep it private infrastructure while it has no user authorization model. If reachable beyond a trusted internal gateway, require a Keyverse-aware gateway or verified service boundary; never enable the anonymous opt-in on an exposed deployment. The same PR also remediates the current `pypdf` Trivy findings and incorporates the review fixes at `3025be1` (startup credential registry, authenticated examples, healthcheck executable-bit check, and complete 401 assertions). |

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
3. The interoperable Keyverse claim contract has explicit validation tiers:
   - every RP token must contain and validate `iss`, `sub`, `aud`, `exp`, and
     `iat`; `iss` is the exact configured HTTPS issuer, `sub` is a non-empty
     opaque subject, `aud` is the exact RP audience (as a string or an array
     containing that audience), and `exp`/`iat` are NumericDate values checked
     with the verifier's bounded clock-skew policy;
   - a tenant-scoped RP must require a non-empty opaque `org` value and bind it
     to a verified local tenant before any resource lookup; a
     workspace-scoped RP must additionally require `workspace` and prove that
     the workspace belongs to that `org`; missing, malformed, or mismatched
     bindings deny access;
   - `role` is optional at token-validation level, but an RP that makes an RBAC
     decision must require a recognized role and treat a missing or unknown
     role as no privilege. The current portable `naruon-web` profile allows
     only `member`; any new role value requires a separately reviewed mapper
     profile, an exact issuer-side test, and downstream elevation/downgrade
     tests;
   - `groups` and application-specific scopes are optional, typed, closed
     extensions. An RP may ignore claims it does not support, but it may not
     infer authorization from an unsupported claim or silently fall back to an
     unverified header, email, client ID, or UUID.

   The issuer-side mapper is covered by
   `services/account_unification/tests/test_validate_realm.py`; the current
   downstream Keyverse claim acceptance evidence is in SDP PR #58 at
   `tests/test_authz.py::test_keyverse_claim_aliases_map_to_tenant_and_bounded_role`,
   `tests/test_authz.py::test_keyverse_unknown_role_does_not_grant_access`,
   `tests/test_api.py::test_oidc_jwks_verification_maps_verified_token_without_token_leak`,
   and `tests/test_api.py::test_oidc_jwks_verification_rejects_wrong_audience`.
   pg-erd-cloud PR #855 adds
   `backend/tests/test_auth_security.py::test_keyverse_organization_claim_is_required_and_exact`
   and an API-key bypass regression; NewsDOM PR #595 adds default-deny and
   explicit-anonymous-mode tests, with the review follow-up at `3025be1`. Both remain `active-PR` evidence until
   their application changes reach protected branches.
   The contract is not a promise that every application supports every claim;
   each other RP must add and record its own exact acceptance-test paths before
   it can leave `deployment-restricted` status.
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
