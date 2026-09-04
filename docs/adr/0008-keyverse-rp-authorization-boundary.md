# ADR-0008: Make Keyverse RP authorization explicit across non-fork applications

**Status:** Accepted  
**Date:** 2026-08-11  
**Updated:** 2026-08-24

## Context

OpenID Connect Core 1.0 defines a relying party as an OAuth 2.0 client that
verifies the end user from tokens issued by an OpenID provider (Sakimura et
al., 2023). JSON Web Token RFC 7519 requires recipients to validate the
signed claims they consume (Jones, Bradley, & Sakimura, 2015). JWT BCP 225
updates that guidance and requires audience checks when a JWT is intended for
a specific recipient (Sheffer et al., 2020). The JWT profile for OAuth 2.0
access tokens requires a resource server to reject a token whose `aud` does
not identify that resource (Bertocci, 2021). Bearer tokens can be used by any
party that possesses them (Jones & Hardt, 2012). NIST SP 800-63C-4 treats
federation assertions as evidence for a separately administered relying party,
not as an authorization decision inside that party's resources (Temoshok,
Richer, et al., 2025).

Those records specify authentication and token-acceptance rules. They do not
grant authorization from a README listing, a shared GitHub organization, or a
hardcoded routing claim. Identity attributes used for tenant binding are
handled through purpose-bound access, encryption, and audit. This ADR does not
claim NIST, IETF, or OpenID conformance.

Keyverse is the ContextualWisdomLab identity hub, but an application does not
inherit that trust merely because it is listed in the Keyverse README or lives
in the same GitHub organization. The ecosystem RPs are separate, non-fork
repositories. Each one must explicitly configure the Keyverse issuer, client
audience, signing-key trust, claim mapping, tenant boundary, and authorization
policy. Authentication success alone is not authorization success.

The application audit below was performed against the non-fork repositories
listed as Keyverse RPs in `README.md` on 2026-08-11. Repository paths are
evidence pointers, not copied implementations. The open-PR evidence was
refreshed on 2026-08-12; this table still cannot by itself promote an RP to
`authorization-ready`.

The snapshot is reproducible from the Keyverse README at immutable revision
`4d2841071e9a8136298bb7198229d47ff406284d` and these audited application refs:

- `naruon`: PR #1321 at `ca6ccba2aeb3d0dcaf58380d031cbe084fe7c28e` (open; the
  `develop` merge conflict was resolved in this head; based on `develop` at
  `2f5c19a138b270fd8f29c5e5620cf204f184cb2c`);
- `pg-erd-cloud`: PR #855 at `e4b4771fa0c46cbbcbd9ca7e777e20b5179b0bcd` (open; based on `main` at `72afe6db712b145baaba084f64a1ff4fb36d9fd0`);
- `semantic-data-portal`: PR #58 at `47e2215c32b32d1ca221082d7acc2f7fcc5e5083` (open; based on `main` at `e48aa13c4af7a4875d4b53e6a60b50405c265a2f`);
- `clearfolio`: `main` at `55d7ae8647208e301f282350f076eeddaba61d11`;
- `contextual-orchestrator`: `main` at `6841b71935e0b7cb98fb52bcb4709cc5100c8d87`; PR #109 at `32ba3a9efd0c3e4ae00b085aa6b8e21755ea01ad` adds the deployment-injected Keyverse verifier seam and current review evidence, and stacked PR #110 at `8607eba46a5dd7773fde211ceedcf70b3855de0d` adds identity-carrying RBAC/ABAC on the latest parent head;
- `newsdom-api`: protected `develop` at `3d0426bf45ad9d3395effb602811a75cbe700cf4` (PR #595 squash-merged; based on `develop` at `2f29e69c99a1201ce6b4e43370a463701efdc81c`).

| Application | Keyverse recognition | Current authorization | Finding and required direction |
|---|---|---|---|
| `naruon` | PR #1321 adds an explicit Keyverse issuer `https://keyverse.example.test/realms/cwl`, reviewed `naruon-web` audience, and exact-token acceptance fixture; OIDC now requires verified `iat` as well as `iss`/`aud`/`exp` | RBAC plus ABAC exists in `backend/services/access_policy.py`; organization/workspace, ownership, delegation, consent, and capability checks precede role allows | Merge PR #1321 after independent review and protected checks. Keep the explicit issuer/audience/JWKS profile, required NumericDate claims, and deny-first authorization; never treat a hardcoded claim as proof of entitlement. |
| `pg-erd-cloud` | Generic OIDC/JWKS verification is present; PR #855 adds an opt-in `OIDC_ORGANIZATION` profile that requires an exact typed Keyverse `org`, audience, and `iat` after token verification | Project-member RBAC (`viewer`/`editor`/`owner`) exists in `backend/app/permissions.py`; the profile adds deployment-level single-tenant `org` ABAC and rejects `pgerd_` API-key bypasses | Use the profile for one-tenant-per-database deployments. A shared multi-tenant database still needs a persisted tenant key, tenant-qualified membership/resource queries, composite constraints, and cross-tenant denial tests before authorization-ready status. |
| `semantic-data-portal` | OIDC verification exists; PR #58 maps bounded Keyverse `org`/`role` aliases, validates every present tenant alias, rejects conflicting aliases and malformed tenant/role claim shapes before authorization context creation, and explicitly rejects unsupported JWT `crit` headers | RBAC and ABAC/purpose/sensitivity/evidence policy exists in `src/sdp/policy.py` | Merge PR #58 after independent review and protected checks; preserve tenant, purpose, row-filter, masking, and evidence checks. Keep the repo-wide security gate green: `cryptography` must be pinned at `50.0.0` or newer in the source and every hash-locked requirements artifact after CVE-2026-69247. |
| `clearfolio` | No production OIDC/JWT verifier; current runtime is a gateway/header tenant scaffold documented in `docs/security/2026-07-02-auth-tenant-model.md` | Permission checks and tenant ownership are implemented, with optional gateway HMAC; the caller identity is not yet a Keyverse-verified token | Keep production fail-closed. Replace public header trust with Keyverse issuer/audience/JWKS verification at the service or a cryptographically trusted gateway, then map `org`/`sub`/roles/scopes and retain same-tenant checks. |
| `contextual-orchestrator` | PR #109 recognizes the Keyverse RP boundary through a deployment-injected verifier; stacked PR #110 requires a verified identity with subject/org/workspace/scopes and rejects boolean-only decisions | Scope RBAC is enforced by the requested scope; PR #110 adds exact org/workspace metadata ABAC plus tenant ownership checks for workflow, evaluation, and batch resources. Main is still unchanged and the deployment adapter must still prove issuer/audience/signature/expiry/JWKS/rotation. | Merge #109 then #110 through normal protected review. Keep the external adapter fail-closed, do not add JWT parsing to the stdlib core, migrate or recreate ownerless legacy resources, and add deployment acceptance evidence before exposing multi-tenant work. |
| `newsdom-api` | No Keyverse OIDC integration; protected `develop` now contains PR #595, which makes the local bearer boundary fail closed by default and permits anonymous parsing only through explicit `NEWSDOM_ALLOW_ANONYMOUS=true` | No application RBAC/ABAC; it is a PDF-to-DOM sidecar | Keep it private infrastructure while it has no user authorization model. If reachable beyond a trusted internal gateway, require a Keyverse-aware gateway or verified service boundary; never enable the anonymous opt-in on an exposed deployment. The merged change also remediates the current `pypdf` Trivy findings and includes the review fixes at `3025be1` (startup credential registry, authenticated examples, healthcheck executable-bit check, and complete 401 assertions). |

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
   semantic-data-portal PR #58 adds
   `tests/test_authz.py::test_keyverse_org_claim_must_be_a_non_empty_string`
   so array/object `org` claims fail closed before `ActorContext`; its current
   exact head is `47e2215` and remains `active-PR` evidence. It also adds
   `tests/test_authz.py::test_keyverse_org_alias_cannot_hide_behind_tenant_id`
   and `tests/test_authz.py::test_keyverse_conflicting_tenant_aliases_fail_closed`
   so malformed, null, blank, and conflicting aliases cannot be hidden by
   `tenant_id` precedence. The exact-head Strix scan on the preceding SDP head
   reported VULN-0001 for a suspected critical JWT `crit`-header injection at
   `src/sdp/authz.py`. PyJWT already rejected the unsupported extension, but the
   application boundary did not state that policy explicitly; PR #58 now
   rejects every `crit` header because SDP supports no critical extensions and
   covers it with
   `tests/test_api.py::test_oidc_jwks_verification_rejects_unsupported_critical_header`.
   Naruon PR #1321 adds
   `backend/tests/test_auth_real.py::test_keyverse_oidc_session_with_verified_claims`
   and `backend/tests/test_auth_real.py::test_keyverse_oidc_session_rejects_missing_issued_at`
   for the exact issuer/audience profile and required `iat`; its current exact
   head is `ca6ccba` and remains `active-PR` evidence after its `develop`
   conflict was resolved; the protected Checks are still running. pg-erd-cloud PR
   #855 adds
   `backend/tests/test_auth_security.py::test_keyverse_organization_claim_is_required_and_exact`
   and an API-key bypass regression and remains `active-PR` evidence; NewsDOM
   PR #595 adds default-deny and explicit-anonymous-mode tests, with the review
   follow-up at `3025be1`, and is now present on protected `develop` at
   `3d0426bf`. The maturity label records merge evidence, not Keyverse-aware
   authorization readiness.
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

## References

Bertocci, V. (2021). *JSON Web Token (JWT) profile for OAuth 2.0 access tokens*
(RFC 9068). Internet Engineering Task Force. https://doi.org/10.17487/RFC9068

Jones, M., Bradley, J., & Sakimura, N. (2015). *JSON Web Token (JWT)*
(RFC 7519). Internet Engineering Task Force. https://doi.org/10.17487/RFC7519

Jones, M., & Hardt, D. (2012). *The OAuth 2.0 authorization framework: Bearer
token usage* (RFC 6750). Internet Engineering Task Force.
https://doi.org/10.17487/RFC6750

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2023).
*OpenID Connect Core 1.0 incorporating errata set 2*. OpenID Foundation.
https://openid.net/specs/openid-connect-core-1_0.html

Sheffer, Y., Hardt, D., & Jones, M. (2020). *JSON Web Token best current
practices* (BCP 225, RFC 8725). Internet Engineering Task Force.
https://doi.org/10.17487/RFC8725

Temoshok, D., Richer, J., Choong, Y.-Y., Fenton, J., Lefkovitz, N.,
Regenscheid, A., & Galluzzo, R. (2025). *Digital identity guidelines:
Federation and assertions* (NIST SP 800-63C-4). National Institute of Standards
and Technology. https://doi.org/10.6028/NIST.SP.800-63C-4
