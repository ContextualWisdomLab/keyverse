# Changelog

All notable changes to Keyverse are documented in this file. The format follows
Keep a Changelog, and releases use semantic versioning.

## [Unreleased]

### Added

- The hourly product-development prompt now reads the exact-head gap baseline and
  open PR/issue inventory before selecting an independent buyer-visible slice.
- A dated product and technical gap baseline that records the live PR/Issue
  queue, exact-head Check evidence, buyer-visible authorization and runtime
  acceptance gaps, and the protected hourly loop.
- ADR-0008 and the non-fork RP authorization matrix, requiring explicit
  Keyverse token validation, tenant/resource ABAC, bounded RBAC, and
  cross-tenant acceptance evidence per application.
- A closed optional OIDC relying-party mapper profile with one self-pinned
  access-token audience, bounded `role`, `org`, and `workspace` hardcoded claims,
  canonical mapper ordering, Keycloak-generated-ID/order normalization, and a
  secret-free `naruon-web` runtime desired-state template.
- ADR-0009's confidential `lineageweave-web` account-derived mapper profile:
  same-client roles plus exact scalar `org` and `workspace` account attributes,
  with no static/dynamic mixing, a secret-free deployment template, and
  reconciliation regression coverage.
- The reserved `lineageweave-web` client now rejects hardcoded authorization
  claims, while Compose keeps the account service fail-closed until its
  post-import account-profile bootstrap succeeds.
- A normative LineageWeave tenant mapping: `org` is the opaque external tenant
  key, `workspace` is its child namespace, ambiguous or multi-membership
  resolution fails closed, and lifecycle changes require a new token or
  session renewal; no generic `tenant` mapper was introduced.
- Durable, secret-free OIDC relying-party desired-state CRUD and reconciliation
  with exact `clientId` matching, duplicate fail-closed behavior, post-mutation
  re-observation, canonical apply receipts, realm-rebuild recovery, per-client
  serialization, and remote-first deletion.
- Authenticated, side-effect-free OIDC relying-party client preflight with
  authorization code plus PKCE `S256`, exact HTTPS redirect/origin/logout
  closure, public/confidential consistency, portable scopes, and non-reflective
  hostile-input handling.
- Authenticated, side-effect-free LDAP and Active Directory component preflight
  with LDAPS-only transport, RFC 4514 distinguished-name validation, closed
  read-only policy, bounded timeouts, and bind-secret redaction.
- An hourly fail-closed NVIDIA NIM OpenCode loop that isolates model credentials,
  requires a production-code/test/changelog vertical, independently verifies
  the sealed patch, and opens one draft PR through a dedicated publication
  token.
- Fail-closed OIDC and Keycloak-OIDC federation preflight with pinned HTTPS
  endpoints, JWKS signature validation, PKCE `S256`, confidential-client
  authentication, and RFC 6749 scope validation before desired-state writes.
- A deployment-ready external OIDC provider template for standalone, CWL,
  and Naruon integrations with `trust_email=false` by default.
- Side-effect-free federation preflight validation with redacted operator
  results, explicit SAML issuer pinning, mandatory signature validation, and
  metadata-backed or cryptographically parsed manual X.509 certificate trust.
- An operational external-federation onboarding and recovery guide for
  standalone, CWL platform, and Naruon-integrated deployments.
- Password-free headless registration that sends one bounded Keycloak action
  email for address verification and passkey enrollment, with failure-atomic
  account rollback.
- Modular product-facing Keycloak Admin API extensions for registration and
  runtime identity-provider federation.
- Runtime federation desired-state convergence with explicit applied-state
  reporting and fail-closed operator-response redaction.
- Router-level validation for decoded privileged and SCIM path parameters,
  including protocol-native SCIM error responses.
- Persistent Compose and Helm storage for audit and user-operation lock data.
- Optional Helm enforcement of immutable account-unification image digests.
- Concurrency and lifecycle regressions for SQLite-backed configuration, audit,
  and mutation-lock persistence.

### Changed

- Rebound the product and technical gap baseline to live Keyverse PR #100 exact
  head `84e0c759f9d757452f109b9c5c96253d54b85853`, recording zero unresolved
  threads and treating pending Strix and Devin Review as unverified rather than
  inheriting predecessor `25cf0e6` Checks.
- Bound the product and technical gap baseline to Keyverse PR #100 exact head
  `25cf0e63760cf22cf73a1322eb1953b0dd2aada7` with zero unresolved threads and
  an in-progress Strix Check recorded as unverified, and re-listed #113, #112,
  #103, #101, #83 plus `.github` #1233/#1252 with no source-fault Check
  failures.
- Refreshed the product and technical gap baseline to the 2026-08-23 exact-head
  queue (#113, #112, #103, #101, #100, #83), recorded independent approval as
  the remaining merge blocker, closed #110/#111 and stacked #115 as historical
  rather than open-PR work, and named G0 then G4 as the next buyer-visible
  order while the queue stays non-empty.
- Refreshed the product and technical gap baseline with the current exact-head
  PR inventory, including the lockfile repair review gate and the requeued
  `lineageweave-web` Checks; predecessor evidence remains non-transferable.
- Added the active PR #113 SCIM deactivation-lock state and the current PR #103
  Strix/IDOR evidence to the gap baseline; neither is represented as protected
  main until exact-head review and merge evidence exists.
- Refreshed the PR #103 Strix evidence with its exact failed run/job and kept
  the contradictory operator-admin IDOR interpretation fail-closed pending
  independent security validation.
- The Helm realm-import operator runbook now migrates the legacy
  `realm-cwl.json` ConfigMap key to `cwl-realm.json` before rollout, preserving
  a rollback copy and requiring post-rollout realm discovery verification.
- Account-derived OIDC claim mappers are now limited to the ADR-0009
  `lineageweave-web` profile, and a non-string observed mapper type is treated
  as reconciliation drift rather than causing an exception. Operator guides now
  consistently name issued `org` (company) and `workspace` (PU) claims.
- The post-import LineageWeave profile bootstrap now reports which required
  `org` or `workspace` account attribute is missing from the read-back profile
  before it stops the dependent service.
- Relying-party deployment controllers now send validated, secret-free metadata
  to Keyverse desired-state PUT instead of applying client representations
  directly to Keycloak; confidential credential placement remains a separate
  secret-management operation.
- Consolidated the August 2026 runtime, transport, certificate, test,
  lint, and build-backend refresh into one lock-consistent dependency
  graph, and migrated package license metadata to the PEP 639 SPDX
  expression and license-file contract.
- The OIDC RP deployment template is now a closed, secret-free Keycloak client
  representation with exact origins and the portable `basic`, `profile`, and
  `email` scope profile; deployment controllers must preflight it before apply.
- The LDAP deployment template is now a closed, preflight-ready Keycloak
  component payload with `trustEmail=false`, `useTruststoreSpi=always`,
  disabled Kerberos, and no synthetic comment fields.
- The bound Keycloak browser flow is now strictly passkey-only; registration no
  longer creates a bootstrap password or runs a credential janitor.
- The public `naruon-web` access-token lifespan is reduced to five minutes while
  the longer SSO session remains available through token refresh and reissue.
- Registration configuration is all-or-nothing and requires a distinct bearer
  token, relying-party client, HTTPS redirect URI, and bounded action-link
  lifetime.
- Registration throttling is isolated by direct peer address rather than one
  process-wide counter.
- Account merge and SCIM replacement now share the same user-operation lock
  boundary.
- SQLite configuration and audit stores support safe multi-threaded access with
  WAL mode and bounded busy timeouts.
- Application shutdown closes Keycloak, audit, and configuration resources and
  removes temporary test-only mutation-lock sidecars deterministically.
- Keycloak Admin API requests refresh an expired bearer token once, including
  account creation and action-email enrollment.

### Fixed

- Prevented Keycloak's omitted empty account-role `rolePrefix` read-back from
  causing perpetual relying-party drift, while retaining fail-closed handling
  for all other missing or changed mapper configuration.
- Allowed passwordless registration to create an identity-only account before
  administrator assignment of `org` and `workspace`; routing remains blocked
  until both claims are assigned and downstream validation accepts them.
- Disabled 37 orphaned active GitHub Actions registry identities whose
  repository paths were absent from protected `main`, while preserving the
  four supported workflow identities and two GitHub-owned dynamic Dependabot
  identities; recorded exact before/after reconciliation and operational smoke
  evidence for issue #99.
- Packaged the portable Keycloak realm under the required `cwl-realm.json`
  directory-import name in Compose and mapped it in Helm, with a deployment
  contract that prevents a healthy-but-empty identity realm.
- Prevented relying-party inventory from silently accepting a KV key/body
  identity mismatch, rejected unsafe live or `Location`-derived client UUIDs,
  and aligned exact client discovery with Keycloak's documented
  `clientId` plus `search=false` query mode.
- Restored authenticated, allowlisted Keycloak component transport for LDAP
  reconciliation, canonicalized private apply receipts across JSON key order,
  and removed completed one-shot implementation workflows and scripts.
- Prevented LDAP and Active Directory source configuration from reaching
  Keycloak with cleartext transport, unresolved private values, malformed DNs,
  writable or Kerberos-enabled policy, trusted-email linking, unsafe component
  shapes, duplicate endpoints, or effectively unbounded login-path timeouts.
- Prevented external OIDC broker configuration from persisting cleartext or
  unpinned endpoints, disabled token-signature/JWKS checks, missing PKCE,
  unsupported client authentication, remote discovery imports, or OAuth-only
  scope sets that omit `openid`.
- Upgraded `cryptography` to 50.0.0 to remediate CVE-2026-69247 while
  retaining the supported DER X.509 certificate parsing API.
- Converted the employer ADFS template from an incompatible raw Keycloak
  representation to the closed Keyverse desired-state API contract.
- Corrected root and template documentation that still claimed employer
  federation was embedded in the portable realm.
- Prevented registration races from surfacing raw Keycloak duplicate-user
  errors by mapping exact HTTP 409 responses to a stable product conflict.
- Prevented unusable registration orphans by deleting accounts when Keycloak
  rejects the verification/passkey action email.
- Prevented external network calls from executing while the federation desired-
  state storage lock is held.
- Prevented unknown federation configuration keys, credentials, and private
  values from being echoed through list, get, or update responses.
- Rejected Unicode-confusable federation aliases outside the explicit ASCII
  slug alphabet.
- Rejected raw C0 controls, DEL, invalid ports, insecure HTTP SSO or metadata
  endpoints, malformed Base64, non-X.509 DER, PEM-wrapped manual certificates,
  and empty rollover certificate entries before federation desired state can
  be persisted.
- Hardened federation operator examples against shell xtrace leakage, HTTP
  redirects, ambiguous preflight responses, and non-standalone recovery steps.
- Raised non-success health responses correctly in the restricted stdlib HTTP
  opener.
- Replaced a potentially expensive registration email regular expression with
  deterministic bounded parsing.
- Made standalone audit history survive container replacement.
