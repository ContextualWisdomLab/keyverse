# Changelog

All notable changes to Keyverse are documented in this file. The format follows
Keep a Changelog, and releases use semantic versioning.

## [Unreleased]

### Added

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
- Rejected raw C0 controls, DEL, invalid ports, malformed Base64, non-X.509
  DER, PEM-wrapped manual certificates, and empty rollover certificate entries
  before federation desired state can be persisted.
- Hardened federation operator examples against shell xtrace leakage, HTTP
  redirects, ambiguous preflight responses, and non-standalone recovery steps.
- Raised non-success health responses correctly in the restricted stdlib HTTP
  opener.
- Replaced a potentially expensive registration email regular expression with
  deterministic bounded parsing.
- Made standalone audit history survive container replacement.
