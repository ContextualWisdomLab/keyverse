# Changelog

All notable changes to Keyverse are documented in this file. The format follows
Keep a Changelog, and releases use semantic versioning.

## [Unreleased]

### Added

- Modular product-facing Keycloak Admin API extensions for self-registration,
  passwordless credential retirement, and runtime identity-provider federation.
- Runtime federation desired-state convergence with operator-response secret
  redaction.
- Router-level validation for decoded privileged and SCIM path parameters.
- Concurrency tests for SQLite-backed configuration and audit persistence.

### Changed

- Account merge and SCIM replacement now share the same user-operation lock
  boundary.
- SQLite configuration and audit stores now support safe multi-threaded access
  with WAL mode and bounded busy timeouts.
- Application shutdown now cancels background work and closes Keycloak,
  configuration, and audit resources deterministically.
- Keycloak Admin API requests refresh an expired bearer token once, including
  account creation.

### Fixed

- Prevented bootstrap-account orphans by rolling back failed registration
  initialization.
- Prevented federation credentials from being echoed through list, get, and
  update responses.
- Replaced a potentially expensive registration email regular expression with
  deterministic bounded parsing.
- Removed sensitive credential terminology from operational log messages.
