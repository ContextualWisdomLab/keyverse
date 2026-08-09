# Keyverse Test Strategy

**Status:** Accepted quality baseline  
**Last reviewed:** 2026-08-09

## Mandatory gates

- Ruff and Python compilation;
- public production docstrings 100%;
- production statement coverage 100%;
- production branch coverage 100%;
- complete pytest suite;
- realm/template/package/Compose/Helm validation as applicable;
- exact-current-head CodeQL, Semgrep, Security Scan, review, and branch protection.

Skipped, cancelled, absent, stale, predecessor-head, synthetic-only, rate-limited, or failed evidence is never passing.

## Authentication and account tests

- passwordless browser flow contains WebAuthn passwordless and no password authenticator;
- registration creates no password and rolls back if enrollment initialization fails;
- exact `(IdP, subject)` matching;
- verified-email matching only;
- unverified email never auto-links/merges;
- explicit link behavior;
- survivor/duplicate tombstone semantics;
- merge idempotency and rollback;
- merge/SCIM shared lock concurrency.

## SCIM tests

Use realistic create/read/update/replace/delete lifecycle, authoritative/deprovisioning behavior, invalid identifiers, tombstones, retry/idempotency, hostile strings, and concurrent user mutation. Verify safe mapping to Keycloak and no accidental resurrection of merged duplicates.

## Federation preflight/reconciliation

### SAML/OIDC

- closed schema and protocol-specific required fields;
- untrusted/invalid issuer/redirect/trust-email policy;
- no discovery/metadata/network/store/Keycloak side effects during preflight;
- exact remote lookup/duplicate handling;
- desired-state-before-mutation and exact post-mutation receipt;
- delete/recovery behavior;
- public response/log redaction.

### LDAP/AD

- LDAPS-only current profile;
- read-only mode and Kerberos disabled;
- `trustEmail=false`;
- RFC-valid DN and bounded config;
- no DNS/socket/bind/search/store/Keycloak side effects during preflight;
- exact component reconciliation, duplicates, remote-first delete;
- controlled real integration lane for bind/search/login after explicit apply, using synthetic test identities/approved environment.

## Relying-party tests

- authorization code + PKCE S256;
- redirect/origin/logout exact-policy matrices;
- public/confidential consistency;
- exact portable scopes;
- clientId key and Keycloak UUID integrity;
- exact Keycloak search behavior;
- duplicate/zero/one remote client classification;
- create/update/delete/re-observation/receipt;
- secret-free desired state and separate secret provision;
- controlled authorization-code/login/logout/token audience acceptance.

PR #72 mapper tests remain active-PR evidence until merged. They should cover exact audience mapper, bounded `role`/`org`/`workspace`, Keycloak-generated mapper IDs/order, and rejection of scripts/arbitrary claims/classes.

## Deployment and persistence tests

- PostgreSQL/KV migrations and rollback for Keyverse-owned records;
- configuration bootstrap and runtime store behavior;
- user-operation locks across processes;
- desired-state idempotency/concurrency;
- secret scanning and redacted logs;
- Compose health/readiness;
- Helm template/install/upgrade/rollback where supported;
- backup/restore of Keyverse-owned audit/config/intent/receipts and supported Keycloak database recovery procedure.

## Security/adversarial tests

Mirror `docs/THREAT_MODEL.md`: malicious IdP/LDAP URLs, path/resource IDs, duplicate Keycloak objects, protocol confusion, account linking attacks, secret reflection, oversized payloads, stale receipts, SCIM races, redirect manipulation, mapper overreach, and automation credential/check-classification failures.

## Documentation contract

CI should require PRD, TRD, Architecture, UML, ERD, Threat Model, Test Strategy, Operability, Traceability, ADR index, README, AGENTS, CLAUDE, CHANGELOG, and authoritative doctoring/operations links. It must assert PR #72/#74 remain active-PR claims until integrated.

## Release acceptance

Release evidence includes protected-head identity protocol tests, real deployment acceptance in an approved environment, SBOM/image provenance/digests, migrations/rollback, readiness plus login/federation/SCIM/RP tests, and independent review. Preflight unit success is never treated as full external federation readiness.