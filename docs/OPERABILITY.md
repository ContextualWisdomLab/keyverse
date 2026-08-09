# Keyverse Operability, Recovery, and Release Guide

**Status:** Accepted cross-cutting operating baseline  
**Last reviewed:** 2026-08-09

Feature-specific procedures under `docs/operations/`, federation/RP onboarding, and deployment READMEs remain authoritative for their slices. This guide defines the shared operating model and evidence needed before declaring the identity platform healthy or release-ready.

## Health model

Distinguish these conditions:

1. **process liveness:** Keycloak/admin process responds;
2. **component readiness:** database/config/bootstrap and core dependencies are usable;
3. **desired-state convergence:** configured federation/directory/RP state matches Keycloak;
4. **protocol acceptance:** controlled login/logout/token/SCIM/bind/search behavior succeeds;
5. **downstream authorization acceptance:** RP accepts expected issuer/audience/claims and applies its own authorization policy.

A lower-level green state never implies a higher-level state.

## Key SLIs

- Keycloak/admin readiness and latency;
- login/passkey success/error rates;
- SCIM mutation success/conflict/retry/lock contention;
- account merge/link outcomes and rollback/tombstone anomalies;
- desired-state drift and reconciliation age;
- federation/LDAP/RP apply/re-observation failures;
- duplicate remote resource detections;
- user-operation lock wait/expiry/recovery;
- token issuer/audience/claim acceptance failures;
- database/storage availability and transaction errors;
- secret/config bootstrap failures;
- hourly governance run outcomes without false-green classification.

Do not put raw tokens, secrets, passwords/bind credentials, protected private payloads, or unnecessary PII into metrics/logs.

## Federation onboarding runbook

1. render private tenant configuration from approved KV/secret source;
2. run authenticated side-effect-free Keyverse preflight;
3. review exact policy result;
4. persist/apply desired state through the owning reconciliation path;
5. verify exact post-mutation Keycloak state/receipt;
6. for LDAP/AD perform controlled bind/search/login acceptance after explicit apply;
7. for SAML/OIDC perform controlled login/issuer/subject/email/trust checks;
8. monitor convergence/errors;
9. retain rollback data until acceptance criteria expire.

## RP onboarding runbook

1. submit secret-free client representation;
2. preflight redirects/origins/logout/PKCE/scopes/type;
3. reconcile exact Keycloak client and receipt;
4. provision confidential secret through the separate secret-management path if needed;
5. configure RP securely;
6. run authorization-code/PKCE login/logout/token audience/claim acceptance;
7. validate downstream authorization separately from authentication.

PR #72's mapper profile requires the same acceptance after merge: operators must test the **Naruon** product login/token/authorization journey using the `naruon-web` RP client ID and verify the expected audience and bounded claims. Mapper unit tests alone do not prove Naruon product authorization readiness.

## Account merge recovery

Merge and SCIM full replacement (`PUT`) must hold the shared operation lock. Protected-main `PATCH active=false` is not currently inside that shared-lock guarantee and must not be treated as transactionally serialized with merge. On failure, classify whether state changed in Keycloak, Keyverse audit, linked identities, or tombstone status. Re-observe before retry. Never infer a retry is safe solely from the previous HTTP response. Preserve survivor and duplicate lineage in audit.

## Desired-state recovery

On controller/API crash after intent but before receipt:

- read persisted desired state;
- query exact remote Keycloak state;
- classify converged, absent, duplicate, or drifted;
- reconcile idempotently;
- write receipt only after exact re-observation and bind it to the desired-state version/hash that was applied.

On delete, keep local intent until remote-first deletion has succeeded where required.

## Database/backup

Back up Keycloak PostgreSQL and Keyverse-owned configuration/audit/intent/receipt state according to deployment RPO/RTO. Restore through supported Keycloak/database procedures, then run reconciliation and controlled authentication/provisioning acceptance. Do not edit unsupported Keycloak internal tables as a normal recovery technique.

## Upgrade/rollback

- review Keycloak release/migration notes and Keyverse CHANGELOG/ADRs;
- rehearse database migration and Helm/Compose upgrade;
- validate realm/config/template compatibility;
- run merge/SCIM/federation/RP suites;
- canary controlled login/provisioning;
- roll back application/config where safe and use supported DB backup/restore for incompatible schema migrations;
- re-run convergence and protocol acceptance after rollback.

## Automation incident RCA

PR #74 demonstrates that a workflow can appear successful while doing no useful work if a GitHub API gate fails open. Scheduled governance must classify transport failure separately from a valid empty/unhealthy result, fit its time budget, keep provider secrets in the broker phase only, and require exact `success` for protected evidence. After PR #74 merges, operational closure requires a real protected-main scheduled/manual run.

## Release gate

Release only after protected-head CI/security/review, 100% coverage/docstrings, realm/package/deployment validation, migrations/rollback/backup, passkey/federation/SCIM/RP controlled acceptance, secret scan, SBOM/provenance/image digest, runbooks/support, and CHANGELOG/version artifacts are coherent. A merged PR is not a release by itself.