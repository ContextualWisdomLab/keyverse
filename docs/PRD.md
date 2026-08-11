# Keyverse Product Requirements Document

**Status:** Accepted cross-cutting product baseline for protected `main` at `c8968ec1e68fab16d0ad8216fb5c8fd0b385e95f`  
**Last reviewed:** 2026-08-09

## 1. Product purpose

Keyverse is the ContextualWisdomLab ecosystem identity control plane: a standalone and embeddable Keycloak-based IdP plus Keyverse-owned control services for passwordless authentication policy, external federation desired state, SCIM provisioning, account unification, relying-party lifecycle, safe deployment preflight/reconciliation, and auditable user operations.

Its job is to let CWL products consume stable standards-based identity without each product reimplementing Keycloak Admin REST, federation trust policy, credential handling, merge semantics, or provisioning safety.

## 2. Current protected-main capabilities

- portable Keycloak `cwl` realm with passwordless-first WebAuthn and no password authenticator for ecosystem-local accounts;
- OIDC/OAuth relying-party service for CWL applications and SAML brokering for external identity providers;
- inbound SCIM v2 shim for lifecycle provisioning;
- account linking/unification and survivor-wins merge with verified-email policy and tombstone behavior;
- user-operation locking across merge and SCIM full-replacement (`PUT`) paths;
- password-free registration enrollment action flow;
- deterministic, side-effect-free SAML/OIDC federation preflight and durable desired-state reconciliation;
- deterministic LDAPS-only directory preflight and durable Keycloak component desired-state reconciliation;
- secret-free OIDC relying-party desired-state preflight/reconciliation with exact Keycloak client identity and receipts;
- standalone Compose and Helm deployment modes with readiness probes;
- configuration/secret bootstrap via KV/DB boundary rather than application environment as runtime source of truth;
- 100% production statement/branch/docstring quality gates and protected review/security workflows.
- an explicit per-RP Keyverse token-validation and downstream ABAC/RBAC acceptance boundary; application login alone is not authorization readiness.

The current SCIM `PATCH active=false` deprovisioning path is not protected by the shared cross-process user-operation lock used by merge and full replacement. It must not be represented as transactionally serialized with merge until a source change and concurrency regression prove that boundary.

## 3. Active-PR boundaries

- PR #72 adds a closed OIDC RP mapper profile for exactly one audience mapper plus bounded `role`, `org`, and `workspace` hardcoded claims; it remains **active-PR** and is not protected-main behavior until merged.
- PR #74 repairs the hourly product-development GitHub API/egress/time-budget/evidence boundary; it remains **active-PR** operational-governance work until merged and then proven by a protected-main run.

## 4. Primary users

- **CWL application team:** onboard an OIDC relying party without owning IdP internals.
- **Enterprise deployment/identity engineer:** connect SAML/OIDC/LDAP/AD sources through explicit safe desired-state/apply workflows.
- **IGA/HR integration engineer:** provision/deprovision users through SCIM.
- **Identity administrator:** link or merge accounts with deterministic verified-evidence rules and audit.
- **Security/SRE:** operate Keycloak/PostgreSQL/admin service with controlled secrets, readiness, rollback, and immutable evidence.

## 5. Product invariants

1. Keyverse is the identity hub; employer/customer directories are external federation sources, not the hub.
2. Unverified email never authorizes automatic account linking or merge.
3. Exact `(identity_provider, subject)` is stronger identity evidence than email.
4. Portable realm configuration contains no customer-specific federation secret/configuration and no confidential RP secret.
5. Preflight is side-effect-free and does not perform DNS/network/bind/search/store/Keycloak mutation unless its endpoint explicitly owns apply/reconciliation.
6. Private rendered apply payloads and credentials never appear in public responses/logs/source/templates.
7. Desired state is recorded before external mutation where the lifecycle requires recoverable intent.
8. Mutation receipts are written only after exact live re-observation confirms the result.
9. Duplicate remote identity/client/component matches fail closed; Keyverse does not pick an arbitrary duplicate.
10. Delete is remote-first where a stale desired-state receipt would otherwise falsely claim deletion.
11. Relying-party credential provisioning is a separate secret-management responsibility from secret-free client desired state.
12. Passwordless-local identity must not silently fall back to a password authenticator.
13. Runtime application code consumes configuration from the approved KV/DB boundary; environment is bootstrap transport only.
14. Tenant/application authorization must not be inferred from client ID, UUID, email, or federation source name alone.
15. Every non-fork application must explicitly validate the Keyverse issuer, audience, signature, subject, expiry, tenant, and application authorization policy before production exposure.

## 6. Functional requirements

### PRD-FR-001 Passwordless authentication

The portable local account flow SHALL require passwordless WebAuthn/passkey enrollment/authentication policy and SHALL not include an ordinary password authenticator for ecosystem-local accounts.

### PRD-FR-002 Federation

Keyverse SHALL support deployment-owned external SAML/OIDC and LDAP/AD onboarding through closed schemas, side-effect-free preflight, explicit trust/email-link policy, durable desired state where owned, reconciliation, redacted observability, and controlled acceptance evidence.

### PRD-FR-003 Account unification

Account matching and merge SHALL follow exact subject → verified email → explicit operator link precedence. Merge SHALL preserve a canonical survivor, disable/tombstone duplicates, retain auditable lineage, and coordinate full-replacement SCIM writes through the shared user-operation lock. Any additional SCIM read-modify-write operation may claim the same serialization guarantee only after it uses that lock and has a concurrency regression covering merge/tombstone interaction.

### PRD-FR-004 SCIM

Inbound SCIM SHALL map authoritative enterprise lifecycle operations into Keycloak while preserving Keyverse merge/tombstone invariants and failing closed on unsafe identity ambiguity. Protected-main currently serializes merge with full SCIM `PUT` replacement; the `PATCH active=false` path is a narrower deprovisioning path and is not yet part of that shared-lock guarantee.

### PRD-FR-005 Relying-party lifecycle

RP registration SHALL validate exact HTTPS redirect/origin/logout and authorization-code + PKCE profile, store secret-free desired state, reconcile an exact Keycloak client, re-observe before receipt, and keep confidential secret placement separate. Native loopback redirect profiles are not part of the current protected-main RP trust contract unless separately introduced with an Accepted ADR and synchronized security/test/traceability rules.

### PRD-FR-006 Claims/profile lifecycle

Optional claim expansion SHALL be closed and least-privilege. New audience/claim mapper profiles require explicit typed policy, no script/user-attribute/group/regex arbitrary mapper classes unless separately accepted, and downstream authorization acceptance tests before claiming application readiness.

### PRD-FR-007 Downstream authorization boundary

Every RP SHALL maintain an explicit Keyverse integration profile and SHALL
validate issuer, signature/algorithm, expiry, subject, and audience before
applying authorization. Tenant/resource/purpose constraints SHALL be evaluated
before roles, scopes, or groups. Missing cross-tenant denial, resource ownership,
or production fail-closed evidence SHALL keep the RP deployment-restricted.

### PRD-FR-008 Configuration/secrets

Secrets SHALL be sourced through private deployment-controlled stores/handles. Logs, responses, CLI args, checked-in templates, and desired-state records must not contain raw secrets unless the exact durable store is designed to own them encrypted.

### PRD-FR-009 Deployment and readiness

Compose/Helm deployments SHALL expose component readiness that distinguishes Keycloak/admin/database/configuration reachability from full end-to-end login/federation acceptance. A green preflight is not a successful login claim.

### PRD-FR-010 Audit and recovery

Privileged identity and desired-state operations SHALL produce auditable intent/outcome evidence sufficient for reconciliation/rollback without exposing protected secret values.

## 7. Security/privacy requirements

- passkey/federation/SCIM/OIDC/SAML/JWT behaviors follow current standards and Keycloak-supported contracts;
- verified-email and issuer/subject/audience validation are explicit;
- dynamic privileged path segments and remote Location identifiers are validated before transport/use;
- directory binds use LDAPS under the current accepted profile;
- secret/PII handling uses least privilege, encryption, bounded retention, audit, controlled export, and private apply payloads rather than destructive blanket masking;
- automation credentials/reviewer/merge/release authority remain separated.

## 8. Non-goals

- replacing Keycloak with a proprietary identity engine;
- embedding employer/customer ADFS/LDAP secrets in portable realm config;
- allowing every RP to administer Keycloak directly;
- automatically linking on unverified email;
- treating preflight as proof of external network/login success;
- storing confidential RP secrets in secret-free desired-state templates;
- giving an autonomous model authority to approve/merge/release identity policy.

## 9. Quality and release

Release requires current protected-head exact CI/security/review, 100% production statement/branch/docstring gates, package/realm/Compose/Helm/template validation, migration/rollback and backup/recovery evidence, SBOM/provenance/image digest, controlled login/federation/SCIM/RP acceptance, and CHANGELOG/version/artifact consistency. No current repository version should be promoted merely because a feature PR is green.
