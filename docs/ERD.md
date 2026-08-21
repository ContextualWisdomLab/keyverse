# Keyverse Logical and Persistence ERD

**Status:** Accepted cross-cutting data model. Exact Keycloak internal schema remains Keycloak-owned.  
**Last reviewed:** 2026-08-18

Keyverse persists its own configuration, desired-state, receipts, merge audit, user-operation locks, authorization grants, SSO combination scopes, and hashed application tokens while Keycloak/PostgreSQL owns canonical IdP users/sessions/clients/federation runtime state. Orgmetra remains the employment-tree system of record; Keyverse stores grants against org-path nodes and does not persist Orgmetra `organization_unit` rows as source of record. This ERD models Keyverse-owned durable records and their relation to external Keycloak identities without pretending to own Keycloak's internal tables.

```mermaid
erDiagram
    IDP_CONFIG_ENTRY }o--|| TENANT_DEPLOYMENT : scoped_to
    FEDERATION_SOURCE }o--|| TENANT_DEPLOYMENT : scoped_to
    DIRECTORY_FEDERATION_SOURCE }o--|| TENANT_DEPLOYMENT : scoped_to
    RELYING_PARTY_SOURCE }o--|| TENANT_DEPLOYMENT : scoped_to
    AUTHORIZATION_SOFTWARE_UNIT_GRANT }o--|| TENANT_DEPLOYMENT : scoped_to
    AUTHORIZATION_MENU_GRANT }o--|| TENANT_DEPLOYMENT : scoped_to
    SSO_COMBINATION_SCOPE }o--|| TENANT_DEPLOYMENT : scoped_to
    APPLICATION_ACCESS_TOKEN }o--|| TENANT_DEPLOYMENT : scoped_to

    FEDERATION_SOURCE ||--o{ FEDERATION_APPLY_RECEIPT : produces
    DIRECTORY_FEDERATION_SOURCE ||--o{ DIRECTORY_FEDERATION_APPLY_RECEIPT : produces
    RELYING_PARTY_SOURCE ||--o{ RELYING_PARTY_APPLY_RECEIPT : produces

    KEYCLOAK_USER_REFERENCE ||--o{ ACCOUNT_MERGE_AUDIT : survivor_or_duplicate
    KEYCLOAK_USER_REFERENCE ||--o| USER_OPERATION_LOCK_STATE : guarded_by
    KEYCLOAK_USER_REFERENCE ||--o{ EXTERNAL_IDENTITY_LINK : owns
    EXTERNAL_IDENTITY_LINK }o--|| FEDERATION_SOURCE : originates_from

    TENANT_DEPLOYMENT {
      uuid tenant_deployment_id PK
      text deployment_name
      text deployment_status_code
      timestamptz created_at
    }

    IDP_CONFIG_ENTRY {
      uuid idp_config_entry_id PK
      uuid tenant_deployment_id FK
      text config_key
      text protected_value_ref
      text config_version
      timestamptz updated_at
    }

    FEDERATION_SOURCE {
      uuid federation_source_id PK
      uuid tenant_deployment_id FK
      text federation_alias
      text protocol_code
      jsonb secret_free_desired_state
      text desired_state_hash
      text lifecycle_status_code
      timestamptz updated_at
    }

    FEDERATION_APPLY_RECEIPT {
      uuid federation_apply_receipt_id PK
      uuid federation_source_id FK
      uuid apply_attempt_id UK
      text desired_state_hash
      text keycloak_resource_id
      text observed_state_hash
      text apply_outcome_code
      timestamptz observed_at
    }

    DIRECTORY_FEDERATION_SOURCE {
      uuid directory_federation_source_id PK
      uuid tenant_deployment_id FK
      text directory_alias
      jsonb private_desired_state
      text desired_state_hash
      text lifecycle_status_code
      timestamptz updated_at
    }

    DIRECTORY_FEDERATION_APPLY_RECEIPT {
      uuid directory_federation_apply_receipt_id PK
      uuid directory_federation_source_id FK
      uuid apply_attempt_id UK
      text desired_state_hash
      text keycloak_component_id
      text observed_state_hash
      text apply_outcome_code
      timestamptz observed_at
    }

    RELYING_PARTY_SOURCE {
      uuid relying_party_source_id PK
      uuid tenant_deployment_id FK
      text client_id
      jsonb secret_free_desired_state
      text desired_state_hash
      text lifecycle_status_code
      timestamptz updated_at
    }

    RELYING_PARTY_APPLY_RECEIPT {
      uuid relying_party_apply_receipt_id PK
      uuid relying_party_source_id FK
      uuid apply_attempt_id UK
      text desired_state_hash
      text keycloak_client_uuid
      text observed_state_hash
      text apply_outcome_code
      timestamptz observed_at
    }

    KEYCLOAK_USER_REFERENCE {
      uuid keycloak_user_reference_id PK
      uuid tenant_deployment_id FK
      text keycloak_user_uuid
      text lifecycle_status_code
    }

    EXTERNAL_IDENTITY_LINK {
      uuid external_identity_link_id PK
      uuid tenant_deployment_id FK
      uuid keycloak_user_reference_id FK
      uuid federation_source_id FK
      text external_subject_hash
      boolean email_verified
    }

    ACCOUNT_MERGE_AUDIT {
      uuid account_merge_audit_id PK
      uuid tenant_deployment_id FK
      uuid survivor_user_reference_id FK
      uuid duplicate_user_reference_id FK
      text match_evidence_code
      text operation_outcome_code
      uuid actor_identity_id
      timestamptz occurred_at
    }

    USER_OPERATION_LOCK_STATE {
      uuid user_operation_lock_state_id PK
      uuid keycloak_user_reference_id FK
      text operation_type_code
      text lock_owner_token
      timestamptz acquired_at
      timestamptz lease_expires_at
    }

    AUTHORIZATION_SOFTWARE_UNIT_GRANT {
      text grant_key PK
      text tenant_deployment_id FK
      text org_path
      text software_unit_id
      text effect_code
      jsonb capability_codes
      jsonb attribute_constraints
      text actor_identity_id
    }

    AUTHORIZATION_MENU_GRANT {
      text grant_key PK
      text tenant_deployment_id FK
      text org_path
      text software_unit_id
      text menu_path
      text effect_code
      jsonb capability_codes
      jsonb attribute_constraints
      text actor_identity_id
    }

    SSO_COMBINATION_SCOPE {
      text combination_name
      text tenant_deployment_id FK
      jsonb software_unit_ids
      text actor_identity_id
    }

    APPLICATION_ACCESS_TOKEN {
      text application_token_id
      text tenant_deployment_id FK
      text software_unit_id
      text token_prefix
      text token_hash
      text purpose_code
      jsonb capability_codes
      text lifecycle_status_code
      timestamptz expires_at
      timestamptz created_at
      timestamptz revoked_at
      text actor_identity_id
      text replaced_token_id
    }
```

## Logical uniqueness constraints

UUID primary identifiers are globally unique. The authorization-plane identifiers
are tenant-qualified text keys; `tenant_deployment_id` is a validated lowercase
slug, not a UUID. Human/provider identifiers are scoped to the owning tenant or
federation source and MUST NOT be interpreted as global keys.

| Entity | Required logical uniqueness |
|---|---|
| `IDP_CONFIG_ENTRY` | `(tenant_deployment_id, config_key)` |
| `FEDERATION_SOURCE` | `(tenant_deployment_id, federation_alias)` |
| `DIRECTORY_FEDERATION_SOURCE` | `(tenant_deployment_id, directory_alias)` |
| `RELYING_PARTY_SOURCE` | `(tenant_deployment_id, client_id)` |
| `AUTHORIZATION_SOFTWARE_UNIT_GRANT` | `(tenant_deployment_id, org_path, software_unit_id)` |
| `AUTHORIZATION_MENU_GRANT` | `(tenant_deployment_id, org_path, software_unit_id, menu_path)` |
| `SSO_COMBINATION_SCOPE` | `(tenant_deployment_id, combination_name)` |
| `APPLICATION_ACCESS_TOKEN` | `(tenant_deployment_id, application_token_id)` and unique `token_hash` |
| `KEYCLOAK_USER_REFERENCE` | `(tenant_deployment_id, keycloak_user_uuid)` |
| `EXTERNAL_IDENTITY_LINK` | `(federation_source_id, external_subject_hash)` |

`federation_source_id` defines the identity-provider scope for the external-subject uniqueness rule. Within one federation source, one normalized/hashed external subject may link to at most one Keycloak user reference. This prevents one issuer/provider subject from being attached to multiple users while still allowing unrelated providers to use the same subject string.

Physical migrations must enforce these constraints in the owning Keyverse store. Documentation labels such as `client_id`, `federation_alias`, or Keycloak UUID never authorize cross-tenant lookup by themselves.

Tenant-qualified composite foreign keys are mandatory for cross-entity identity
references. At minimum, the physical schema MUST enforce:

- `EXTERNAL_IDENTITY_LINK (tenant_deployment_id, keycloak_user_reference_id)` →
  `KEYCLOAK_USER_REFERENCE (tenant_deployment_id, keycloak_user_reference_id)`;
- `EXTERNAL_IDENTITY_LINK (tenant_deployment_id, federation_source_id)` →
  `FEDERATION_SOURCE (tenant_deployment_id, federation_source_id)`;
- `ACCOUNT_MERGE_AUDIT (tenant_deployment_id, survivor_user_reference_id)` →
  `KEYCLOAK_USER_REFERENCE (tenant_deployment_id, keycloak_user_reference_id)`;
- `ACCOUNT_MERGE_AUDIT (tenant_deployment_id, duplicate_user_reference_id)` →
  `KEYCLOAK_USER_REFERENCE (tenant_deployment_id, keycloak_user_reference_id)`.

The referenced tenant-qualified pairs MUST be unique keys. A child row carrying
only a globally unique UUID is insufficient evidence of tenant isolation; the
database constraint must reject a mismatched tenant even when application code
or documentation labels are bypassed.

## Identity and authorization rules

- Keycloak UUIDs, federation aliases, RP client IDs, email values, and external subjects are data identifiers, not authorization by themselves.
- Exact external identity key is `(identity_provider, subject)`; verified email may support matching under policy but unverified email never authorizes linking.
- `tenant_deployment_id` is explicit in Keyverse-owned records; deployment/customer separation must not be inferred from realm/resource names.
- The non-persisted `AssignmentSnapshot` decision input also requires an
  explicit `tenant_deployment_id`. Software-unit `attribute_constraints` are
  intentionally absent: ABAC belongs to `AUTHORIZATION_MENU_GRANT`; a
  software-unit payload carrying those constraints is rejected.
- Secrets are referenced through protected values/handles where possible; secret-free desired-state tables must never gain client/bind credentials accidentally.
- Application access tokens store the hashed secret and lifecycle metadata only;
  plaintext tokens and org-tree secrets never appear on grant or combination
  rows. KV storage keys for grants and combinations are tenant-qualified.
- Hierarchical grant paths use `group_company` / `legal_entity` / `business_unit` / `team` / `person`. They do not persist Orgmetra trees and do not reuse LineageWeave `role` / `org` / `workspace` claim names.

## Desired-state and receipt invariant

```mermaid
flowchart LR
    PRIVATE[Private rendered input]
    VALID[Preflight validation]
    INTENT[Versioned desired-state source]
    REMOTE[Keycloak live state]
    RECEIPT[Version-bound apply receipt]

    PRIVATE --> VALID
    VALID --> INTENT
    INTENT --> REMOTE
    REMOTE --> RECEIPT
```

Every apply receipt records the exact `desired_state_hash` that was acted on as well as the canonical `observed_state_hash`, outcome, unique `apply_attempt_id`, and observation time. A receipt is current for a source only when its `desired_state_hash` equals that source's current desired-state hash. The latest current receipt is the greatest `observed_at` among receipts for that exact desired-state hash; a receipt for an older hash is historical evidence and cannot establish convergence for a newer desired state.

Retry handling is idempotency-aware. Reusing the same `apply_attempt_id` must return/reuse the same receipt rather than create a second logical attempt. A retry under a new attempt ID may create another receipt, but it remains a distinct attempt and must still bind to the exact desired-state hash. Delete flows that require remote-first semantics cannot remove local desired state before remote deletion succeeds.

## Keycloak ownership

Users, sessions, roles, groups, credentials, WebAuthn material, IdP runtime representation, LDAP storage components, and RP clients ultimately live in Keycloak's schema/API. Keyverse stores controlled references/intent/receipts but does not duplicate or directly edit unsupported Keycloak internal tables.

## Migration acceptance

Changes to Keyverse-owned persistence require migrations/rollback, transaction/concurrency tests, indexes/constraints, tenant isolation, secret/logging tests, backup/restore impact, and ERD/operability/ADR synchronization. Keycloak upgrades require supported schema migration through Keycloak, not custom manipulation of its private database tables.
