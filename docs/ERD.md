# Keyverse Logical and Persistence ERD

**Status:** Accepted cross-cutting data model. Exact Keycloak internal schema remains Keycloak-owned.  
**Last reviewed:** 2026-08-09

Keyverse persists its own configuration, desired-state, receipts, merge audit, and user-operation locks while Keycloak/PostgreSQL owns canonical IdP users/sessions/clients/federation runtime state. This ERD models Keyverse-owned durable records and their relation to external Keycloak identities without pretending to own Keycloak's internal tables.

```mermaid
erDiagram
    IDP_CONFIG_ENTRY }o--|| TENANT_DEPLOYMENT : scoped_to
    FEDERATION_SOURCE }o--|| TENANT_DEPLOYMENT : scoped_to
    DIRECTORY_FEDERATION_SOURCE }o--|| TENANT_DEPLOYMENT : scoped_to
    RELYING_PARTY_SOURCE }o--|| TENANT_DEPLOYMENT : scoped_to

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
      text config_key UK
      text protected_value_ref
      text config_version
      timestamptz updated_at
    }

    FEDERATION_SOURCE {
      uuid federation_source_id PK
      uuid tenant_deployment_id FK
      text federation_alias UK
      text protocol_code
      jsonb secret_free_desired_state
      text desired_state_hash
      text lifecycle_status_code
      timestamptz updated_at
    }

    FEDERATION_APPLY_RECEIPT {
      uuid federation_apply_receipt_id PK
      uuid federation_source_id FK
      text keycloak_resource_id
      text observed_state_hash
      text apply_outcome_code
      timestamptz observed_at
    }

    DIRECTORY_FEDERATION_SOURCE {
      uuid directory_federation_source_id PK
      uuid tenant_deployment_id FK
      text directory_alias UK
      jsonb private_desired_state
      text desired_state_hash
      text lifecycle_status_code
      timestamptz updated_at
    }

    DIRECTORY_FEDERATION_APPLY_RECEIPT {
      uuid directory_federation_apply_receipt_id PK
      uuid directory_federation_source_id FK
      text keycloak_component_id
      text observed_state_hash
      text apply_outcome_code
      timestamptz observed_at
    }

    RELYING_PARTY_SOURCE {
      uuid relying_party_source_id PK
      uuid tenant_deployment_id FK
      text client_id UK
      jsonb secret_free_desired_state
      text desired_state_hash
      text lifecycle_status_code
      timestamptz updated_at
    }

    RELYING_PARTY_APPLY_RECEIPT {
      uuid relying_party_apply_receipt_id PK
      uuid relying_party_source_id FK
      text keycloak_client_uuid
      text observed_state_hash
      text apply_outcome_code
      timestamptz observed_at
    }

    KEYCLOAK_USER_REFERENCE {
      uuid keycloak_user_reference_id PK
      uuid tenant_deployment_id FK
      text keycloak_user_uuid UK
      text lifecycle_status_code
    }

    EXTERNAL_IDENTITY_LINK {
      uuid external_identity_link_id PK
      uuid keycloak_user_reference_id FK
      uuid federation_source_id FK
      text external_subject_hash
      boolean email_verified
    }

    ACCOUNT_MERGE_AUDIT {
      uuid account_merge_audit_id PK
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
```

## Identity and authorization rules

- Keycloak UUIDs, federation aliases, RP client IDs, email values, and external subjects are data identifiers, not authorization by themselves.
- Exact external identity key is `(identity_provider, subject)`; verified email may support matching under policy but unverified email never authorizes linking.
- `tenant_deployment_id` is explicit in Keyverse-owned records; deployment/customer separation must not be inferred from realm/resource names.
- Secrets are referenced through protected values/handles where possible; secret-free desired-state tables must never gain client/bind credentials accidentally.

## Desired-state invariant

```mermaid
flowchart LR
    PRIVATE[Private rendered input]
    VALID[Preflight validation]
    INTENT[Desired-state source]
    REMOTE[Keycloak live state]
    RECEIPT[Apply receipt]

    PRIVATE --> VALID
    VALID --> INTENT
    INTENT --> REMOTE
    REMOTE --> RECEIPT
```

A receipt is valid only after exact post-mutation re-observation. Delete flows that require remote-first semantics cannot remove local desired state before remote deletion succeeds.

## Keycloak ownership

Users, sessions, roles, groups, credentials, WebAuthn material, IdP runtime representation, LDAP storage components, and RP clients ultimately live in Keycloak's schema/API. Keyverse stores controlled references/intent/receipts but does not duplicate or directly edit unsupported Keycloak internal tables.

## Migration acceptance

Changes to Keyverse-owned persistence require migrations/rollback, transaction/concurrency tests, indexes/constraints, tenant isolation, secret/logging tests, backup/restore impact, and ERD/operability/ADR synchronization. Keycloak upgrades require supported schema migration through Keycloak, not custom manipulation of its private database tables.