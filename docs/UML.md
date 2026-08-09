# Keyverse UML and Runtime Views

**Status:** Accepted protected-main diagrams with active-PR items labelled.  
**Last reviewed:** 2026-08-09

## Component and authority view

```mermaid
flowchart LR
    USER[User / workforce identity]
    EXT[External IdPs / LDAP / HR-IGA]
    EDGE[WAF / public edge]
    KC[Keycloak engine]
    ADMIN[Account-unification + SCIM API]
    DEPLOY[Private deployment controller]
    KV[(KV / secret manager)]
    PG[(PostgreSQL)]
    RP[CWL relying parties]

    USER --> EDGE
    EXT --> EDGE
    EDGE --> KC
    EDGE --> ADMIN
    KC --> PG
    ADMIN --> PG
    DEPLOY --> KV
    DEPLOY --> ADMIN
    DEPLOY --> KC
    KC --> RP
```

## Federation desired-state sequence

```mermaid
sequenceDiagram
    actor Operator
    participant Deploy as Deployment controller
    participant Keyverse
    participant Store as KV/PostgreSQL
    participant Keycloak

    Operator->>Deploy: private rendered federation payload
    Deploy->>Keyverse: authenticated preflight
    Keyverse->>Keyverse: local closed-schema validation
    Keyverse-->>Deploy: redacted readiness result
    Deploy->>Keyverse: desired-state apply/reconcile
    Keyverse->>Store: persist intent
    Keyverse->>Keycloak: exact lookup / create or update
    Keycloak-->>Keyverse: live remote state
    Keyverse->>Keyverse: canonical re-observation
    Keyverse->>Store: write canonical receipt
    Keyverse-->>Deploy: redacted outcome
    Deploy->>Operator: controlled acceptance evidence
```

## RP registration sequence

```mermaid
sequenceDiagram
    actor AppOwner
    participant Deploy as Deployment controller
    participant Keyverse
    participant Store as Desired-state store
    participant Keycloak
    participant Secret as Secret-management port
    participant App as Relying party

    AppOwner->>Deploy: secret-free client representation
    Deploy->>Keyverse: preflight
    Keyverse-->>Deploy: policy result
    Deploy->>Keyverse: reconcile desired state
    Keyverse->>Store: intent
    Keyverse->>Keycloak: exact client search/create/update
    Keycloak-->>Keyverse: exact live representation
    Keyverse->>Store: apply receipt
    opt confidential client
        Deploy->>Secret: provision secret separately
        Secret-->>App: controlled credential placement
    end
    Deploy->>App: run login/logout/token acceptance
```

PR #72 extends this sequence with a closed mapper profile; it remains active-PR.

## Account merge state view

```mermaid
stateDiagram-v2
    [*] --> distinct_accounts
    distinct_accounts --> candidate_link: exact subject / verified email / operator evidence
    candidate_link --> rejected: unsafe or ambiguous evidence
    candidate_link --> locked: acquire shared user-operation lock
    locked --> merging
    merging --> survivor_active
    merging --> rollback_required: downstream/transaction failure
    survivor_active --> duplicate_tombstoned
    duplicate_tombstoned --> [*]
    rollback_required --> distinct_accounts
    rejected --> [*]
```

Unverified email cannot enter `candidate_link` by itself.

## SCIM / merge concurrency authority

```mermaid
flowchart LR
    SCIM[SCIM mutation]
    MERGE[Merge/link mutation]
    LOCK[user_operation_lock_state]
    USER[Keycloak user state]
    AUDIT[account_merge_audit / operation evidence]

    SCIM --> LOCK
    MERGE --> LOCK
    LOCK --> USER
    USER --> AUDIT
```

## Automation authority

```mermaid
flowchart LR
    MODEL[OpenCode model process]
    VERIFY[credential-free verifier]
    PUB[bounded PR publisher]
    REVIEW[independent review/security]
    MAIN[protected main]

    MODEL --> VERIFY
    VERIFY --> PUB
    PUB --> REVIEW
    REVIEW --> MAIN
```

PR #74 changes exact hourly gate implementation but not this authority separation.

## Maintenance rule

Update these views whenever Keycloak/Keyverse/deployment-controller ownership, identity matching, desired-state lifecycle, secret boundary, persistence, or protected automation authority changes. Active-PR items must not be relabelled as protected-main until integrated.