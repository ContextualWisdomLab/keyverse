# Keyverse UML and Runtime Views

**Status:** Accepted protected-main diagrams with integrated changes labelled.
**Last reviewed:** 2026-08-18

## Component and authority view

```mermaid
flowchart LR
    USER[User / workforce identity]
    EXT[External IdPs / LDAP / HR-IGA]
    EDGE[WAF / public edge]
    KC[Keycloak engine]
    KCAPI[Keycloak Admin REST API]
    ADMIN[Account-unification + SCIM API]
    DEPLOY[Private deployment controller]
    KV[(KV / secret manager)]
    KCDB[(Keycloak-owned PostgreSQL)]
    KVS[(Keyverse-owned config / intent / receipt / audit store)]
    RP[CWL relying parties]

    USER --> EDGE
    EXT --> EDGE
    EDGE --> KC
    EDGE --> ADMIN
    KC --> KCDB
    KCAPI --> KC
    ADMIN --> KCAPI
    ADMIN --> KVS
    DEPLOY --> KV
    DEPLOY --> ADMIN
    DEPLOY --> KCAPI
    KC --> RP
```

The two storage nodes are authority boundaries, even when a deployment places them on the same physical database service. Keycloak owns and migrates its internal schema. Keyverse reads/writes only its own supported store and reaches Keycloak user/client/federation state through the supported Admin API rather than direct private-table access.

## Federation desired-state sequence

```mermaid
sequenceDiagram
    actor Operator
    participant Deploy as Deployment controller
    participant Keyverse
    participant Store as Keyverse state store
    participant Keycloak as Keycloak Admin API/engine

    Operator->>Deploy: private rendered federation payload
    Deploy->>Keyverse: authenticated preflight
    Keyverse->>Keyverse: local closed-schema validation
    Keyverse-->>Deploy: redacted readiness result
    Deploy->>Keyverse: desired-state apply/reconcile
    Keyverse->>Store: persist versioned intent
    Keyverse->>Keycloak: exact lookup / create or update
    Keycloak-->>Keyverse: live remote state
    Keyverse->>Keyverse: canonical re-observation
    Keyverse->>Store: write desired-version-bound receipt
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
    participant Keycloak as Keycloak Admin API/engine
    participant Secret as Secret-management port
    participant App as Relying party

    AppOwner->>Deploy: secret-free client representation
    Deploy->>Keyverse: preflight
    Keyverse-->>Deploy: policy result
    Deploy->>Keyverse: reconcile desired state
    Keyverse->>Store: versioned intent
    Keyverse->>Keycloak: exact client search/create/update
    Keycloak-->>Keyverse: exact live representation
    Keyverse->>Store: version-bound apply receipt
    opt confidential client
        Deploy->>Secret: provision secret separately
        Secret-->>App: controlled credential placement
    end
    Deploy->>App: run login/logout/token acceptance
```

PR #72 extends this sequence with a closed mapper profile and is integrated
in protected main; downstream authorization acceptance remains deployment
specific.

Downstream authorization is a separate sequence after token issuance:

```mermaid
sequenceDiagram
    participant Keycloak
    participant RP as Non-fork RP
    participant Policy as RP ABAC/RBAC policy
    participant Resource as Tenant/resource store
    Keycloak-->>RP: signed OIDC token
    RP->>RP: validate issuer/signature/algorithm/exp/sub/aud
    RP->>Policy: verified tenant, resource, purpose, role/scope
    Policy->>Resource: same-tenant ownership and policy check
    Resource-->>Policy: allow or deny
    Policy-->>RP: authorization decision
```

Authentication, client reconciliation, mapper presence, and Keyverse PDP
receipts do not bypass the RP policy sequence. ADR-0008 records the audited
status of each non-fork RP. ADR-0010 adds an issuer-side decision that the RP
may consult after token validation.

## Hierarchical authorization decision

```mermaid
sequenceDiagram
    participant Orgmetra
    participant Operator
    participant Keyverse as Keyverse PDP
    participant Store as Grant store
    participant RP as Relying-party PEP

    Orgmetra-->>Operator: assignment_record snapshot
    Operator->>Keyverse: persist software-unit or menu grant
    Keyverse->>Store: authorization grant
    RP->>RP: validate iss/aud/sig/exp/sub
    RP->>Keyverse: decide with org_path snapshot
    Keyverse->>Store: load grants
    Keyverse->>Keyverse: most-specific inherited grant
    Keyverse-->>RP: attributes and effect
    RP->>RP: enforce locally
```

Orgmetra remains employment SoR. Keyverse never copies the org tree.

## App start-login helper

```mermaid
sequenceDiagram
    participant App as Relying application
    participant Keyverse
    participant Registry as Local IdP registry
    participant Browser
    participant Keycloak

    App->>Keyverse: POST start-login
    Keyverse->>Registry: read enabled providers
    Keyverse-->>App: kc_idp_hint URL, no metadata fetch
    App->>Browser: redirect with PKCE
    Browser->>Keycloak: authorization + kc_idp_hint
```

## Programmable application token

```mermaid
sequenceDiagram
    participant Operator
    participant Keyverse
    participant Store as Hashed token store
    participant App as Software unit

    Operator->>Keyverse: issue PAT
    Keyverse->>Store: token_hash only
    Keyverse-->>Operator: plaintext once
    Operator->>App: secret-manager placement
    App->>Keyverse: verify token + software unit + APIs
    Keyverse-->>App: allow or deny, no secret echo
```

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
    PUT[SCIM full replacement PUT]
    PATCH[SCIM PATCH active=false — current narrower path]
    MERGE[Merge/link mutation]
    LOCK[user_operation_lock_state]
    USER[Keycloak user state]
    AUDIT[account_merge_audit / operation evidence]

    PUT --> LOCK
    MERGE --> LOCK
    LOCK --> USER
    PATCH -. not currently in shared-lock guarantee .-> USER
    USER --> AUDIT
```

Protected `main` guarantees the shared cross-process lock for merge/link and full SCIM replacement. The current `PATCH active=false` path is explicitly not represented as serialized with merge. Extending that guarantee is a source-and-concurrency-test change, not a documentation relabel.

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

PR #74 is integrated in protected main and changes the exact hourly gate
implementation without changing this authority separation; a protected-main
scheduled or manual run remains operational evidence.

## Maintenance rule

Update these views whenever Keycloak/Keyverse/deployment-controller ownership, identity matching, desired-state lifecycle, secret boundary, persistence, or protected automation authority changes. Active-PR items must not be relabelled as protected-main until integrated.
