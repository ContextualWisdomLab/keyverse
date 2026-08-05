# LDAP and Active Directory Desired-State Reconciliation Design

**Date:** 2026-08-05  
**Status:** Approved for the autonomous bounded-development loop  
**Tracking:** #51, next bounded delivery of #2

## 1. Problem

Keyverse validates a rendered LDAP/Active Directory component before apply, but
an operator still applies the private payload directly to Keycloak Admin REST.
That leaves enterprise buyers without a Keyverse-owned lifecycle for directory
federation:

- no durable source of truth after a realm rebuild;
- no idempotent create/update decision;
- no duplicate-component protection;
- no safe delete ordering;
- no bounded retry after Keycloak outages;
- no operator-safe convergence status; and
- no one API contract shared by standalone, CWL, and Naruon deployments.

## 2. Goals

This increment adds authenticated KV/DB-backed desired-state CRUD and Keycloak
component reconciliation while reusing the already-protected LDAP preflight
validator.

The service must:

- store the original private component representation only inside the configured
  KV/DB trust boundary;
- expose only a redacted operator view;
- create exactly one Keycloak LDAP component when absent;
- update exactly one matching component when present;
- fail closed when multiple exact matches exist;
- preserve desired state when Keycloak is unavailable;
- delete Keycloak before removing desired state;
- snapshot storage before network calls;
- serialize convergence without holding the storage lock during network I/O;
- distinguish stored intent, live non-secret state, and secret observability
  honestly; and
- preserve the existing passwordless, verified-email, audit, scheduler, review,
  and modularity boundaries.

## 3. Non-goals

This increment does not:

- test a live LDAP bind or search;
- verify TLS chains, DNS ownership, or directory replication;
- persist Keycloak-generated component IDs as the source of truth;
- enable writable, unsynced, Kerberos, trusted-email, StartTLS, or custom-filter
  profiles;
- claim full secret equality with Keycloak;
- add LLM logic;
- alter review-agent credentials;
- publish a release.

## 4. Approaches considered

### 4.1 Persist only and leave apply to deployment tooling

This adds recovery data but does not close idempotency, duplicate, drift, or
outage-status gaps. It is rejected.

### 4.2 Persist Keycloak component IDs

This makes updates cheap but binds desired state to one realm instance. IDs can
change after rebuild, restore, migration, or manual deletion. The ID is therefore
operational output, not stable identity. Rejected as the source of truth.

### 4.3 Reconcile by exact component identity — selected

Use `name` plus exact
`providerType=org.keycloak.storage.UserStorageProvider` and
`providerId=ldap` as the stable desired identity. Each reconciliation lists
matching components:

- zero matches: create;
- one match: compare observable non-secret fields and update when needed;
- more than one match: fail closed without mutation.

The service returns the observed component ID only as diagnostic status.

## 5. API contract

### 5.1 Side-effect-free validation

Existing endpoint remains unchanged:

```http
POST /federation/user-directories:validate
```

It performs no storage or Keycloak I/O.

### 5.2 List

```http
GET /federation/user-directories
```

Returns a sorted list of redacted status objects.

### 5.3 Get

```http
GET /federation/user-directories/{directory_name}
```

Returns one redacted status or bounded HTTP 404.

### 5.4 Put and converge

```http
PUT /federation/user-directories/{directory_name}
```

- path and body name must match;
- the existing preflight validator runs before storage;
- private desired state is stored first;
- one convergence attempt follows;
- temporary failure does not roll back desired intent;
- response remains redacted.

### 5.5 Delete

```http
DELETE /federation/user-directories/{directory_name}
```

The service finds exact live matches. Duplicates fail closed. For one match it
deletes Keycloak first and removes desired state only after remote success. If
none exists, it removes desired state idempotently.

### 5.6 Reconcile all

```http
POST /federation/user-directories:reconcile
```

Takes one snapshot under the storage lock, releases it, and serially converges
each registration under the convergence lock.

## 6. Response model and honest status

```json
{
  "registration": {
    "name": "corp-ldap",
    "providerId": "ldap",
    "providerType": "org.keycloak.storage.UserStorageProvider",
    "config": {
      "bindDn": ["<redacted>"],
      "bindCredential": ["<redacted>"]
    }
  },
  "desired_state_stored": true,
  "convergence_state": "in_sync",
  "component_id": "keycloak-generated-id",
  "secret_observation": "not_observable",
  "last_convergence_error_code": null
}
```

`convergence_state` values:

- `in_sync` — exactly one live component and every observable non-secret field
  matches desired state;
- `drifted` — exactly one live component but observable non-secret fields differ;
- `absent` — no matching live component;
- `ambiguous` — multiple exact live matches;
- `unavailable` — Keycloak could not be queried;
- `apply_failed` — create/update/delete failed during a mutation attempt.

`secret_observation` is always `not_observable` because Keycloak does not expose
the stored bind credential in a form suitable for equality proof. `in_sync`
therefore means observable non-secret convergence plus a successful private
apply history, not proof of current secret bytes. This limitation is explicit in
operator documentation.

`last_convergence_error_code` uses bounded product codes only:

- `keycloak_unavailable`;
- `duplicate_components`;
- `component_create_failed`;
- `component_update_failed`;
- `component_delete_failed`;
- `stored_state_invalid`.

No URL, host, DN, credential, token, response body, exception text, or stack
trace enters the HTTP model.

## 7. Storage model

Namespace:

```text
directory_federation_sources
```

Key: validated component `name`.  
Value: the complete private
`DirectoryFederationRegistration.model_dump_json(by_alias=true)`.

The namespace is descriptive multi-word snake_case. No database schema change is
required because `KvStore` already stores namespace/key/value records in
`idp_config_entries`.

Malformed stored JSON, alias mismatch, or invalid legacy values fail closed with
`stored_state_invalid`. The service never returns raw stored text.

## 8. Keycloak component adapter

`ProductAdminApi` gains a narrow component surface:

```python
list_user_storage_components(name: str) -> list[dict]
create_user_storage_component(payload: dict) -> str | None
update_user_storage_component(component_id: str, payload: dict) -> None
delete_user_storage_component(component_id: str) -> None
```

`ProductHttpAdminApi` uses the official component endpoints:

- `GET /admin/realms/{realm}/components` with `name` and `type` query parameters;
- `POST /admin/realms/{realm}/components`;
- `PUT /admin/realms/{realm}/components/{id}`;
- `DELETE /admin/realms/{realm}/components/{id}`.

Every dynamic component ID passes the existing opaque path-segment validator.
The guarded Admin REST route allowlist expands only for these component routes.
Existing one-shot 401 reauthentication remains centralized.

## 9. Normalization and comparison

Keycloak component representations may contain generated fields and unordered
maps. The service compares only observable desired fields:

- `name`;
- `providerId`;
- `providerType`;
- each non-secret config entry in the closed preflight profile.

It ignores:

- `id`;
- `parentId`;
- `subType`;
- Keycloak-generated metadata;
- absent or masked `bindCredential`;
- absent or masked `bindDn`.

Config values are compared as exact one-element string lists because preflight
already rejects ambiguous multivalued entries.

## 10. Locking and concurrency

`DirectoryFederationService` owns:

- `_state_lock`: protects only KV read/write/snapshot operations;
- `_convergence_lock`: serializes remote create/update/delete/reconcile
  decisions in this process.

Network calls never run while `_state_lock` is held. This prevents a slow
Keycloak request from blocking local desired-state reads.

The first implementation uses process-local locks, matching the existing SAML
and OIDC federation registry. Multi-replica deployment must run one active
reconciler until a shared advisory-lock backend is introduced. This limitation
is documented rather than hidden.

## 11. Mutation flows

### Put

```text
validate path/body and preflight
  -> convergence lock
  -> state lock: persist private desired state
  -> release state lock
  -> list exact components
  -> 0 create / 1 compare+update / >1 fail closed
  -> return redacted status
```

### Delete

```text
validate name
  -> convergence lock
  -> state lock: prove desired state exists
  -> release state lock
  -> list exact components
  -> >1 fail closed
  -> 1 delete remote
  -> state lock: delete desired state
  -> 204
```

### Reconcile all

```text
state lock: snapshot values
  -> release state lock
  -> parse and validate snapshot
  -> convergence lock
  -> converge sequentially
  -> sorted redacted statuses
```

## 12. Error handling

- HTTP 400: path/body mismatch or policy violation;
- HTTP 404: desired state absent;
- HTTP 409: duplicate exact Keycloak components;
- HTTP 502: create/update/delete failed after a mutation request;
- HTTP 503: Keycloak observation unavailable;
- malformed stored data becomes an explicit redacted status for list/reconcile,
  or bounded HTTP 500 for direct get when the requested record is corrupt.

Temporary observation failure during list/get must not destroy desired state.
PUT returns stored intent with `unavailable` or `apply_failed` status instead of
pretending convergence succeeded.

## 13. Testing

TDD begins with failing service and API tests before production code.

Realistic scenarios:

- create a rendered AD source into empty Keycloak;
- repeat PUT as no-op when observable state matches;
- update timeout, endpoint, or base DN drift;
- preserve private desired state during Keycloak outage;
- recover and reconcile after outage or realm rebuild;
- duplicate live components fail without mutation;
- delete ordering preserves desired state when remote delete fails;
- malformed stored JSON does not disclose secrets;
- list/get/put/status responses redact bind identity and credential;
- storage locks are not held across network calls;
- exact dynamic component path validation;
- 401 token refresh on component methods;
- concurrent same-name mutations are serialized;
- different desired-state reads remain available during a blocked remote call.

Repository-wide gates remain Ruff, compileall, production docstrings 100%,
production statement and branch coverage 100%, complete pytest, package build,
realm, Compose, template JSON, CodeQL, Semgrep, Security Scan, current-head
review, unresolved-thread policy, and protected merge.

## 14. Documentation and release

Update:

- `CHANGELOG.md`;
- `ARCHITECTURE.md`;
- `README.md`;
- `CLAUDE.md` and `AGENTS.md` where contracts change;
- LDAP onboarding, rollback, and secret-rotation guidance;
- `docs/doctoring/ldap-directory-desired-state.md` with APA 7th references.

No version bump or release is justified by this increment alone. Release remains
gated by exact-main regression, live directory E2E, immutable image digest,
SBOM/provenance, backup/restore, and rollback evidence.

## 15. References — APA 7th

Harrison, R. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Authentication methods and security mechanisms* (RFC 4513). Internet
Engineering Task Force. https://doi.org/10.17487/RFC4513

Keycloak. (n.d.-a). *Keycloak Admin REST API*. Retrieved August 5, 2026, from
https://www.keycloak.org/docs-api/latest/rest-api/index.html

Keycloak. (n.d.-b). *Server Administration Guide: LDAP and Active Directory*.
Retrieved August 5, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
The protocol* (RFC 4511). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4511

Zeilenga, K. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Directory information models* (RFC 4512). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4512
