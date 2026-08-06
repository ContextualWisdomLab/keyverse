# OIDC Relying-Party Desired-State Reconciliation Design

**Status:** Approved for autonomous implementation under issue #67.

## Problem

The side-effect-free relying-party preflight proves that one rendered Keycloak
`ClientRepresentation` satisfies Keyverse policy. It does not persist operator
intent, create or repair a Keycloak client, survive realm rebuilds, detect
duplicates, or preserve recovery data when deletion fails. Deployment
controllers therefore still need a durable apply boundary.

## Decision

Keyverse will own one secret-free desired-state lifecycle for the exact closed
OIDC client profile accepted by `POST /clients/relying-parties:validate`.
Validation remains pure. Stateful reconciliation is a separate module behind the
existing `KvStore` and Keycloak Admin API ports.

## HTTP contract

```text
GET    /clients/relying-parties
POST   /clients/relying-parties:reconcile
GET    /clients/relying-parties/{client_id}
PUT    /clients/relying-parties/{client_id}
DELETE /clients/relying-parties/{client_id}
```

The existing validation endpoint remains unchanged.

## Storage contract

```text
relying_party_sources
relying_party_apply_receipts
```

Both namespaces are multi-word `snake_case`. The existing standalone SQLite
object `idp_config_entries` remains unchanged; no migration is introduced.

The desired-state record contains the complete validated, secret-free client
representation. The receipt is SHA-256 over alias-preserving canonical JSON
(`sort_keys=True`, compact separators, UTF-8).

## Convergence states

- `in_sync`: exactly one live client, all observable desired fields match, and
  the canonical receipt matches the most recent successful verified apply.
- `drifted`: one live client exists but observable fields or the receipt differ.
- `absent`: no exact live client exists.
- `ambiguous`: multiple exact `clientId` matches exist; no mutation occurs.
- `unavailable`: live observation could not complete.
- `apply_failed`: create or update did not produce one verified matching client.

A receipt proves only which secret-free private revision Keyverse last verified.
It does not prove a successful authorization-code login or the absence of
out-of-band changes after observation.

## Reconciliation algorithm

1. Validate path `client_id` and require it to match the body `clientId`.
2. Run the existing relying-party policy validator.
3. Persist desired state before remote convergence.
4. Under a process-local lock keyed by `client_id`, list Keycloak clients by
   `clientId` and filter exact matches.
5. Zero matches: create, re-read, and accept only one exact observable match.
6. One match: no-op when observable state and receipt match; otherwise update,
   re-read, and accept only the same exact observable client.
7. Multiple matches: return `ambiguous` and perform no mutation.
8. Record the receipt only after successful re-observation.
9. Delete remotely first; remove desired state and receipt only after the exact
   live client is absent or successfully deleted.
10. Bulk reconciliation snapshots only desired keys, then re-reads each current
    record under its keyed lock so concurrent updates or deletions are not
    overwritten by stale values.

State locks protect KV access only. No Keycloak network request occurs while the
state lock is held. Different client IDs may reconcile concurrently; mutations
for the same client ID are serialized.

## Keycloak transport

`ProductAdminApi` gains explicit methods for list/create/update/delete client
representations. `ProductHttpAdminApi` reuses its current bearer-token cache,
allowed-route guard, and exactly-once HTTP 401 reauthentication boundary.
Dynamic Keycloak UUIDs are validated as opaque path segments before PUT or
DELETE. Create and update payloads are copied; update pins the body `id` to the
validated path UUID.

## Secret boundary

The accepted preflight representation has no client secret or registration
access token field. Reconciliation neither accepts, generates, stores, logs, nor
returns client secrets. Secret provisioning and rotation remain a separate
port. Any later secret feature requires an independent ADR, storage contract,
audit model, and recovery tests.

## Modularity

Standalone Keyverse uses the existing SQLite-backed `KvStore`. CWL and Naruon
controllers may provide another implementation of the same `KvStore` and
`ProductAdminApi` boundaries. The pure validator remains independently reusable.
No LLM or contextual orchestrator is used for deterministic OAuth metadata and
state reconciliation.

## Verification

Tests must cover empty-realm create, repeat no-op, drift repair, realm rebuild,
outage with retained intent, create/update failure, post-mutation verification,
duplicate fail-closed behavior, malformed stored state, canonical receipts,
remote-first delete, stale-snapshot avoidance, lock-free stored-state reads,
unsafe generated IDs, one-shot 401 refresh, and authenticated HTTP lifecycle.

Protected completion requires Ruff, Python compilation, package build, complete
pytest, production docstrings 100%, production statement coverage 100%,
production branch coverage 100%, realm/Compose/template validation, CodeQL,
Semgrep, Security Scan, independent current-head review, and zero unresolved
threads.

## Standards and vendor basis

The closed metadata policy remains based on OAuth 2.0 Security Best Current
Practice (RFC 9700), PKCE (RFC 7636), and OpenID Connect Dynamic Client
Registration 1.0 incorporating errata set 2. Client CRUD and observable fields
follow the current Keycloak Admin REST `ClientRepresentation` contract. These
sources guide product policy; Keyverse makes no formal conformance claim.
