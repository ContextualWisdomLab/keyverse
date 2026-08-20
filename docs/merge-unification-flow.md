# Account unification & merge flow

Neither Keycloak nor an external ADFS *merges two pre-existing accounts into one*
natively. The `account-unification` service (this repo, `services/account_unification`)
fills that gap. It does two things:

1. **Inspect** — list the external identities (Keycloak federated identities)
   tied to one user (one-user-to-many-external-identities).
2. **Merge** — fold a duplicate account into a survivor, moving everything the
   duplicate owns, tombstoning it, and auditing every step.

It talks to Keycloak through the **Admin REST API** (`app/keycloak_client.py`),
authenticating with a confidential service-account client (client credentials)
that holds `realm-management` `view-users` + `manage-users`.

## Matching rules (precedence, highest first)

Implemented in `app/matching.py` / enforced in `app/service.py`:

1. **Exact `(identity_provider, external subject/userId)`** shared by both
   accounts (a Keycloak federated-identity link).
2. **Verified email** equal on **both** accounts (`emailVerified` true on each).
   Case-insensitive.
3. **Explicit operator link** (`explicit_link: true` on the merge request).

**Hard rule:** never auto-merge on an *unverified* email. If the accounts share
only an unverified email, the merge is refused with `422 Unverified email`.

## Merge algorithm (survivor-wins)

```
merge(survivor S, duplicate D, actor A):
  reject if S == D                         -> 400 SameUser
  acquire shared user-operation locks for S and D
  load S, D (must exist)                   -> 404 UserNotFound
  reject if S or D disabled                -> 409 InactiveAccount
  decision = decide_match(S, D, explicit)
  reject if only tie is unverified email   -> 422 UnverifiedEmailMerge
  reject if no rule satisfied              -> 409 NoMatch

  audit "merge_started" {match_reason, conflict_policy=survivor_wins}

  for each federated identity L in D:
     if S already links L.provider (or L.subject): CONFLICT -> keep S's, detach D's, audit
     else: add L to S, remove L from D, audit "federated_identity_moved"

  for each role mapping R in D (realm + client roles):
     if S already has (R.client, R.name): CONFLICT -> keep S's, drop D's, audit
     else: add R to S, remove R from D, audit "role_mapping_moved"

  for each group membership G in D (ownership via group inheritance):
     if S already in G: CONFLICT -> keep S's, drop D's, audit
     else: add G to S, remove G from D, audit "group_membership_moved"

  set D.attributes[merged_into_user_id] = S.id   # tombstone pointer
  disable D                                       # D can never authenticate again
  audit "duplicate_tombstoned"
  audit "merge_completed" {moved_*, conflicts}
  release shared user-operation locks
  return MergeResult{..., audit_id}
```

**Survivor-wins** means: on any collision (same external identity / provider,
same realm-or-client role, same group), the survivor's value is kept, the
duplicate's is dropped, and the collision is recorded as a `MergeConflict{
resolution: "survivor_wins"}` in both the result and the audit trail. Because
Keycloak allows at most one federated-identity link per provider alias, a
duplicate link on an already-linked provider is always a survivor-wins conflict.

## Tombstoning

The duplicate is **not deleted**. Its Keycloak user attribute
`merged_into_user_id = <survivor>` is set and the user is disabled
(`enabled: false`). This preserves forensic history and lets any stale reference
resolve to the survivor.

### SCIM/merge serialization invariant

`PUT /scim/v2/Users/{id}` performs a full Keycloak user-representation write and
can set `active: true`. Its tombstone check and replacement PUT therefore execute
inside the **same user-operation lock** used by the complete merge transaction.
A merge cannot create `merged_into_user_id` between those two Admin API calls,
and SCIM PUT cannot wipe a newly-created tombstone or reactivate the duplicate.

The supported `PATCH /scim/v2/Users/{id}` `active=false` deprovisioning shape now
executes its read/deactivate/read path inside
`user_operation_locks.hold(user_id)`, so PATCH and merge are transactionally
serialized at the service boundary. Lock contention returns retryable HTTP
`503` before mutation. Future PATCH shapes still require a source change and a
merge/PATCH race regression before joining this guarantee.

Standalone deployments use a dedicated SQLite sidecar lock database and hold a
`BEGIN IMMEDIATE` transaction for the complete critical section. This provides a
crash-safe mutex shared by every worker/process using the same database path;
process death closes the connection and releases the lock. The current backend
serializes operations that participate in the shared lock conservatively rather
than risking a multi-user deadlock. Lock acquisition waits up to 10 seconds,
then returns retryable HTTP `503` without performing a partial mutation. A
clustered Postgres deployment must provide the same `UserOperationLocks`
contract and wire one shared instance into the merge service and every SCIM
operation that claims this serialization guarantee.

## Audit

Every step emits an immutable `account_merge_audit` event sharing one
correlation `audit_id`, with `actor`, `event_type`, both user ids, and a JSON
payload. Retrieve the full trail:

```
GET /merges/{audit_id}/audit
```

Standalone deployments persist audit to SQLite (`account_merge_audit` table);
production swaps in a Postgres-backed sink.

## HTTP surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/users/{id}` | Inspect a user + its federated identities |
| `GET` | `/users/{id}/identities` | List external identities |
| `POST` | `/merges` | Merge duplicate into survivor |
| `GET` | `/merges/{audit_id}/audit` | Full audit trail of a merge |
| `POST` | `/scim/v2/Users` | SCIM inbound provisioning (create) |
| `GET`/`PUT`/`PATCH`/`DELETE` | `/scim/v2/Users/{id}` | SCIM read / replace / deactivate |
| `GET` | `/healthz` | Readiness |

## Configuration

All config/secrets (Keycloak server URL, realm, service-account client id +
secret, conflict policy) come from the KV/DB store via the bootstrap pointer —
see `services/account_unification/app/config.py`. No runtime `os.getenv`.
