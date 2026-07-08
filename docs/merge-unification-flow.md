# Account unification & merge flow

Neither ZITADEL nor an external ADFS *merges two pre-existing accounts into one*
natively. The `account-unification` service (this repo, `services/account_unification`)
fills that gap. It does two things:

1. **Inspect** — list the external identities (`idp_links`) tied to one user
   (one-user-to-many-external-identities).
2. **Merge** — fold a duplicate account into a survivor, moving everything the
   duplicate owns, tombstoning it, and auditing every step.

## Matching rules (precedence, highest first)

Implemented in `app/matching.py` / enforced in `app/service.py`:

1. **Exact `(idp_id, external subject/nameID)`** shared by both accounts.
2. **Verified email** equal on **both** accounts (`is_email_verified` true on
   each). Case-insensitive.
3. **Explicit operator link** (`explicit_link: true` on the merge request).

**Hard rule:** never auto-merge on an *unverified* email. If the accounts share
only an unverified email, the merge is refused with `422 Unverified email`.

## Merge algorithm (survivor-wins)

```
merge(survivor S, duplicate D, actor A):
  reject if S == D                         -> 400 SameUser
  load S, D (must exist)                   -> 404 UserNotFound
  reject if S or D not active              -> 409 InactiveAccount
  decision = decide_match(S, D, explicit)
  reject if only tie is unverified email   -> 422 UnverifiedEmailMerge
  reject if no rule satisfied              -> 409 NoMatch

  audit "merge_started" {match_reason, conflict_policy=survivor_wins}

  for each idp_link L in D:
     if S already has (L.idp, L.subject): CONFLICT -> keep S's, detach D's, audit
     else: add L to S, remove L from D, audit "idp_link_moved"

  for each role grant G in D:
     if S already granted on G.project: CONFLICT -> keep S's, drop D's, audit
     else: grant G.project/roles to S, remove from D, audit "grant_moved"

  for each membership M in D (org/project/instance ownership):
     if S already a member of M.aggregate: CONFLICT -> keep S's, drop D's, audit
     else: add M to S, remove M from D, audit "membership_moved"

  set D.metadata[merged_into_user_id] = S.id     # tombstone pointer
  deactivate D                                    # D can never authenticate again
  audit "duplicate_tombstoned"
  audit "merge_completed" {moved_*, conflicts}
  return MergeResult{..., audit_id}
```

**Survivor-wins** means: on any collision (same external identity, same project
grant, same ownership), the survivor's value is kept, the duplicate's is
dropped, and the collision is recorded as a `MergeConflict{resolution:
"survivor_wins"}` in both the result and the audit trail.

## Tombstoning

The duplicate is **not deleted**. It is stamped with metadata
`merged_into_user_id = <survivor>` and deactivated. This preserves forensic
history and lets any stale reference resolve to the survivor.

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
| `GET` | `/users/{id}` | Inspect a user + its idp_links |
| `GET` | `/users/{id}/identities` | List external identities |
| `POST` | `/merges` | Merge duplicate into survivor |
| `GET` | `/merges/{audit_id}/audit` | Full audit trail of a merge |
| `GET` | `/healthz` | Readiness |

## Configuration

All config/secrets (ZITADEL API base, management token, org id, conflict policy)
come from the KV/DB store via the bootstrap pointer — see
`services/account_unification/app/config.py`. No runtime `os.getenv`.
