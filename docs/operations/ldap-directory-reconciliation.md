# LDAP Directory Reconciliation Operations

## Purpose

Operate the Keyverse-owned LDAP/Active Directory desired-state lifecycle without
exposing private directory values or bypassing exact component safety.

## Routine workflow

1. Render `deploy/templates/ldap-source.json` into a private mode-0600 file.
2. Call `POST /federation/user-directories:validate` and require HTTP 200 plus
   `ready_to_apply=true`.
3. Call `PUT /federation/user-directories/{directory_name}` with the original
   private file.
4. Require `convergence_state=in_sync`,
   `last_apply_receipt_matches=true`, and
   `secret_observation=not_observable`.
5. Run controlled live directory connection, bind/search, and login tests.
6. Record only non-secret evidence: desired name, component ID, template digest,
   Keycloak version, endpoint identifiers, status, operator, and test results.

## Status triage

| Status | Meaning | Operator action |
| --- | --- | --- |
| `in_sync` | One exact component, observable fields match, and the exact private revision has a successful local apply receipt. | Run or retain live operational evidence. |
| `drifted` | One exact component exists but observable fields or the apply receipt differ. | Reconcile; investigate repeated drift. |
| `absent` | No exact component exists. | Reconcile after confirming the realm and desired-state source. |
| `ambiguous` | More than one exact component exists. No mutation occurred. | Freeze automation, inventory IDs, preserve evidence, remove duplicates manually, then reconcile. |
| `unavailable` | Keycloak observation failed. Desired state remains stored. | Restore Keycloak/network health and retry reconcile. |
| `apply_failed` | Create or update failed. Desired state remains stored. | Inspect bounded service and Keycloak logs, repair the cause, and retry. |

`secret_observation=not_observable` is not an error. Keycloak does not provide a
live bind-secret equality proof. Never infer live secret equality solely from
`in_sync`.

## Rebuild and restore

After a realm rebuild or restore:

```bash
curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request POST \
  "$KEYVERSE_ADMIN/federation/user-directories:reconcile"
```

Expected behavior:

- missing components are created;
- one drifted component is updated;
- duplicates remain untouched and return `ambiguous`;
- unavailable or failed components retain desired state for a later retry.

## Rotation

1. Create the new directory credential with an overlap window.
2. Render a new private payload.
3. Repeat validate and PUT.
4. Verify `last_apply_receipt_matches=true` and run a live bind/login test.
5. Retire the old credential only after successful evidence.

Canonical receipts are independent of JSON key order. A real private value
change produces a different receipt and forces an update even when non-secret
fields are unchanged.

## Delete

`DELETE /federation/user-directories/{directory_name}` is remote-first:

- zero live matches: remove desired state and receipt;
- one match: delete it, then remove desired state and receipt;
- duplicates: HTTP 409, no mutation;
- Keycloak failure: HTTP 502/503, desired state retained.

Do not manually remove the KV record before remote deletion; doing so destroys
recovery intent.

## Concurrency

Storage and convergence locks are process-local. Run one active reconciler per
deployment. Do not schedule concurrent reconciliation from multiple replicas
until a shared advisory-lock backend is implemented.

Network calls never run while the desired-state storage lock is held, so a slow
Keycloak observation does not freeze independent local snapshots. Same-process
mutations remain serialized by the convergence lock.

## Security boundaries

- Operator bearer credentials belong in mode-0600 curl configuration files.
- Bind DN and credential remain in the private request file only.
- Responses, issues, PRs, screenshots, artifacts, and logs must contain only
  redacted values.
- Never enable cleartext LDAP, writable/unsynced mode, Kerberos, or trusted email
  as an incident workaround.
- Existing review-agent tokens and the hourly NVIDIA NIM OpenCode development
  credential are unrelated to runtime directory operations.

## Escalation evidence

For an incident, preserve:

- exact Keyverse and Keycloak versions;
- desired-state name and component ID(s);
- status and bounded error code;
- workflow or request timestamp;
- template digest, not template contents;
- approved endpoint identifiers, not credentials or full DNs;
- live test result and rollback result;
- relevant non-secret Keycloak audit events.

## Release boundary

This lifecycle is recorded under `CHANGELOG.md` `[Unreleased]`. Do not tag or
publish solely because reconciliation is available. Release additionally
requires exact-main regression, live directory E2E, immutable image digest,
SBOM/provenance, backup/restore, rollback rehearsal, and SLO evidence.

Standards interpretation is in
`docs/doctoring/ldap-directory-desired-state.md`.
