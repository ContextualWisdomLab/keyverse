# Authorization-plane operations

## When to use this runbook

Use this procedure after Orgmetra assignment data is available and the
Keyverse operator token is in the deployment secret store. It covers grant
changes, start-login troubleshooting, and PAT rotation. It does not replace
federation or RP desired-state apply.

The authorization router enforces the operator bearer and privileged path
checks at its own module boundary. A parent application may embed the router,
but must still provide the configured operator token; `actor_identity_id` in a
grant is administrative policy metadata, not a caller identity derived from a
shared operator bearer.

## Persist grants

1. Confirm the org path is contiguous from `group_company`.
2. Put the explicit `tenant_deployment_id` on the snapshot and every grant.
3. PUT the software-unit grant, then any menu grants.
4. Decide with a current Orgmetra snapshot. If the effect is unexpected,
   inspect winning_org_path, winning_menu_path, `inherited`, and whether a
   more-specific deny exists. `inherited=true` means the winning org path or
   menu path is a strict ancestor of the requested path. For menu decisions,
   menu-path specificity is evaluated before org-path specificity.
5. Do not persist Orgmetra organization units into Keyverse.

When the same grant key or combination name exists in more than one tenant,
include `tenant_deployment_id` as the GET/DELETE query parameter; an ambiguous
administration operation fails closed. The query value is validated before the
tenant-qualified KV record is selected.

## Start-login failures

- Empty `identity_providers`: the local federation registry has no enabled
  IdP. Register one through desired state; do not point the helper at a
  discovery URL.
- HTTP 404 on `provider_alias_hint`: the alias is missing or disabled.
- Multiple providers and a null `start_login_url`: supply an explicit hint.
- Never treat a green start-login response as production login acceptance.

## PAT rotation

Rotation is a server-side credential cutover: after a successful rotate
response, the predecessor is already retired and the replacement plaintext is
the only usable new secret. The application secret manager therefore has to be
ready before the request is sent.

1. Preflight the target secret-manager entry and confirm the operator can write
   and immediately read back a non-sensitive probe or otherwise use the secret
   manager's supported readiness check. Do not rotate while the destination is
   unavailable or read-only.
2. POST `/application-tokens/{id}:rotate` with the same software unit and
   explicit tenant. If validation returns HTTP 400, correct the replacement
   settings; the old token remains active and must not be discarded.
3. On success, capture the returned replacement `application_token_id` and
   plaintext in a protected process-local response and write the plaintext to
   the application secret manager immediately. A successful server response
   means the predecessor has already transitioned to the rotated state; do not
   describe or operate this as a client-side "store then retire" sequence.
4. If the first secret-manager write fails but the protected response is still
   available, retry the write without logging or reprinting the plaintext. If
   the plaintext is lost or cannot be placed safely, issue a **new** token with
   the same reviewed tenant/software-unit/purpose/capabilities, store that new
   plaintext, verify it, and revoke the stranded replacement by its returned
   token ID. Do not attempt to rotate the already retired predecessor again.
5. Confirm the predecessor verifies as `revoked_token` and the credential now
   stored by the application verifies as active. Rotation persists predecessor
   and replacement through one KV-store transaction; if Keyverse audit
   persistence itself fails before the response, one atomic compensation
   operation restores the predecessor and removes the replacement.
6. Revoke unused tokens instead of extending them as login credentials. An
   expired or retired predecessor is not rotatable.

A future deployment integration may wrap Keyverse rotation and the application
secret manager in a stronger transactional handoff, but this runbook does not
claim cross-system atomicity that the current HTTP API does not provide.

## Recovery

Corrupt grant or token rows fail closed with HTTP 500. Restore the KV/DB
namespace from backup and re-apply reviewed grants. Do not reconstruct
plaintext PATs from hashes.
