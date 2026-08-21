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

When the same combination name exists in more than one tenant, include
`tenant_deployment_id` as the GET/DELETE query parameter; an ambiguous
administration operation fails closed.

## Start-login failures

- Empty `identity_providers`: the local federation registry has no enabled
  IdP. Register one through desired state; do not point the helper at a
  discovery URL.
- HTTP 404 on `provider_alias_hint`: the alias is missing or disabled.
- Multiple providers and a null `start_login_url`: supply an explicit hint.
- Never treat a green start-login response as production login acceptance.

## PAT rotation

1. POST `/application-tokens/{id}:rotate` with the same software unit.
2. If validation returns HTTP 400, correct the replacement settings; the old
   token remains active and must not be discarded.
3. Place a successful response's new plaintext in the application secret
   manager before retiring the old credential.
4. Confirm the old token verifies as `revoked_token` and the new token verifies
   as active.
5. Revoke unused tokens instead of extending them as login credentials.
   Include the same explicit tenant in rotate and verify requests; an expired
   predecessor is not rotatable.

## Recovery

Corrupt grant or token rows fail closed with HTTP 500. Restore the KV/DB
namespace from backup and re-apply reviewed grants. Do not reconstruct
plaintext PATs from hashes.
