# Authorization-plane operations

## When to use this runbook

Use this procedure after Orgmetra assignment data is available and the
Keyverse operator token is in the deployment secret store. It covers grant
changes, start-login troubleshooting, and PAT rotation. It does not replace
federation or RP desired-state apply.

## Persist grants

1. Confirm the org path is contiguous from `group_company`.
2. PUT the software-unit grant, then any menu grants.
3. Decide with a current Orgmetra snapshot. If the effect is unexpected,
   inspect winning_org_path and whether a more-specific deny exists.
4. Do not persist Orgmetra organization units into Keyverse.

## Start-login failures

- Empty `identity_providers`: the local federation registry has no enabled
  IdP. Register one through desired state; do not point the helper at a
  discovery URL.
- HTTP 404 on `provider_alias_hint`: the alias is missing or disabled.
- Multiple providers and a null `start_login_url`: supply an explicit hint.
- Never treat a green start-login response as production login acceptance.

## PAT rotation

1. POST `/application-tokens/{id}:rotate` with the same software unit.
2. Place the new plaintext in the application secret manager.
3. Confirm the old token verifies as `revoked_token`.
4. Revoke unused tokens instead of extending them as login credentials.

## Recovery

Corrupt grant or token rows fail closed with HTTP 500. Restore the KV/DB
namespace from backup and re-apply reviewed grants. Do not reconstruct
plaintext PATs from hashes.
