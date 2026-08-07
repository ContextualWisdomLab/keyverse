# OIDC Relying-Party Reconciliation Operations

## Purpose

Operate the Keyverse-owned, secret-free OIDC relying-party desired-state
lifecycle. This runbook deliberately separates metadata reconciliation from
confidential-client secret placement and from live authorization-code acceptance.

## Routine workflow

1. Render `deploy/templates/oidc-rp-client.json` into a private mode-0600 file.
2. Call `POST /clients/relying-parties:validate` and require HTTP 200 plus
   `ready_to_apply=true`.
3. Call `PUT /clients/relying-parties/{client_id}` with the same original file.
4. Require `convergence_state=in_sync` and
   `last_apply_receipt_matches=true`.
5. For a confidential client, provision or rotate its credential through the
   separately approved secret-management channel; never add it to this payload.
6. Run controlled authorization-code plus PKCE login, refresh, logout, and
   rollback tests.
7. Record only non-secret evidence: desired client ID, Keycloak UUID, desired
   payload digest, apply receipt, versions, operator, test result, and rollback
   reference.

## Example

```bash
set -euo pipefail
KEYVERSE_ADMIN="https://keyverse-admin.example"
CLIENT_ID="naruon-web"
PAYLOAD="$(mktemp)"
RESPONSE="$(mktemp)"
AUTH_CONFIG="$(mktemp)"
cleanup() {
  rm -f "$PAYLOAD" "$RESPONSE" "$AUTH_CONFIG"
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$RESPONSE" "$AUTH_CONFIG"

XTRACE_WAS_ON=0
case $- in
  *x*) XTRACE_WAS_ON=1; set +x ;;
esac
KEYVERSE_TOKEN="$(kv get secret/keyverse/operator-api-token)"
printf 'header = "Authorization: Bearer %s"\n' "$KEYVERSE_TOKEN" \
  >"$AUTH_CONFIG"
unset KEYVERSE_TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

render deploy/templates/oidc-rp-client.json >"$PAYLOAD"

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$KEYVERSE_ADMIN/clients/relying-parties:validate" \
  >"$RESPONSE"

python3 - "$RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
raise SystemExit(0 if response.get("ready_to_apply") is True else 1)
PY

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request PUT \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$KEYVERSE_ADMIN/clients/relying-parties/$CLIENT_ID" \
  >"$RESPONSE"

python3 - "$RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
valid = (
    response.get("convergence_state") == "in_sync"
    and response.get("last_apply_receipt_matches") is True
    and isinstance(response.get("client_uuid"), str)
)
raise SystemExit(0 if valid else 1)
PY
```

## Status triage

| State | Meaning | Safe action |
|---|---|---|
| `in_sync` | One exact observable client matches the last verified desired revision | Run or retain live acceptance evidence |
| `drifted` | One client exists but observable metadata or receipt differs | Review drift, then PUT or reconcile |
| `absent` | Desired state exists but no exact client exists | Reconcile; investigate prior deletion |
| `ambiguous` | More than one exact `clientId` exists | Stop mutation; remove duplicate manually with evidence |
| `unavailable` | Keycloak observation failed | Restore connectivity; desired state remains durable |
| `apply_failed` | Mutation or post-apply verification failed | Inspect bounded error code; repair and reconcile |

## Realm rebuild

After Keycloak realm restoration or replacement:

```bash
curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request POST \
  "$KEYVERSE_ADMIN/clients/relying-parties:reconcile"
```

Every stored key is re-read immediately before its own convergence decision.
The operation cannot use a stale value snapshot to recreate a desired record
that was deleted while reconciliation was running.

## Duplicate recovery

`ambiguous` is fail-closed. Keyverse does not choose a winner, update all
matches, or delete any client automatically.

1. Export non-secret representations from private Keycloak administration.
2. Identify which UUID is referenced by current sessions, credentials, audit,
   and deployment evidence.
3. Stop new login traffic for the RP.
4. Delete or rename the unintended duplicate through an approved change.
5. Re-run GET and require `drifted` or `in_sync`, then reconcile as needed.
6. Run controlled login and rollback tests.

## Drift and out-of-band changes

A canonical receipt proves that Keyverse once re-observed the exact desired
revision. It is not a lease or continuous integrity monitor. If another operator
changes Keycloak later, GET reports observable drift when the changed field is
within the closed profile. Reconcile restores the reviewed desired values.

## Deletion and rollback

`DELETE /clients/relying-parties/{client_id}` is remote-first. On observation,
duplicate, or remote deletion failure, Keyverse retains desired state and the
last receipt. After successful remote deletion or confirmed absence, it removes
both records.

Before deletion:

- stop user routing;
- capture non-secret client and session evidence;
- preserve the desired payload digest and rollback artifact;
- revoke or escrow confidential credentials through the secret-management port;
- confirm an owner and rollback window.

Rollback uses the same validate and PUT sequence, followed by fresh credential
placement and live authorization-code acceptance.

## What the API never proves

The API does not prove:

- DNS or TLS reachability;
- successful authorization-code or PKCE exchange;
- client-secret existence or equality;
- token audience or mapper correctness outside the closed profile;
- user/session migration;
- absence of out-of-band changes after the observation;
- production SLO compliance.

These require separate controlled evidence.
