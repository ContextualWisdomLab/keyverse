# OIDC Relying-Party Reconciliation Operations

## Purpose

Operate the Keyverse-owned, secret-free OIDC relying-party desired-state
lifecycle. This runbook deliberately separates deterministic metadata and mapper
reconciliation from confidential-client secret placement and from live
authorization-code/JWT acceptance.

## Routine workflow

1. Render `deploy/templates/oidc-rp-client.json` for a generic RP or
   `deploy/templates/oidc-rp-naruon.json` for the reviewed Naruon public-client
   mapper profile into a private mode-0600 file.
2. Resolve all HTTPS and routing placeholders. Treat Naruon `role`, `org`, and
   `workspace` values as visible product data, never credentials or personal
   secrets.
3. Call `POST /clients/relying-parties:validate` and require HTTP 200 plus
   `ready_to_apply=true`.
4. Call `PUT /clients/relying-parties/{client_id}` with the same original file.
5. Require `convergence_state=in_sync` and
   `last_apply_receipt_matches=true` after exact live re-observation.
6. For a confidential client, provision or rotate its credential through the
   separately approved secret-management channel; never add it to this payload.
7. Run controlled authorization-code plus PKCE login, downstream JWT
   signature/issuer/expiry/audience acceptance and rejection, refresh, logout,
   and rollback tests.
8. Record only non-secret evidence: desired client ID, Keycloak UUID, desired
   payload digest, apply receipt, versions, operator, controlled acceptance
   result, and rollback reference.

## Naruon mapper contract

The Naruon runtime artifact is a public `naruon-web` client with exactly four
canonical mappers:

1. `keyverse-audience` — `oidc-audience-mapper`, access-token audience pinned to
   `naruon-web`;
2. `keyverse-claim-role` — hardcoded `role`;
3. `keyverse-claim-org` — hardcoded `org`;
4. `keyverse-claim-workspace` — hardcoded `workspace`.

The profile allows no script, user-attribute, group, regex, arbitrary claim,
unknown mapper class, extra nested field, or credential material. Token
configuration is issuer-side evidence only. The receiving Naruon boundary must
independently validate the token and must not infer authorization merely from the
presence of a hardcoded claim.

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

render deploy/templates/oidc-rp-naruon.json >"$PAYLOAD"

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
| `in_sync` | One exact observable client, including the closed mapper profile, matches the last verified desired revision | Run or retain live acceptance evidence |
| `drifted` | One client exists but observable metadata, closed mapper semantics, or receipt differs | Review drift, then PUT or reconcile |
| `absent` | Desired state exists but no exact client exists | Reconcile; investigate prior deletion |
| `ambiguous` | More than one exact `clientId` exists | Stop mutation; remove duplicate manually with evidence |
| `unavailable` | Keycloak observation failed | Restore connectivity; desired state remains durable |
| `apply_failed` | Mutation or post-apply verification failed | Inspect bounded error code; repair and reconcile |

## Mapper observation and drift

Keycloak may add generated mapper IDs or return known mappers in a different
order. Keyverse normalizes only those vendor representation details before
semantic comparison:

- a generated mapper `id` may be ignored only when it is a valid non-empty
  string;
- known mapper identities are sorted into the canonical audience, role, org,
  workspace order;
- the remaining mapper shape is revalidated against the same closed product
  policy used by preflight.

An unknown mapper, malformed field/config, duplicate mapper identity, changed
claim value, changed audience, changed token destination, or other semantic
difference is `drifted`. Do not delete unknown live state or broaden the
allowlist merely to make the status green. Establish ownership and intent first.

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
that was deleted while reconciliation was running. For Naruon, require the
closed mapper profile to be re-observed `in_sync` and then rerun controlled
login and downstream token acceptance before restoring user traffic.

## Duplicate recovery

`ambiguous` is fail-closed. Keyverse does not choose a winner, update all
matches, or delete any client automatically.

1. Export non-secret representations from private Keycloak administration.
2. Identify which UUID is referenced by current sessions, credentials, audit,
   and deployment evidence.
3. Stop new login traffic for the RP.
4. Delete or rename the unintended duplicate through an approved change.
5. Re-run GET and require `drifted` or `in_sync`, then reconcile as needed.
6. Run controlled login, downstream JWT validation, and rollback tests.

## Drift and out-of-band changes

A canonical receipt proves that Keyverse once re-observed the exact desired
revision. It is not a lease or continuous integrity monitor. If another operator
changes Keycloak later, GET reports observable drift when the changed field is
within the closed profile. Reconcile restores only the reviewed desired values.
Unknown live mappers stay fail-closed; they are not silently filtered away.

## Deletion and rollback

`DELETE /clients/relying-parties/{client_id}` is remote-first. On observation,
duplicate, or remote deletion failure, Keyverse retains desired state and the
last receipt. After successful remote deletion or confirmed absence, it removes
both records.

Before deletion:

- stop user routing;
- capture non-secret client, mapper, and session evidence;
- preserve the desired payload digest and rollback artifact;
- revoke or escrow confidential credentials through the secret-management port;
- confirm an owner and rollback window.

Rollback uses the same validate and PUT sequence, followed by fresh credential
placement when applicable, exact mapper/status re-observation, and live
authorization-code plus downstream JWT acceptance.

## What the API never proves

The API does not prove:

- DNS or TLS reachability;
- successful authorization-code or PKCE exchange;
- client-secret existence or equality;
- downstream JWT signature, issuer, expiry, token-type, or audience validation;
- authorization correctness for `role`, `org`, or `workspace`;
- user/session migration;
- absence of out-of-band changes after the observation;
- production SLO compliance.

These require separate controlled evidence. Do not interpret `in_sync` or a
successful mapper receipt as authentication or authorization acceptance.
