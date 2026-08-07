# Relying-party onboarding

Each ecosystem application is an OpenID Connect relying party (RP) of Keyverse.
The deployment controller owns rendering, Keyverse validation and reconciliation,
confidential-client credential placement, and controlled acceptance tests.
Application workloads never receive a Keycloak administrator credential.

The first profile covers server-side web clients and public browser clients
that use exact HTTPS redirects. Native private-use schemes and loopback HTTP
redirects require a separate reviewed profile and are not accepted here.

## Render, validate, then reconcile

Render `deploy/templates/oidc-rp-client.json` into a private temporary file.
Resolve every placeholder from deployment configuration or KV. For a public
browser client set `publicClient=true` and
`clientAuthenticatorType=none`; the committed template defaults to a
confidential web client with `client-secret` authentication.

The same original secret-free payload must pass pure preflight and then the
durable Keyverse desired-state boundary:

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

Preflight performs no configuration write, DNS lookup, HTTP request, Keycloak
call, client creation, or secret generation. The PUT stores validated desired
state before attempting Keycloak convergence. It classifies exact `clientId`
matches, creates or repairs one client, re-observes the live metadata, and writes
a canonical receipt only after exact verification.

Neither response proves successful login. The deployment controller remains
responsible for private network routing, Keycloak availability, TLS trust,
credential placement, live authorization-code tests, rollback, and operating
SLO evidence.

## Closed first-profile policy

The payload must satisfy all of the following:

- authorization code flow enabled;
- implicit, password/direct-access, and service-account flows disabled;
- PKCE fixed to `S256` for both public and confidential clients;
- exact HTTPS redirect URIs, CORS origins, and post-logout URI;
- no wildcard, `+`, userinfo, query, fragment, control, encoded delimiter, or
  dot-segment syntax;
- CORS origins exactly equal the set of redirect URI origins;
- post-logout URI uses one of those registered origins;
- confidential clients use `client-secret`; public clients use `none`;
- no credential or registration-token field in the payload;
- `fullScopeAllowed=false`;
- exact portable default scope set: `basic`, `profile`, and `email`;
- access token lifetime between 60 and 900 seconds;
- backchannel logout session handling enabled;
- unresolved template markers rejected.

Role and audience claims remain server-owned realm/client mapper policy. The RP
template does not widen its default scope set to request deployment-specific
claims.

## Desired-state lifecycle

The authenticated surface is:

```text
GET    /clients/relying-parties
POST   /clients/relying-parties:reconcile
GET    /clients/relying-parties/{client_id}
PUT    /clients/relying-parties/{client_id}
DELETE /clients/relying-parties/{client_id}
```

`in_sync` requires one exact live client, observable equality for the closed
profile, and a canonical receipt matching the desired revision. `drifted`,
`absent`, `ambiguous`, `unavailable`, and `apply_failed` are explicit and never
reported as success. Duplicate exact clients are not mutated automatically.

Deletion is remote-first. If live observation, duplicate resolution, or remote
deletion fails, Keyverse retains the desired state and receipt needed for
recovery. Realm rebuilds are repaired by the reconcile endpoint.

See `docs/operations/oidc-rp-reconciliation.md` for detailed triage and rollback.

## Credential placement

The desired-state payload never contains a client secret. Keycloak may generate
a secret for a confidential client, but reading and placing it is a separate
approved secret-management operation. Store it, for example, under:

```text
secret/idp/rp/naruon-web/client-id
secret/idp/rp/naruon-web/client-secret
```

The RP receives a bootstrap reference or workload identity, not a literal
secret in source, a checked-in environment file, a command argument, a
Keyverse desired-state record, or an operator response. Public clients have no
client secret.

## Acceptance evidence

Before routing production users, record the desired payload digest, canonical
apply receipt, Keyverse version, Keycloak version, client UUID, operator
identity, controlled authorization-code/PKCE login result, refresh result,
logout result, and rollback reference. Do not record bearer tokens,
authorization codes, code verifiers, or client-secret bytes.

## Checklist

- [ ] placeholders resolved in a mode-0600 file
- [ ] authenticated preflight returned exact HTTP 200
- [ ] `ready_to_apply=true` verified without applying the response body
- [ ] original rendered file sent to Keyverse PUT, not directly to public Admin REST
- [ ] `convergence_state=in_sync` and receipt match verified
- [ ] confidential secret stored only through the approved secret-management port
- [ ] exact redirect/origin/logout values independently reviewed
- [ ] controlled login, refresh, logout, and rollback evidence recorded
