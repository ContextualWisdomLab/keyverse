# Relying-party onboarding

Each ecosystem application is an OpenID Connect relying party (RP) of Keyverse.
The deployment controller owns rendering, preflight, private Keycloak apply,
and credential placement. Application workloads never receive a Keycloak
administrator credential.

The first profile covers server-side web clients and public browser clients
that use exact HTTPS redirects. Native private-use schemes and loopback HTTP
redirects require a separate reviewed profile and are not accepted here.

## Render, validate, then apply

Render `deploy/templates/oidc-rp-client.json` into a private temporary file.
Resolve every placeholder from deployment configuration or KV. For a public
browser client set `publicClient=true` and
`clientAuthenticatorType=none`; the committed template defaults to a
confidential web client with `client-secret` authentication.

The rendered payload must pass the authenticated Keyverse preflight before the
same original file is sent to private Keycloak Admin REST:

```bash
set -euo pipefail
KEYVERSE_ADMIN="https://keyverse-admin.example"
KEYCLOAK_ADMIN="https://keycloak-admin.internal"
REALM="cwl"
PAYLOAD="$(mktemp)"
PREFLIGHT_RESPONSE="$(mktemp)"
KEYVERSE_AUTH_CONFIG=""
KEYCLOAK_AUTH_CONFIG=""
cleanup() {
  rm -f "$PAYLOAD" "$PREFLIGHT_RESPONSE"
  [ -z "${KEYVERSE_AUTH_CONFIG:-}" ] || rm -f "$KEYVERSE_AUTH_CONFIG"
  [ -z "${KEYCLOAK_AUTH_CONFIG:-}" ] || rm -f "$KEYCLOAK_AUTH_CONFIG"
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$PREFLIGHT_RESPONSE"

XTRACE_WAS_ON=0
case $- in
  *x*) XTRACE_WAS_ON=1; set +x ;;
esac
KEYVERSE_TOKEN="$(kv get secret/keyverse/operator-api-token)"
KEYCLOAK_TOKEN="$(keycloak-admin-token)"
KEYVERSE_AUTH_CONFIG="$(mktemp)"
KEYCLOAK_AUTH_CONFIG="$(mktemp)"
chmod 0600 "$KEYVERSE_AUTH_CONFIG" "$KEYCLOAK_AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$KEYVERSE_TOKEN" \
  >"$KEYVERSE_AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$KEYCLOAK_TOKEN" \
  >"$KEYCLOAK_AUTH_CONFIG"
unset KEYVERSE_TOKEN KEYCLOAK_TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

render deploy/templates/oidc-rp-client.json >"$PAYLOAD"

PREFLIGHT_STATUS="$(
  curl --config "$KEYVERSE_AUTH_CONFIG" \
    --silent \
    --show-error \
    --max-redirs 0 \
    --output "$PREFLIGHT_RESPONSE" \
    --write-out '%{http_code}' \
    --header "Content-Type: application/json" \
    --data-binary @"$PAYLOAD" \
    "$KEYVERSE_ADMIN/clients/relying-parties:validate"
)"
if [ "$PREFLIGHT_STATUS" != "200" ]; then
  printf 'RP preflight returned HTTP %s\n' "$PREFLIGHT_STATUS" >&2
  cat "$PREFLIGHT_RESPONSE" >&2
  exit 1
fi
python3 - "$PREFLIGHT_RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
raise SystemExit(0 if response.get("ready_to_apply") is True else 1)
PY

curl --config "$KEYCLOAK_AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request POST \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$KEYCLOAK_ADMIN/admin/realms/$REALM/clients"
```

Preflight performs no configuration write, DNS lookup, HTTP request, Keycloak
call, client creation, or secret generation. HTTP 200 means only that the
payload satisfies the local Keyverse policy. The deployment controller remains
responsible for private network routing, Keycloak availability, TLS trust,
conflict handling, rollback, and a controlled login test.

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

## Credential placement

Keycloak generates a secret only after a confidential client is created. Read
it through the private administration channel and place it in the platform
secret store, for example:

```text
secret/idp/rp/naruon-web/client-id
secret/idp/rp/naruon-web/client-secret
```

The RP receives a bootstrap reference or workload identity, not a literal
secret in source, a checked-in environment file, a command argument, or an
operator response. Public clients have no client secret.

## Acceptance evidence

Before routing production users, record the rendered payload digest, Keyverse
version, Keycloak version, client UUID, operator identity, preflight receipt,
controlled authorization-code/PKCE login result, logout result, and rollback
reference. Do not record bearer tokens, authorization codes, code verifiers, or
client-secret bytes.

## Checklist

- [ ] placeholders resolved in a mode-0600 file
- [ ] authenticated preflight returned exact HTTP 200
- [ ] `ready_to_apply=true` verified without applying the response body
- [ ] original rendered file applied through private Keycloak Admin REST
- [ ] confidential secret stored only in the approved secret backend
- [ ] exact redirect/origin/logout values independently reviewed
- [ ] controlled login, refresh, logout, and rollback evidence recorded
