# External federation onboarding

Keyverse treats external identity providers as deployment desired state rather
than portable realm code. This keeps the standalone component reusable across
organizations and allows a parent CWL or Naruon deployment to manage federation
through one stable API.

## Trust boundary

The operator API is privileged. Store its bearer token in the platform secret
manager and expose it only to the deployment controller. The preflight endpoint
accepts the same closed request schema as `PUT`, but deliberately performs no
storage write, Keycloak call, DNS lookup, or metadata download.

For SAML providers, Keyverse requires:

- explicit service-provider and identity-provider entity identifiers;
- an HTTP(S) SSO endpoint;
- signature validation enabled;
- an explicit certificate-source mode;
- either an HTTP(S) metadata descriptor URL or a manually supplied signing
  certificate;
- fully rendered values without `{{...}}` markers.

SAML entity identifiers are bounded absolute URIs and may use an interoperable
`urn:` form. Network endpoints remain restricted to HTTP(S) and reject
credentials, fragments, whitespace, backslashes, and raw or percent-encoded
control characters. Preflight validates syntax and policy only; a deployment
controller should separately restrict Keycloak egress to the approved metadata
and SSO hosts.

## Render, validate, apply

The following example keeps both the rendered payload and bearer header in
private temporary files. The token is never passed in the `curl` process
arguments.

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
ALIAS="employer-adfs"
PAYLOAD="$(mktemp)"
PREFLIGHT_RESPONSE="$(mktemp)"
AUTH_CONFIG=""
cleanup() {
  rm -f "$PAYLOAD" "$PREFLIGHT_RESPONSE"
  if [ -n "${AUTH_CONFIG:-}" ]; then
    rm -f "$AUTH_CONFIG"
  fi
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$PREFLIGHT_RESPONSE"

XTRACE_WAS_ON=0
case $- in
  *x*)
    XTRACE_WAS_ON=1
    set +x
    ;;
esac
TOKEN="$(kv get secret/keyverse/operator-api-token)"
AUTH_CONFIG="$(mktemp)"
chmod 0600 "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

render deploy/templates/saml-idp-employer-adfs.json >"$PAYLOAD"

PREFLIGHT_STATUS="$(
  curl --config "$AUTH_CONFIG" \
    --silent \
    --show-error \
    --max-redirs 0 \
    --output "$PREFLIGHT_RESPONSE" \
    --write-out '%{http_code}' \
    --header "Content-Type: application/json" \
    --data-binary @"$PAYLOAD" \
    "$BASE/federation/identity-providers:validate"
)"
if [ "$PREFLIGHT_STATUS" != "200" ]; then
  printf 'preflight returned HTTP %s\n' "$PREFLIGHT_STATUS" >&2
  cat "$PREFLIGHT_RESPONSE" >&2
  exit 1
fi
if ! python3 - "$PREFLIGHT_RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
raise SystemExit(0 if response.get("ready_to_apply") is True else 1)
PY
then
  echo 'preflight response did not confirm ready_to_apply=true' >&2
  exit 1
fi

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request PUT \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers/$ALIAS"
```

A successful `PUT` persists desired state even when Keycloak is temporarily
unavailable and returns `applied_to_keycloak: false`. This makes the outage
visible without losing the intended configuration.

## Convergence and recovery

The recovery block is independently executable. It recreates its private bearer
configuration, lists redacted desired state and live convergence status, then
reapplies every stored provider after a Keycloak restart, realm rebuild, or
temporary outage:

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
AUTH_CONFIG=""
cleanup() {
  if [ -n "${AUTH_CONFIG:-}" ]; then
    rm -f "$AUTH_CONFIG"
  fi
}
trap cleanup EXIT

XTRACE_WAS_ON=0
case $- in
  *x*)
    XTRACE_WAS_ON=1
    set +x
    ;;
esac
TOKEN="$(kv get secret/keyverse/operator-api-token)"
AUTH_CONFIG="$(mktemp)"
chmod 0600 "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  "$BASE/federation/identity-providers"

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request POST \
  "$BASE/federation/identity-providers:apply"

cleanup
trap - EXIT
```

Delete removes the provider from Keycloak first and then removes desired state.
If Keycloak deletion fails, the desired-state record remains so the operator can
retry without silently orphaning an applied provider.

## Secret and certificate handling

Unknown provider configuration values are accepted for convergence but are
redacted from every operator response. Payload files must be private and
short-lived. Do not pass client secrets, bearer tokens, or signing material in
process arguments, workflow logs, issue comments, or source-controlled
templates.

When metadata refresh is enabled, pin the identity-provider entity identifier
and restrict network egress to the approved metadata host. When metadata refresh
is disabled, `signingCertificate` must contain one or more comma-separated
Base64 DER X.509 certificate bodies without PEM headers or footers.

For a manual certificate rollover, render both the previous and next certificate
as active trust material in the same `PUT` payload, for example
`"signingCertificate": "<previous-base64-der>,<next-base64-der>"`. Run the
complete render → preflight → `PUT` sequence before the upstream IdP switches
keys. Keep both certificates in that field throughout the overlap window. After
the upstream rollover period ends, render only the next certificate and repeat
preflight and `PUT` to remove the previous certificate. Storing the previous
certificate elsewhere does not preserve active signature trust.

## Standards basis

- OASIS Security Services Technical Committee. (2019). *SAML V2.0 Metadata
  Interoperability Profile Version 1.0*.
  https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.html
- Keycloak. (2026). *Server Administration Guide: SAML v2.0 identity providers*.
  https://www.keycloak.org/docs/latest/server_admin/#saml-v2-0-identity-providers
