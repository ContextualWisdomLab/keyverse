# External federation onboarding

Keyverse treats external identity providers as deployment desired state rather
than portable realm code. This keeps the standalone component reusable across
organizations and allows a parent CWL or Naruon deployment to manage federation
through one stable API.

## Trust boundary

The operator API is privileged. Store its bearer token in the platform secret
manager and expose it only to the deployment controller. At the WAF edge,
expose only the Keyverse admin and SCIM APIs plus explicitly permitted Keycloak
OIDC endpoints. Keep the account-unification/federation service network and the
Keycloak Admin REST API private and unreachable from the public internet. The
preflight endpoint accepts the same closed request schema as `PUT`, but
deliberately performs no storage write, Keycloak call, DNS lookup, or metadata
download.

For SAML providers, Keyverse requires:

- explicit service-provider and identity-provider entity identifiers;
- an HTTP(S) SSO endpoint;
- signature validation enabled;
- an explicit certificate-source mode;
- either an HTTP(S) metadata descriptor URL or a manually supplied signing
  certificate;
- fully rendered values without `{{...}}` markers.

SAML entity identifiers are bounded absolute URIs and may use an interoperable
`urn:` form. Network endpoints are restricted to HTTPS and reject credentials,
fragments, whitespace, backslashes, and raw or percent-encoded control
characters. Preflight deliberately does not dereference metadata or follow
redirects, so it cannot observe a redirect target. Restrict Keycloak egress or
its outbound proxy to approved HTTPS metadata and SSO hosts, and reject every
HTTPS-to-HTTP redirect before the response reaches Keycloak.

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
  if [ -n "$AUTH_CONFIG" ]; then
    rm -f "$AUTH_CONFIG"
  fi
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$PREFLIGHT_RESPONSE"

xtrace_was_on=0
case $- in
  *x*) xtrace_was_on=1; set +x ;;
esac
TOKEN="$(kv get secret/keyverse/operator-api-token)"
AUTH_CONFIG="$(mktemp)"
chmod 0600 "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN
if [ "$xtrace_was_on" -eq 1 ]; then
  set -x
fi

render deploy/templates/saml-idp-employer-adfs.json >"$PAYLOAD"

preflight_code="$(
  curl --config "$AUTH_CONFIG" \
    --max-redirs 0 \
    --silent \
    --show-error \
    --output "$PREFLIGHT_RESPONSE" \
    --write-out '%{http_code}' \
    --header "Content-Type: application/json" \
    --data-binary @"$PAYLOAD" \
    "$BASE/federation/identity-providers:validate"
)"

if [ "$preflight_code" != "200" ]; then
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

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --max-redirs 0 \
  --silent \
  --show-error \
  --request PUT \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers/$ALIAS"
```

A successful `PUT` persists desired state even when Keycloak is temporarily
unavailable and returns `applied_to_keycloak: false`. This makes the outage
visible without losing the intended configuration.

## Convergence and recovery

The recovery block below is independently executable in a new shell. It creates
and removes its own private bearer configuration before listing and applying
stored provider desired state:

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
AUTH_CONFIG=""
cleanup() {
  if [ -n "$AUTH_CONFIG" ]; then
    rm -f "$AUTH_CONFIG"
  fi
}
trap cleanup EXIT

xtrace_was_on=0
case $- in
  *x*) xtrace_was_on=1; set +x ;;
esac
TOKEN="$(kv get secret/keyverse/operator-api-token)"
AUTH_CONFIG="$(mktemp)"
chmod 0600 "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN
if [ "$xtrace_was_on" -eq 1 ]; then
  set -x
fi

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --max-redirs 0 \
  --silent \
  --show-error \
  "$BASE/federation/identity-providers"

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --max-redirs 0 \
  --silent \
  --show-error \
  --request POST \
  "$BASE/federation/identity-providers:apply"
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

When metadata refresh is enabled, pin the identity-provider entity identifier,
restrict network egress to the approved HTTPS metadata host, and reject
redirect downgrade. A supplied optional `signingCertificate` is still parsed
and rejected if malformed, but metadata remains the selected certificate source.
When metadata refresh is disabled, each `signingCertificate` entry must be a
Base64 DER X.509
certificate body without PEM headers or footers. For a manual rollover, set
`signingCertificate` in the `PUT` payload to
`previous_certificate_body,next_certificate_body` so both certificates remain
active trusted certificates throughout the upstream rollover window. After the
upstream no longer signs with the previous key, render, preflight, and `PUT` the
payload again with only `next_certificate_body`; storing the previous
certificate separately does not preserve active trust.

## Standards basis

- OASIS Security Services Technical Committee. (2019). *SAML V2.0 Metadata
  Interoperability Profile Version 1.0*.
  https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.html
- Keycloak. (2026). *Server Administration Guide: SAML v2.0 identity providers*.
  https://www.keycloak.org/docs/latest/server_admin/#saml-v2-0-identity-providers
