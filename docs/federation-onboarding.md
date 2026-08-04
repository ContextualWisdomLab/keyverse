# External federation onboarding

Keyverse treats external identity providers as deployment desired state rather
than portable realm code. This keeps the standalone component reusable across
organizations and allows a parent CWL or Naruon deployment to manage federation
through one stable API.

## Trust boundary

The operator API is privileged. Store its bearer token in the platform secret
manager and expose it only to the deployment controller. The preflight endpoint
accepts the same closed request schema as `PUT`, but it deliberately performs no
storage write, Keycloak call, DNS lookup, or metadata download.

For SAML providers Keyverse requires:

- explicit service-provider and identity-provider entity identifiers;
- an HTTP(S) SSO endpoint;
- signature validation enabled;
- an explicit certificate-source mode;
- either an HTTP(S) metadata descriptor URL or a manually supplied signing
  certificate;
- fully rendered values without `{{...}}` markers.

SAML entity identifiers are absolute URIs and may use an interoperable `urn:`
form. Network endpoints remain restricted to HTTP(S).

## Render, validate, apply

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
ALIAS="employer-adfs"
TOKEN="$(kv get secret/keyverse/operator-api-token)"
PAYLOAD="$(mktemp)"
trap 'rm -f "$PAYLOAD"' EXIT
chmod 0600 "$PAYLOAD"
render deploy/templates/saml-idp-employer-adfs.json >"$PAYLOAD"

curl --fail-with-body --silent --show-error   -H "Authorization: Bearer ${TOKEN}"   -H "Content-Type: application/json"   --data-binary @"$PAYLOAD"   "$BASE/federation/identity-providers:validate"

curl --fail-with-body --silent --show-error -X PUT   -H "Authorization: Bearer ${TOKEN}"   -H "Content-Type: application/json"   --data-binary @"$PAYLOAD"   "$BASE/federation/identity-providers/${ALIAS}"
```

A successful `PUT` persists desired state even when Keycloak is temporarily
unavailable and returns `applied_to_keycloak: false`. This makes the outage
visible without losing the intended configuration.

## Convergence and recovery

List redacted desired state and live convergence status:

```bash
curl --fail-with-body --silent --show-error   -H "Authorization: Bearer ${TOKEN}"   "$BASE/federation/identity-providers"
```

After a Keycloak restart, realm rebuild, or temporary outage, reapply all stored
providers:

```bash
curl --fail-with-body --silent --show-error -X POST   -H "Authorization: Bearer ${TOKEN}"   "$BASE/federation/identity-providers:apply"
```

Delete removes the provider from Keycloak first and then removes desired state.
If Keycloak deletion fails, the desired-state record remains so the operator can
retry without silently orphaning an applied provider.

## Secret handling

Unknown provider configuration values are accepted for convergence but are
redacted from every operator response. Payload files must be private and
short-lived. Do not pass client secrets or signing material in process arguments,
workflow logs, issue comments, or source-controlled templates.

## Standards basis

- OASIS Security Services Technical Committee. (2019). *SAML V2.0 Metadata
  Interoperability Profile Version 1.0*.
  https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.html
- Keycloak. (2026). *Server Administration Guide: SAML v2.0 identity providers*.
  https://www.keycloak.org/docs/latest/server_admin/#saml-v2-0-identity-providers
