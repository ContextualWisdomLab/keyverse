# Federation & client registration templates

These are **request-body templates** for the Keycloak Admin REST API. They are
applied as-code (idempotently) by your provisioning tooling, which resolves
`{{placeholders}}` from the ecosystem KV config store and posts them with an
admin bearer token (obtained from a service-account client whose secret is in
KV). Nothing here contains a secret.

| Template | Direction | Keycloak endpoint |
| --- | --- | --- |
| `saml-idp-employer-adfs.json` | inbound (external IdP → cwl-idp) | `POST /admin/realms/{realm}/identity-provider/instances` |
| `ldap-source.json` | inbound (external directory → cwl-idp) | `POST /admin/realms/{realm}/components` |
| `oidc-rp-client.json` | outbound (cwl-idp → RP) | `POST /admin/realms/{realm}/clients` |

The realm itself (flows, base client template, the two federation sources) is
imported as-code from [`../keycloak/realm-cwl.json`](../keycloak/realm-cwl.json);
these templates are for registering **additional** RPs / IdPs against a running
realm.

## Apply pattern

```bash
# 1. Get an admin token from the service-account client (secret from KV).
REALM=cwl
BASE="https://idp.example"
TOKEN=$(curl -sS -X POST \
  "$BASE/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d client_id=account-unification-svc \
  -d client_secret="$(kv get secret/idp/account-unification-client-secret)" \
  | jq -r .access_token)

# 2. Render placeholders from KV, then POST.
render deploy/templates/oidc-rp-client.json \
  | curl -sS -X POST "$BASE/admin/realms/$REALM/clients" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" \
      --data @-
```

## Auto-linking policy (important)

Both federation templates set `trustEmail: true`, which makes an incoming
**verified** email an eligible anchor for Keycloak's first-broker-login flow to
auto-link the external identity to a single existing account (and JIT-provision
otherwise). The account-unification service (this repo) enforces the stricter
rule end-to-end: **never link or merge on an unverified email** — see
`docs/merge-unification-flow.md`.
