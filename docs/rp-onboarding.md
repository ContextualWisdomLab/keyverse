# Relying-party (RP) onboarding guide

Each ecosystem component registers as an **OIDC client** of cwl-idp. Client
registrations and secrets live in the **IdP DB / KV**, never in an RP's
environment file.

Ecosystem RPs: `naruon`, `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`,
`contextual-orchestrator`, and `newsdom-api` (reached via the WAF edge).

## 1. Register an OIDC client

Use the template `deploy/templates/oidc-rp-client.json` against the Keycloak
Admin REST API. One client per RP in the `cwl` realm:

```bash
REALM=cwl
BASE="https://idp.example"

# admin token from the service-account client (secret from KV)
TOKEN=$(curl -sS -X POST \
  "$BASE/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d client_id=account-unification-svc \
  -d client_secret="$(kv get secret/idp/account-unification-client-secret)" \
  | jq -r .access_token)

# create the client (render placeholders from KV first)
render deploy/templates/oidc-rp-client.json \
  | curl -sS -X POST "$BASE/admin/realms/$REALM/clients" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" --data @-
```

For a confidential client, read the generated secret with
`GET /admin/realms/$REALM/clients/{uuid}/client-secret`.

## 2. Store credentials in KV (not env)

```bash
kv put secret/idp/rp/naruon/client-id     "naruon"
kv put secret/idp/rp/naruon/client-secret "$CLIENT_SECRET"   # if confidential
```

The RP reads these from KV at boot. Its deployment env carries at most a single
bootstrap pointer to the KV path — the same pattern the admin service uses.

## 3. Auth method per RP type (OAuth 2.1)

| RP shape | `publicClient` | Flow | Notes |
| --- | --- | --- | --- |
| Server-side web / API (e.g. `newsdom-api`, `contextual-orchestrator`) | `false` | auth-code + PKCE, client secret or `private_key_jwt` | Confidential; secret/JWK in KV |
| SPA / browser (e.g. parts of `semantic-data-portal`) | `true` | auth-code + PKCE (S256) | No secret; PKCE required |
| Native / CLI | `true` | auth-code + PKCE (S256) | No secret; PKCE required |

All RPs use the authorization-code flow with refresh tokens; the implicit and
hybrid flows are **disabled** (`implicitFlowEnabled: false`) per OAuth 2.1.
Access tokens are JWTs with role assertions so RPs can authorize locally.

## 4. Endpoints the RP configures

Discovery document (everything else is derived from it):

```
https://idp.example/realms/cwl/.well-known/openid-configuration
```

| Purpose | Endpoint (realm `cwl`) |
| --- | --- |
| Issuer | `https://idp.example/realms/cwl` |
| Authorization | `/realms/cwl/protocol/openid-connect/auth` |
| Token | `/realms/cwl/protocol/openid-connect/token` |
| UserInfo | `/realms/cwl/protocol/openid-connect/userinfo` |
| JWKS | `/realms/cwl/protocol/openid-connect/certs` |
| End session | `/realms/cwl/protocol/openid-connect/logout` |

## 5. Redirect URIs

Set the RP's exact callback and post-logout URIs in the template
(`redirectUris`, and the `post.logout.redirect.uris` attribute). Use only
registered, HTTPS redirect URIs in real environments (no wildcards).

## 6. Roles & grants

Define realm or client roles in Keycloak, assign them to users/groups, and keep
`roles` in the client's default scopes (already set in the template) so tokens
carry role claims. During account merges, role mappings and group memberships
follow the survivor — see `merge-unification-flow.md`.

## Checklist

- [ ] OIDC client registered from the template
- [ ] `clientId` / `clientSecret` stored in KV under `secret/idp/rp/<name>/…`
- [ ] RP reads credentials from KV at boot (no secret in env)
- [ ] Public clients use PKCE (S256); implicit/hybrid disabled
- [ ] Redirect + post-logout URIs registered, HTTPS only
- [ ] Realm/client roles defined and asserted in tokens
