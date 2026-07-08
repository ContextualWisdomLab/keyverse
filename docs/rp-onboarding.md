# Relying-party (RP) onboarding guide

Each ecosystem component registers as an **OIDC client** of cwl-idp. Client
registrations and secrets live in the **IdP DB / KV**, never in an RP's
environment file.

Ecosystem RPs: `naruon`, `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`,
`contextual-orchestrator`, and `newsdom-api` (reached via the WAF edge).

## 1. Register a project + OIDC app

Use the template `deploy/templates/oidc-rp-client.json` against the ZITADEL
Management API. One project per RP, one OIDC app inside it:

```bash
PAT="$(kv get secret/idp/mgmt-pat)"          # bootstrap transport only
ORG="$(kv get config/idp/org-id)"
BASE="https://idp.example"

# create the project (once)
PROJECT_ID=$(curl -sS -X POST "$BASE/management/v1/projects" \
  -H "Authorization: Bearer $PAT" -H "x-zitadel-orgid: $ORG" \
  -H "Content-Type: application/json" \
  -d '{"name":"naruon"}' | jq -r .id)

# create the OIDC app (render placeholders from KV first)
render deploy/templates/oidc-rp-client.json \
  | curl -sS -X POST "$BASE/management/v1/projects/$PROJECT_ID/apps/oidc" \
      -H "Authorization: Bearer $PAT" -H "x-zitadel-orgid: $ORG" \
      -H "Content-Type: application/json" --data @-
```

ZITADEL returns a `clientId` and, for confidential apps, a `clientSecret`.

## 2. Store credentials in KV (not env)

```bash
kv put secret/idp/rp/naruon/client-id     "$CLIENT_ID"
kv put secret/idp/rp/naruon/client-secret "$CLIENT_SECRET"   # if confidential
```

The RP reads these from KV at boot. Its deployment env carries at most a single
bootstrap pointer to the KV path — the same pattern the admin service uses.

## 3. Auth method per RP type

| RP shape | `appType` | `authMethodType` | Notes |
| --- | --- | --- | --- |
| Server-side web / API (e.g. `newsdom-api`, `contextual-orchestrator`) | `WEB` | `PRIVATE_KEY_JWT` (preferred) or `BASIC` | Confidential; secret/JWK in KV |
| SPA / browser (e.g. parts of `semantic-data-portal`) | `USER_AGENT` | `NONE` + PKCE | No secret; PKCE required |
| Native / CLI | `NATIVE` | `NONE` + PKCE | No secret; PKCE required |

All RPs use the authorization-code flow (`OIDC_RESPONSE_TYPE_CODE`) with refresh
tokens; access tokens are JWTs with role assertions enabled so RPs can authorize
locally from the token.

## 4. Endpoints the RP configures

Discovery document (everything else is derived from it):

```
https://idp.example/.well-known/openid-configuration
```

| Purpose | Endpoint |
| --- | --- |
| Issuer | `https://idp.example` |
| Authorization | `/oauth/v2/authorize` |
| Token | `/oauth/v2/token` |
| UserInfo | `/oidc/v1/userinfo` |
| JWKS | `/oauth/v2/keys` |
| End session | `/oidc/v1/end_session` |

## 5. Redirect URIs

Set the RP's exact callback and post-logout URIs in the template
(`redirectUris`, `postLogoutRedirectUris`). `devMode: false` in all real
environments so only registered, https redirect URIs are accepted.

## 6. Roles & grants

Define project roles in ZITADEL, grant them to users/orgs, and enable
`accessTokenRoleAssertion` / `idTokenRoleAssertion` (already set in the
template). During account merges, grants follow the survivor — see
`merge-unification-flow.md`.

## Checklist

- [ ] Project + OIDC app registered from the template
- [ ] `clientId` / `clientSecret` stored in KV under `secret/idp/rp/<name>/…`
- [ ] RP reads credentials from KV at boot (no secret in env)
- [ ] Correct `appType` / `authMethodType` for the RP shape (PKCE for public)
- [ ] Redirect + post-logout URIs registered, `devMode: false`
- [ ] Project roles defined and asserted in tokens
