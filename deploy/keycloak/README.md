# Keycloak config-as-code

cwl-idp runs on **Keycloak** (Apache-2.0). The realm is declared as-code and
imported at container start; secrets are patched afterwards from the KV store.

| File | What |
| --- | --- |
| `realm-cwl.json` | The `cwl` realm: passkey-first passwordless browser flow, OIDC/OAuth2.1 RP client template, employer ADFS SAML IdP (inbound), LDAP/AD federation, and the account-unification service-account client. Imported via `start --import-realm`. |
| `kcadm-bootstrap.sh` | Post-import patch: injects secrets/URLs (ADFS metadata, LDAP bind credential, service-account client secret) from KV using `kcadm.sh`, and grants the service account `realm-management` view-users/manage-users. |

## Passwordless-first (passkeys)

`realm-cwl.json` defines an authentication flow **`browser-passwordless`** with
`auth-username-form` → `webauthn-authenticator-passwordless` and **no password
authenticator**, and binds it as the realm `browserFlow`. Combined with
`resetPasswordAllowed:false` and a default
`webauthn-register-passwordless` required action, ecosystem-local accounts
authenticate with a **passkey (FIDO2/WebAuthn)**, never a password. Self-service
signup is allowed (`registrationAllowed:true`, `registrationEmailAsUsername:true`):
the registration form's throwaway password never becomes a usable login
credential, because the first session immediately enrolls a passkey and the
browser flow has no password authenticator. `verifyEmail` stays `false` until a
realm `smtpServer` is configured (the validator enforces that pairing). See
[`../../docs/passwordless-policy.md`](../../docs/passwordless-policy.md).

## What is committed vs. patched from KV

Committed (non-secret shape): realm, flows, client template, IdP + LDAP
*structure*, mappers. Patched from KV at bootstrap (never committed): ADFS
metadata URL, LDAP connection URL / bind DN / bind credential, and every client
secret. Placeholders read `__set_from_kv__`.

## Apply

```bash
# 1. Keycloak imports realm-cwl.json automatically on first start
#    (docker-compose mounts it at /opt/keycloak/data/import).
docker compose up -d

# 2. Once Keycloak is READY, patch secrets from KV:
KC_SERVER=http://localhost:8080 deploy/keycloak/kcadm-bootstrap.sh
```

## Federation & client registration templates

Additional Admin-API request bodies for registering more RPs / IdPs live in
[`../templates/`](../templates/) (Keycloak client / SAML IdP / LDAP component
representations).

## Realm-file rules Keycloak 26 enforces

The realm JSON is parsed into typed representations, so two patterns that used
to live in this file are **import failures** on Keycloak 26 and must not come
back (`scripts/validate_realm.py` guards both):

- **No `$`-prefixed annotation keys.** `RealmRepresentation` rejects unknown
  fields (`Unrecognized field "$comment"`), which aborts `--import-realm` and
  crash-loops the container. Document intent in this README instead of inline
  JSON annotations.
- **No committed external federation.** SAML IdP URL fields are URL-validated
  at import (a bare `__set_from_kv__` aborts it) and an enabled LDAP source
  with placeholder DNs breaks every realm user operation (`Invalid DN`). The
  deeper problem is that employer-specific federation (ADFS, corporate LDAP)
  is deployment data, so the realm commits **none of it**: register external
  IdPs at runtime through the account-unification service's
  `/federation/identity-providers` API. Desired state persists in the KV/DB
  config store and is converged into Keycloak over the Admin REST API, so a
  realm rebuild is re-converged with one `POST
  /federation/identity-providers:apply`. `../templates/` holds ready-made
  payloads (ADFS SAML, LDAP component, OIDC RP).

## Client scopes and the Keycloak 26 lightweight-token pitfall

Imported realms do **not** get the standard client scopes auto-created, and
without the `basic` scope Keycloak 26 access tokens omit the `sub` claim —
which breaks any RP that authenticates by subject (naruon returns 401 for
every request). The realm therefore commits `basic` (Subject + auth_time),
`profile`, and `email` scopes and assigns them as realm defaults plus explicit
`defaultClientScopes` on each RP client.

## RP clients: template + naruon

`ecosystem-rp-template` stays the confidential-client blueprint (OAuth 2.1:
code + PKCE S256, no implicit, exact redirect URIs, secret from KV). Clones
must rename the audience mapper's `included.client.audience` to the new
clientId.

`naruon-web` is the first concrete RP, committed as-code as a **public** PKCE
client because the naruon browser flow cannot hold a client secret. It carries
the claims naruon's backend session contract requires: `sub` (via `basic`),
an `aud` containing `naruon-web`, and hardcoded `role=member` /
`org` / `workspace` claims. The committed `org`/`workspace` values
(`org-cwl` / `workspace-org-cwl`) and the `https://naruon.example` redirect
URIs are deployment placeholders — patch them per environment with `kcadm.sh`
(see `../templates/`). `access.token.lifespan` is 43200s to fit naruon's 12h
session ceiling; admin roles are never asserted from IdP claims by design.
