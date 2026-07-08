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
`resetPasswordAllowed:false`, `registrationAllowed:false`, and a default
`webauthn-register-passwordless` required action, ecosystem-local accounts
authenticate with a **passkey (FIDO2/WebAuthn)**, never a password. See
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
