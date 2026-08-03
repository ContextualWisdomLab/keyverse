# Keycloak config-as-code

cwl-idp runs on **Keycloak** (Apache-2.0). The portable realm shape is declared
as code and imported at container start. Deployment-specific secrets and
federation desired state remain outside the repository.

| File | What |
| --- | --- |
| `realm-cwl.json` | The portable `cwl` realm: passkey-first browser flow, standard client scopes, OIDC/OAuth 2.1 RP templates, the concrete `naruon-web` public PKCE client, and the account-unification service-account client. Imported via `start --import-realm`. |
| `kcadm-bootstrap.sh` | Idempotent post-import convergence: reads the service-account client secret from KV without placing it in process arguments, grants the minimum `realm-management` roles, and reconciles the client scope/protocol mapper required to emit them. |

## Passwordless-first (passkeys)

`realm-cwl.json` defines an authentication flow **`browser-passwordless`** with
`auth-username-form` → `webauthn-authenticator-passwordless` and **no password
authenticator**, and binds it as the realm `browserFlow`. Combined with
`resetPasswordAllowed:false` and a default
`webauthn-register-passwordless` required action, ecosystem-local accounts
authenticate with a **passkey (FIDO2/WebAuthn)** in the steady state.
Self-service signup is **headless**: product frontends such as Naruon own the
signup page and create accounts through the account-unification service's
`/registration/accounts` API (`registrationAllowed` stays `false`, so the
IdP-hosted registration form never appears). API-registered accounts carry a
bootstrap password that the `browser-passwordless-credentials` subflow offers
only while no passkey exists; the first session enrolls a passkey and the
credential janitor then removes the bootstrap credential. `verifyEmail` stays
`false` until a realm `smtpServer` is configured; the validator enforces that
pairing. See
[`../../docs/passwordless-policy.md`](../../docs/passwordless-policy.md).

## What is committed, bootstrapped, and registered at runtime

**Committed portable shape:** realm settings, browser flows, standard client
scopes, RP client structure, protocol mappers, and the account-unification
service-account client. Any committed secret field remains a non-deployable
placeholder such as `__set_from_kv__`.

**Converged by `kcadm-bootstrap.sh`:** the account-unification client secret,
its least-privilege `realm-management` grants, the client scope mappings, and a
single named protocol mapper. The script is safe to repeat: it updates the
existing mapper, removes historical duplicates, and keeps the reusable admin
password and client secret out of child-process arguments.

**Registered at runtime:** employer ADFS, LDAP-fronting brokers, optional OIDC
providers, and their credentials. The account-unification federation API stores
desired state in KV/DB and converges Keycloak through the Admin REST API. This
keeps employer-specific topology out of reusable realm source code.

## Apply

```bash
# 1. Keycloak imports realm-cwl.json automatically on first start
#    (docker-compose mounts it at /opt/keycloak/data/import).
docker compose up -d

# 2. Once Keycloak is READY, converge the service account from KV:
KC_SERVER=http://localhost:8080 deploy/keycloak/kcadm-bootstrap.sh

# 3. Register or re-apply deployment-specific federation desired state:
# POST /federation/identity-providers:apply
```

## Federation and client-registration templates

Admin-API request bodies for registering additional RPs and external identity
providers live in [`../templates/`](../templates/). These are payload
references, not resources imported into the committed realm.

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
  with placeholder DNs breaks realm user operations (`Invalid DN`). Employer
  ADFS and corporate LDAP are deployment data, so the realm commits none of
  them. Register providers through `/federation/identity-providers`; desired
  state persists in KV/DB and a rebuilt realm is re-converged with
  `POST /federation/identity-providers:apply`.

## Client scopes and the Keycloak 26 lightweight-token pitfall

Imported realms do **not** get the standard client scopes auto-created, and
without the `basic` scope Keycloak 26 access tokens omit the `sub` claim. That
breaks RPs that authenticate by subject. The realm therefore commits `basic`
(Subject + auth_time), `profile`, and `email` scopes and assigns them as realm
defaults plus explicit `defaultClientScopes` on each RP client.

## RP clients: template + Naruon

`ecosystem-rp-template` stays the confidential-client blueprint (OAuth 2.1:
code + PKCE S256, no implicit flow, exact redirect URIs, secret from KV). Clones
must rename the audience mapper's `included.client.audience` to the new
`clientId`.

`naruon-web` is the first concrete RP, committed as a **public** PKCE client
because a browser cannot hold a client secret. It carries the claims Naruon's
backend session contract requires: `sub` (via `basic`), an `aud` containing
`naruon-web`, and hardcoded `role=member`, `org`, and `workspace` claims. The
committed `org`/`workspace` values (`org-cwl` / `workspace-org-cwl`) and
`https://naruon.example` redirect URIs are deployment placeholders and must be
replaced per environment through an operator-managed Admin API payload.
`access.token.lifespan` is 43200 seconds to fit Naruon's 12-hour session ceiling;
admin roles are never asserted from external IdP claims by design.
