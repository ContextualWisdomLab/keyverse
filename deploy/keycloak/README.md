# Keycloak config-as-code

Keyverse runs on **Keycloak** (Apache-2.0). The portable `cwl` realm shape is
imported at container start; deployment-specific secrets and external identity
providers are converged afterwards from the KV/DB source of truth.

| File | Responsibility |
| --- | --- |
| `realm-cwl.json` | Portable passwordless realm, shared client scopes, RP template, concrete `naruon-web` PKCE client, and account-unification service client |
| `kcadm-bootstrap.sh` | Idempotently inject the service-client secret, grant least-privilege realm-management roles, and reconcile the role mapper |
| `../templates/` | Reference payloads for runtime federation and additional relying-party registrations |

## Passwordless browser and enrollment flows

The bound `browser-passwordless` flow accepts an existing session, a federated
identity, or username followed by `webauthn-authenticator-passwordless`. It has
**no password authenticator**.

First-party products create password-free accounts through
`POST /registration/accounts`. The account-unification service then invokes
Keycloak's `execute-actions-email` Admin REST operation with `VERIFY_EMAIL` and
`webauthn-register-passwordless`. The resulting bounded link verifies control of
the address and enrolls the first passkey before normal login. A failed email
request rolls the new account back.

A deployment that enables registration must configure Keycloak SMTP and set the
following account-unification KV entries:

- `registration_api_token`
- `registration_client_id`
- `registration_redirect_uri`
- `registration_action_lifespan_seconds`

Without the registration token the endpoint is unavailable rather than open.
See [`../../docs/passwordless-policy.md`](../../docs/passwordless-policy.md).

## Portable realm versus deployment data

The committed realm contains no employer ADFS, LDAP/AD source, or other external
federation. Those objects are customer/deployment data and are managed through
`/federation/identity-providers`. Desired state is stored in the KV/DB backend
and can be reapplied after a realm rebuild with
`POST /federation/identity-providers:apply`.

This separation also avoids Keycloak 26 import failures from placeholder SAML
URLs or invalid placeholder LDAP distinguished names.

## Keycloak 26 import rules

`scripts/validate_realm.py` enforces these fail-closed rules:

- no `$`-prefixed annotation keys;
- no committed external federation or user-storage provider;
- no password authenticator in any subflow reachable from `browserFlow`;
- `webauthn-register-passwordless` remains enabled;
- `basic`, `profile`, and `email` scopes exist, with `basic` providing `sub`;
- public `naruon-web` requires PKCE S256 and an access-token lifespan no greater
  than 900 seconds;
- committed client secrets are placeholders only.

## RP clients

`ecosystem-rp-template` is a confidential PKCE S256 blueprint. It uses the
reserved `rp.example.invalid` host so no product-specific deployment value is
silently inherited. Clones must replace redirect/origin values, client ID,
secret, and audience mapper together.

`naruon-web` is the first concrete public PKCE client. It carries the audience
and `role`/`org`/`workspace` claims required by the current Naruon session
contract. Its access tokens last 300 seconds; the longer SSO session is serviced
through normal token refresh/reissue rather than a twelve-hour bearer token.

`naruon-web` also has `directAccessGrantsEnabled: true` — a scoped, reviewed
exception ([ADR-0014](../../docs/adr/0014-naruon-owned-password-form.md)) so
naruon can render its own login form with zero Keycloak-rendered HTML in the
loop. No other RP gets this exception; the account-unification dynamic-
registration validator still hard-rejects `directAccessGrantsEnabled: true`
for everyone else.

A real password credential to authenticate with comes from
`POST /registration/accounts/password`
([ADR-0015](../../docs/adr/0015-naruon-password-credential-issuance.md)),
gated by its own `password_registration_api_token` — a third bearer
credential, distinct from `operator_api_token` and `registration_api_token`.
Without it configured, naruon's signup surface stays unavailable (503)
rather than open. The realm's `passwordPolicy`
(`"length(12) and notUsername and notEmail"`) enforces the same minimum a
second time, server-side, independent of the endpoint's own validation.

## Bootstrap

```bash
# Keycloak imports the realm at first start.
docker compose up -d

# Once Keycloak is ready, converge the service client and its scoped roles.
KC_SERVER=http://localhost:8080 deploy/keycloak/kcadm-bootstrap.sh
```

The bootstrap obtains credentials from the platform `kv` helper, keeps kcadm
session material inside a private temporary directory, never places reusable
secrets in process arguments, validates every resolved identifier, and
reconciles the protocol mapper without creating duplicates.
