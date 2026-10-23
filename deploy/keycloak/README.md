# Keycloak config-as-code

Keyverse runs on **Keycloak** (Apache-2.0). The portable `cwl` realm shape is
imported at container start; deployment-specific secrets and external identity
providers are converged afterwards from the KV/DB source of truth.

| File | Responsibility |
| --- | --- |
| `realm-cwl.json` | Portable passwordless realm, shared client scopes, and the account-unification control-plane service client; no application RP clients |
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

The committed realm contains no employer ADFS, LDAP/AD source, external
federation, reusable RP template, or application RP. Those objects are
customer/deployment data. Federation is managed through
`/federation/identity-providers`; application clients are managed through
`/clients/relying-parties`. Desired state is stored in the KV/DB backend and can
be reapplied after a realm rebuild through the respective reconciliation route.

This separation also avoids Keycloak 26 import failures from placeholder SAML
URLs or invalid placeholder LDAP distinguished names.

## Keycloak 26 import rules

`scripts/validate_realm.py` enforces these fail-closed rules:

- no `$`-prefixed annotation keys;
- no committed external federation or user-storage provider;
- no password authenticator in any subflow reachable from `browserFlow`;
- `webauthn-register-passwordless` remains enabled;
- `basic`, `profile`, and `email` scopes exist, with `basic` providing `sub`;
- runtime application clients are rejected from the portable import;
- the `account-unification-svc` control-plane client remains present;
- committed client secrets are placeholders only.

## RP clients

`deploy/templates/oidc-rp-client.json` is the confidential PKCE S256 blueprint;
`deploy/templates/oidc-rp-naruon.json` is the concrete public Naruon profile.
Neither is imported with the realm. Render and preflight the chosen template,
persist it through Keyverse desired state, reconcile it into Keycloak, place any
confidential secret through the separate secret channel, and only then route
login traffic. The Naruon profile carries the reviewed audience and bounded
`role`/`org`/`workspace` claims and retains a 300-second access-token lifetime.

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
