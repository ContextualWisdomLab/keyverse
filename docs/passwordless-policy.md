# Passwordless-first policy

## Goal

Eliminate passwords for **ecosystem-local accounts**. Every human either signs
in through a federated IdP or with a **FIDO2/passkey** registered on cwl-idp.
The bound browser flow contains no password authenticator, so there is no local
password to phish, reuse, reset, or leak.

## How it is enforced as code

`deploy/keycloak/realm-cwl.json` fixes the following invariants:

| Setting | Value | Effect |
| --- | --- | --- |
| `browserFlow` | `browser-passwordless` | Cookie/federation or username followed by passwordless WebAuthn |
| `authenticationFlows[browser-passwordless-credentials]` | `webauthn-authenticator-passwordless` only | A password can never authenticate to the `cwl` realm |
| `registrationAllowed` | `false` | Signup is owned by first-party product backends, not an IdP-hosted form |
| `registrationEmailAsUsername` | `true` | The normalized email address is the account identity |
| `resetPasswordAllowed` | `false` | No password-reset surface exists |
| `requiredActions[webauthn-register-passwordless]` | enabled | Keycloak can execute the passkey enrollment action |
| `webAuthnPolicyPasswordless*` | resident key and user verification required | Passkeys are discoverable and user-verified |

`scripts/validate_realm.py` follows every nested subflow reachable from
`browserFlow` and fails CI if it finds `auth-password-form`,
`auth-username-password-form`, or another password authenticator. It also
rejects application RP clients from the portable realm. The runtime
`deploy/templates/oidc-rp-naruon.json` profile independently fixes the public
client access-token lifetime at 300 seconds and is validated by the same closed
Keyverse RP preflight used during deployment.

## Password-free headless registration

The account-unification service's `POST /registration/accounts` endpoint accepts
only identity/profile data. It does **not** accept or create a password.

After creating the disabled-password account, the service calls Keycloak's
Admin REST `execute-actions-email` operation with two required actions:

1. `VERIFY_EMAIL`
2. `webauthn-register-passwordless`

Keycloak sends one bounded link associated with the configured relying-party
client and HTTPS redirect URI. If Keycloak cannot accept the action-email
request, the service deletes the newly created account; if rollback also fails,
the API reports a distinct failure so an operator can reconcile it.

Enabling this endpoint requires all of these KV entries:

- `registration_api_token`, different from `operator_api_token`
- `registration_client_id`
- `registration_redirect_uri`, an absolute HTTPS URI without credentials or a fragment
- `registration_action_lifespan_seconds`, a positive integer no greater than 3600

The Keycloak realm must also have a working SMTP configuration. A deployment
without SMTP should omit `registration_api_token`; the endpoint then fails
closed with HTTP 503 before creating an account.

Registration throttling is keyed by direct peer address. Operators terminating
traffic at a WAF or gateway must preserve trustworthy source isolation there;
the service deliberately does not trust arbitrary forwarded-address headers.

## The one bootstrap exception

Keycloak requires an initial administrator in the `master` realm. It is created
once from deployment secrets, registers a passkey, and then has its reusable
bootstrap credential rotated or disabled. This exception is outside the `cwl`
realm and is governed by the bootstrap runbook.

## Verified email is the linking anchor

An email address authorizes linking only when both accounts hold the same
verified address or an exact external `(provider, subject)` tie exists. The
account-unification service rejects an unverified-email coincidence even when a
caller supplies `explicit_link=true`. The configuration key
`allow_unverified_email_link` remains solely as audit evidence and startup
rejects any attempt to set it true.

## Why this boundary matters

- Federated employees already authenticate at their authoritative employer IdP.
- Passkeys are phishing-resistant and origin-bound.
- Registration proves control of the submitted address through the same
  one-time action link that enrolls the passkey.
- A five-minute access token limits bearer-token exposure while a longer SSO
  session can still support normal product use through refresh and reissue.
