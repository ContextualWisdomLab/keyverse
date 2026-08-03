# Passwordless-first policy

## Goal

Eliminate passwords for **ecosystem-local accounts**. Every human either signs
in through a federated IdP (employer ADFS, corporate LDAP/AD, optional personal
OIDC) or with a **FIDO2 / passkey** registered on cwl-idp. The password
authenticator is removed from the browser flow so there is no local password to
phish, reuse, or leak.

## How it is enforced (as-code)

Set once at realm import from `deploy/keycloak/realm-cwl.json`:

| Setting | Value | Effect |
| --- | --- | --- |
| `browserFlow` | `browser-passwordless` | Custom flow: username form → **WebAuthn passwordless**, no password authenticator |
| `authenticationFlows[browser-passwordless-forms]` | `auth-username-form` + `webauthn-authenticator-passwordless` | Passkey is the primary (and only) knowledge-free factor |
| `registrationAllowed` | `false` | Signup happens on product pages via the account-unification `/registration/accounts` API, never on IdP-hosted forms |
| `registrationEmailAsUsername` | `true` | The email address is the account identity |
| `verifyEmail` | `false` (until SMTP) | Must stay `false` while the realm has no `smtpServer`; the validator enforces the pairing |
| `resetPasswordAllowed` | `false` | No password-reset surface |
| `authenticationFlows[browser-passwordless-credentials]` | passkey + credential form, both ALTERNATIVE | The credential form is a **bootstrap-only** path: it is offered solely to API-registered accounts that have not enrolled a passkey yet, and the registration password janitor revokes the credential after enrollment |
| `requiredActions[webauthn-register-passwordless]` | `defaultAction: true` | New users are prompted to enrol a passkey |
| `webAuthnPolicyPasswordless*` | RP name / ES256,RS256 / resident key / UV required | Passkey relying-party policy |

Because the bound browser flow contains **no** `auth-password-form` /
`auth-username-password-form` authenticator, a local password is never accepted
at login even if one existed on the user. `scripts/validate_realm.py` asserts
this invariant in CI (fails if any password authenticator appears in the bound
browser flow, or if the passwordless WebAuthn authenticator is missing).

The passkey relying-party name is `webAuthnPolicyPasswordlessRpEntityName`; the
RPID derives from the request host (behind the WAF, the public IdP host), so
`KC_HOSTNAME` must match the domain the browser sees.

## The one exception: the bootstrap admin

Keycloak requires an initial admin in the `master` realm. It is created **once**
from `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD` (bootstrap
transport from KV), then that admin registers a passkey and the password is
retired (operational runbook: switch to passkey-only, rotate/disable the
bootstrap password). No ecosystem-local account in the `cwl` realm has a
password.

## Verified-email is the linking anchor (NIST SP 800-63C)

Following NIST SP 800-63C on federated assertions, cwl-idp treats an email as an
identity-linking anchor **only when the asserting IdP marks it verified**. This
is enforced in two places:

1. **Keycloak** federation config: `trustEmail: true` on the employer ADFS SAML
   IdP and the LDAP/AD source lets the first-broker-login flow auto-link a new
   external identity to an existing account on a matching **verified** email.
2. **account-unification service** (`app/matching.py`): the merge engine refuses
   to treat an unverified-email coincidence as a match, and refuses any merge
   whose only tie is an unverified email (`UnverifiedEmailMergeError`).

The config key `allow_unverified_email_link` exists solely so an audit can prove
it is hard-defaulted to `false`.

## Why passwordless here specifically

- Most human logins arrive already authenticated by the employer ADFS or the
  corporate directory — a local password would be a redundant, weaker factor.
- Passkeys are phishing-resistant and bind to the origin, which matters when a
  single IdP fronts many ecosystem RPs.
