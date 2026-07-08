# Passwordless-first policy

## Goal

Eliminate passwords for **ecosystem-local accounts**. Every human either signs
in through a federated IdP (employer ADFS, corporate LDAP/AD, optional personal
OIDC) or with a **FIDO2 / passkey** registered on cwl-idp. Password providers
are disabled so there is no local password to phish, reuse, or leak.

## How it is enforced (as-code)

Set once at instance init in `deploy/zitadel/init-steps.yaml`:

| Setting | Value | Effect |
| --- | --- | --- |
| `LoginPolicy.AllowUsernamePassword` | `false` | No username+password login for local accounts |
| `LoginPolicy.AllowRegister` | `false` | No self-service password signup |
| `LoginPolicy.PasswordlessType` | `PASSWORDLESS_TYPE_ALLOWED` | Passkeys are a first-class login method |
| `LoginPolicy.AllowExternalIDP` | `true` | Federated (ADFS/LDAP/OIDC) sign-in stays open |
| `LoginPolicy.HidePasswordReset` | `true` | No password-reset surface |
| `SecondFactors` | `WEBAUTHN`, `TOTP` | Passkey / authenticator factors |
| `MultiFactors` | `WEBAUTHN` | Passkey as MFA |

The passkey relying-party name is set via `WebAuthNName` in
`zitadel-config.yaml`; the RPID is derived from `ExternalDomain`, so it must
match the domain the browser sees (behind the WAF, that is the public IdP host).

## The one exception: the bootstrap admin

ZITADEL requires an initial human admin. It is created **once** with a strong
(16+ char, all classes) password, then that admin registers a passkey and the
password is retired (`PasswordChangeRequired: true` forces rotation; operational
runbook is to switch to passkey-only). No other local account ever has a
password.

## Verified-email is the linking anchor (NIST SP 800-63C)

Following NIST SP 800-63C on federated assertions, cwl-idp treats an email as an
identity-linking anchor **only when the asserting IdP marks it verified**. This
is enforced in two places:

1. **ZITADEL** federation config: `AUTO_LINKING_OPTION_EMAIL` links a new
   external identity to an existing account on matching email — and ZITADEL only
   does so for verified addresses.
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
