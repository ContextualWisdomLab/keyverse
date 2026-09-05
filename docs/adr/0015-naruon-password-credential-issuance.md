# ADR-0015: Scoped password-credential issuance so naruon's signup form actually logs in

**Status:** Accepted, endpoint fails closed pending RFC-compliant redesign — see
**Correction (2026-09-03)** below before implementing anything against this ADR.
**Date:** 2026-09-02
**Decision owner:** Keyverse maintainers
**Scope:** A new, narrowly scoped account-unification endpoint that creates a
`cwl`-realm user with an immediately usable password credential, callable
only by naruon. Does not touch `browserFlow`, does not change any other RP's
capabilities, and does not add self-service password reset, email
verification, or CAPTCHA-equivalent abuse hardening — see "Deferred."

## Correction (2026-09-03)

[ADR-0014](0014-naruon-owned-password-form.md)'s Correction disabled `naruon-web`'s
`directAccessGrantsEnabled` (RFC 9700 §2.4 / RFC 10017 §7.3: the Resource Owner
Password Credentials grant this ADR's "immediately usable password credential" was
built for). That leaves the account this endpoint creates with no way to log in at
all — the bound `browser-passwordless` flow accepts only passkeys
(`services/account_unification/tests/test_realm_policy.py::test_bound_browser_flow_rejects_password_authenticator`),
and Direct Access Grants (the only mechanism that could use a password credential)
is off.

`POST /registration/accounts/password` (`app/password_registration.py`) now fails
closed with `503` behind the module constant `PASSWORD_CREDENTIAL_LOGIN_AVAILABLE
= False`, rather than create accounts nothing can authenticate into. The shared
runtime Keycloak client no longer allowlists or implements `reset-password`;
therefore the unavailable route cannot leave credential-reset authority dormant
in a reusable adapter. A future standards-compliant replacement must introduce
and review its own least-privilege owner contract rather than flip this gate.

## Context

[ADR-0014](0014-naruon-owned-password-form.md) enabled `directAccessGrantsEnabled`
for `naruon-web` so naruon's own login form could authenticate against
Keycloak's token endpoint without ever showing Keycloak-rendered HTML. That
ADR left a gap open deliberately: flipping the client flag does not, by
itself, let anyone log in, because **no account in the `cwl` realm has a
password credential** — `POST /registration/accounts`
(`app/registration.py`) explicitly creates accounts without one, and
`resetPasswordAllowed` stays `false`. naruon's login route was therefore
real but non-functional against the live realm. This ADR closes that gap:
naruon also needs "로그인 및 회원가입" (login *and* signup) working, per the
original product ask.

## What the naruon signup form needs

Naruon's own signup form must be able to create an account with a password
credential, server-side, with zero Keycloak-rendered HTML — the same
constraint ADR-0014 already established for login. The two realistic
mechanisms:

### Rejected as naruon's own integration: raw Keycloak Admin REST from naruon

naruon's backend could call Keycloak's Admin REST API
(`POST /admin/realms/cwl/users` + `PUT .../reset-password`) directly if it
held an admin/service-account credential. [ADR-0008](0008-keyverse-rp-authorization-boundary.md)
already settles this: "No downstream application receives Keycloak Admin
credentials to compensate for that gap." Handing naruon an admin-scoped
Keycloak client secret would let it create, modify, or delete *any* user or
realm object — a blast radius wildly out of proportion to "let a user sign
up with a password." Rejected outright, not reconsidered here.

### Accepted: extend account-unification, keyverse's existing narrow-scope admin proxy

`services/account_unification` already exists precisely to give product
backends narrow, purpose-built admin capabilities without an admin
credential: `POST /registration/accounts` proves the pattern for
passwordless signup, gated by its own dedicated bearer token
(`registration_api_token`, distinct from `operator_api_token`), calling
Keycloak Admin REST only through `ProductHttpAdminApi`'s allow-listed path
guard (`_ADMIN_PATH_PATTERNS`). Adding a sibling endpoint that does the
credential-bearing equivalent — create user, then set a password — reuses
every piece of existing infrastructure (bearer-token auth pattern, rate
limiter, email validation, rollback-on-failure, path allow-listing) instead
of building a second admin proxy from scratch. This is the smaller, more
reviewable diff, and it keeps every admin credential inside the one service
whose whole job is holding them.

A **separate standalone service** was considered and rejected: it would
duplicate account-unification's Keycloak client, config loading, and
auth-dependency plumbing for no isolation benefit — the new endpoint carries
no different trust level than the existing registration surface; it is
authorized by, and shares infrastructure with, the same admin proxy.

### Self-registration vs. invite-only

Self-registration (any caller with the token can submit any email) was
chosen over an invite-only flow (pre-provisioned invite tokens, admin
approval) for this first slice, matching `POST /registration/accounts`'s own
existing model — naruon already builds product accounts self-service, and
introducing an invite system here would be new product surface this ADR has
no mandate to design. The tradeoff is an open signup-abuse surface, which
this ADR does not fully close (see "Deferred").

## Decision

1. `POST /registration/accounts/password` (`app/password_registration.py`),
   authenticated by a **third**, independent bearer token
   (`password_registration_api_token`) — distinct from both
   `operator_api_token` and `registration_api_token`, checked with
   `hmac.compare_digest` the same way. Naruon's backend is the only holder of
   this token; no other RP is provisioned one, and nothing in this service
   authorizes any other RP to acquire this capability implicitly.
2. Request: `email_address`, `password` (12–128 chars), optional
   `first_name`/`last_name`. Response: `account_id`, `email_address` — never
   the password.
3. Implementation: `ProductAdminApi.reset_password(user_id, password)`
   (`app/product_keycloak_client.py`) calls Keycloak's
   `PUT /admin/realms/cwl/users/{id}/reset-password` with
   `{"type": "password", "value": password, "temporary": false}` —
   *non-temporary*, deliberately, so the account is usable immediately
   without a forced first-login password change (there is no
   password-change UI in this passwordless-first realm to force one into).
   The new admin path is added to the existing `_ADMIN_PATH_PATTERNS`
   allow-list, so a compromised/misconfigured caller still cannot reach any
   Keycloak Admin REST route this service does not already expose.
4. `deploy/keycloak/realm-cwl.json` gains `"passwordPolicy":
   "length(12) and notUsername and notEmail"` — realm-enforced, independent
   of the endpoint's own length/match validation, so a bug or a future
   caller of `reset_password` cannot silently skip the minimum. This policy
   is inert for every other flow (the browser flow has no password
   authenticator to apply it to).
5. Account creation, then credential-set, then rollback-on-failure — the
   same three-step shape as `POST /registration/accounts`'s
   create-then-`execute-actions-email`-then-rollback. A failure setting the
   password deletes the just-created account rather than leaving an
   unusable orphan.
6. A per-peer fixed-window rate limit (30 attempts / 5 minutes), duplicated
   from `registration.py` rather than extracted into a shared utility — the
   existing codebase already keeps this state module-local per registration
   surface, and extracting it would have forced touching that module's
   already-100%-covered, monkeypatch-coupled tests for no functional gain.

## Security tradeoffs made explicitly

- **Service-account credential scope.** `reset_password` reuses the same
  confidential `account-unification-svc` Keycloak service-account credential
  every other admin operation in this service already uses — no new,
  wider-scoped Keycloak client was created. The blast radius of a leaked
  `password_registration_api_token` is bounded to "create a `cwl` user with
  an attacker-chosen password" (and, transitively, whatever RBAC the
  `member` role already grants) — not "call any Admin REST endpoint," because
  `_ADMIN_PATH_PATTERNS` still gates every call this client can make.
- **Password policy enforcement is two-layered.** The endpoint rejects a
  too-short or email-matching password before any Keycloak call (fast,
  precise error messages); the realm `passwordPolicy` rejects it again
  server-side regardless of what the application layer does. Neither layer
  alone is trusted as sufficient.
- **Abuse/rate-limiting surface.** The per-peer fixed-window limiter bounds
  brute-force account creation from one source IP but does not stop a
  distributed attempt, does not verify the submitted email is reachable
  before creating the account, and has no CAPTCHA-equivalent challenge. This
  is a materially weaker abuse posture than `POST /registration/accounts`
  already has implicitly (that flow's account is unusable until the email
  link is clicked; this flow's account works immediately on creation).
  Explicitly accepted as this slice's tradeoff, not overlooked — see
  Deferred.
- **No password credential exists for accounts already created via
  `POST /registration/accounts`.** This endpoint's accounts and the
  passwordless-enrollment endpoint's accounts remain two disjoint
  populations; there is no path here for a passwordless user to add a
  password, nor for a password user to add a passkey. Unifying them is out
  of scope.

## Deferred (not shipped in this slice)

- **Email verification.** Accounts are created with `emailVerified: false`
  and no `VERIFY_EMAIL` required action, so an unverified, even
  non-existent, address can be signed up and immediately used. A follow-up
  should send a verification link post-signup and decide whether to
  require it before granting write access anywhere downstream.
- **CAPTCHA-equivalent / stronger abuse detection.** Only the existing
  per-peer fixed-window limiter applies. No device fingerprinting, no
  distributed rate limiting, no anomaly detection.
- **Self-service password reset or change.** `resetPasswordAllowed` stays
  `false`. A user who forgets a password issued this way has no recovery
  path yet.
- **Merging a password identity with an existing passwordless identity for
  the same person.** [ADR-0003](0003-identity-matching.md)'s
  verified-email-match precedence is not wired to this endpoint.

Each of the above is a real, separately-reviewable piece of work, not an
oversight; shipping all of it in this slice would have meant reversing or
extending several other accepted decisions (self-service password reset,
verified-email merge policy) without the review those decisions themselves
require.

## Consequences

- naruon's login (ADR-0014) and signup (this ADR) are now both real and
  connected end-to-end: an account created through
  `POST /registration/accounts/password` can immediately authenticate
  through `naruon-web`'s Direct Access Grants.
- Every other RP is unaffected: no new capability, client attribute, or
  Admin REST route is reachable by anyone who does not hold naruon's
  specific `password_registration_api_token`.
- The three account-unification bearer tokens (`operator_api_token`,
  `registration_api_token`, `password_registration_api_token`) must all
  remain pairwise distinct — enforced at config-load time
  (`app/config.py`), so a misconfiguration that reuses a token fails closed
  at startup rather than silently widening a caller's authority.

## References

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749),
§4.3 Resource Owner Password Credentials Grant.
https://doi.org/10.17487/RFC6749

Internet Engineering Task Force. (2025, January). *OAuth 2.0 security best
current practice* (RFC 9700, BCP 240), §2.4 Resource Owner Password
Credentials Grant — the finding behind this ADR's Correction, above.
https://www.rfc-editor.org/rfc/rfc9700.html

Internet Engineering Task Force. (2026, August). *OAuth 2.0 for browser-based
applications* (RFC 10017), §7.3 Resource Owner Password Credentials Grant.
https://www.rfc-editor.org/rfc/rfc10017.html

Keycloak. (n.d.). *Server administration guide* (Version 26.7.1), Password
policies; Admin REST API — reset a user's password.
https://www.keycloak.org/docs/latest/server_admin/
