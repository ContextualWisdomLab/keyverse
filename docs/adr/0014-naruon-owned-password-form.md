# ADR-0014: Scoped Direct Access Grants exception so naruon can render its own login form

**Status:** Accepted, mechanism superseded pending RFC-compliant redesign — see **Correction (2026-09-03)** below before implementing anything against this ADR.
**Date:** 2026-09-02
**Decision owner:** Keyverse maintainers, with explicit product direction from
the naruon product owner (see Context).
**Scope:** `naruon-web` only. Does not change `browserFlow`, does not create
any password credential, and does not change the account-unification
dynamic-RP-registration policy that still hard-rejects
`directAccessGrantsEnabled: true` for every other/future RP
(`services/account_unification/app/relying_party.py`, `must be false`).

## Correction (2026-09-03)

**A newer standards finding invalidates this ADR's grant-type choice. The underlying product goal —
naruon renders 100% of its own login/signup UI with zero Keycloak-rendered HTML in the loop, Keyverse
stays the canonical identity backend — is NOT superseded and should not be abandoned.**

RFC 9700 (*OAuth 2.0 Security Best Current Practice*, BCP 240, January 2025), §2.4, states that clients
and authorization servers **MUST NOT** use the Resource Owner Password Credentials grant. RFC 10017
(*OAuth 2.0 for Browser-Based Applications*, BCP, August 2026), §7.3, independently repeats that
prohibition specifically for browser-based OAuth/OIDC applications and requires a redirect-based flow
such as Authorization Code (+ PKCE) instead. Both post-date RFC 6749 (cited in this ADR's own References
below), which merely *defined* the ROPC grant in 2012 without reflecting the subsequent decade of
threat-model findings that led to its later deprecation.

This ADR's Decision section (point 1, below) treated the product owner's explicit sign-off as satisfying
[ADR-0002](0002-passwordless-local-accounts.md)'s "explicit security/product review and migration
evidence" amendment clause. **That is no longer sufficient**: a product-owner risk acceptance can
document an organizational deviation from this org's own passwordless-first preference, but it cannot
make `grant_type=password` standards-compliant for a browser-based application — RFC 9700/10017 are
current IETF security guidance, not one team's stylistic preference, and no local risk-acceptance memo
overrides a MUST-NOT.

Discovered when `naruon#1532` (the companion PR implementing point 4 of the Decision below) was returned
to Draft over this exact finding rather than merged or landed as-is — see that PR and this PR's own
comment thread (2026-09-03T02:59:17Z) for the original citation. Primary references:
[RFC 9700 §2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4),
[RFC 10017 §7.3](https://www.rfc-editor.org/rfc/rfc10017.html#section-7.3).

**What remains valid, unchanged:** every section below this one — the Context, what was ruled out and
why (Keycloak-theme reskin fails by construction; a naruon-rendered WebAuthn ceremony against Keycloak
is currently unachievable without a custom Keycloak REST resource provider) — is still accurate. Read
the rest of this ADR as the record of *why the product requirement exists and what does not solve it*,
not as license to ship the specific mechanism in point 1 of the Decision below.

**What needs repair before `naruon-web`'s `directAccessGrantsEnabled: true`
(`deploy/keycloak/realm-cwl.json`) and the companion naruon-side password route
(`frontend/src/app/auth/password/login/route.ts`) may ship:** the ROPC mechanism must be replaced with a
standards-compliant headless authentication contract. Candidates worth investigating, not yet decided:
(a) an Authorization Code + PKCE flow run inside an in-app browser view (popup/webview) rather than a
full top-level redirect — may satisfy "naruon renders the surrounding chrome" without a full-page
Keycloak-rendered navigation, needs verification against the "zero Keycloak-rendered HTML" requirement
before assuming it qualifies; (b) a custom Keycloak REST resource provider exposing a headless, versioned
session/challenge API for password and/or passkey/WebAuthn authentication — this ADR's own Consequences
section already anticipated a custom Keycloak SPI/REST provider as the eventual path for a full WebAuthn
ceremony, so this investment may resolve both gaps (password AND passkey) at once.

**Config change, 2026-09-03:** `naruon-web`'s `directAccessGrantsEnabled` in
`deploy/keycloak/realm-cwl.json` has been set to `false` as a fail-closed measure — the
mechanism this ADR's Decision (point 1, below) turned on must not ship per the RFC 9700/10017
finding above, and this PR was not yet merged/deployed, so nothing live depended on it staying
`true`. Decision point 1 is left unedited below as the historical record of what was originally
decided; it no longer describes the current config value. Re-enable only alongside a
standards-compliant replacement mechanism (see the candidates above), tracked in the new ADR
called for below.

**Status intentionally left as Accepted, not Rejected/Superseded**, because the product goal stands and
the Context/ruled-out-alternatives sections remain load-bearing evidence — only the grant-type mechanism
in the Decision needs a successor. Per this org's repair-not-close convention for findings against an
already-Accepted decision with real, still-valid product intent behind it: open a new ADR once a
replacement mechanism is chosen and cross-reference it here, rather than silently rewriting this one's
history or treating this correction as grounds to abandon the underlying naruon-owned-login-form goal.

## Context

Product direction for naruon's login/signup surface was clarified twice.
First: only the *page/form* should be naruon's own; Keyverse remains the
identity backend. On review of a Keycloak-theme-reskin implementation, the
product owner rejected it outright: *"아니 그리고 누가 Naruon을 Theme
붙이겠대"* ("who ever said [they wanted] a Theme attached to naruon") — a
reskinned Keycloak theme is still Keycloak's own server rendering the
response, which is exactly what was not wanted, disguised or not. The
re-confirmed requirement: naruon's own frontend renders 100% of the
login/signup UI with zero Keycloak-rendered HTML anywhere in the loop, and
naruon's own backend talks to Keyverse purely as an API backend.

### What was ruled out, and why

**A Keycloak-hosted page, reskinned or not**, fails the requirement by
construction — it is Keycloak's server producing the HTML the user's browser
receives, regardless of how closely its CSS matches naruon's design. This is
true whether the browser is redirected to it, shown it in a popup, or shown
it in an iframe.

**A naruon-rendered WebAuthn ceremony against Keycloak as a headless API**
was investigated and is not achievable with Keycloak's current architecture
— not because Keyverse has not built it yet, but because of how Keycloak
implements WebAuthn. The authentication ceremony (as opposed to registration)
runs inside Keycloak's own `login-actions` flow, bound to a server-side
`AuthenticationSessionModel` that generates the challenge and later verifies
the posted assertion; Keycloak does not publish a REST pair ("give me a
challenge" / "here is my assertion") for the login ceremony outside that
flow. Even Keyverse's own passwordless *registration* path
(`docs/passwordless-policy.md`) ends the same way: after
`POST /registration/accounts`, Keycloak's `execute-actions-email` sends a
link that lands the user on a Keycloak-hosted required-action page to run
`webauthn-register-passwordless`, before redirecting back to naruon's
`passkey-complete` page. Only the redirect *target* is naruon's; the
ceremony page itself is Keycloak's. A fully naruon-rendered WebAuthn
ceremony would require Keycloak to expose that as a public API, which it
does not, or a custom Keycloak REST resource provider reimplementing the
ceremony's session/challenge handling — real, separately-scoped engineering,
not something achievable by naruon or by config alone.

**Direct Access Grants (OAuth2 Resource Owner Password Credentials)** against
`/protocol/openid-connect/token` is the one mechanism Keycloak exposes as a
plain, stateless, public REST endpoint that fits "naruon's own form, naruon's
own backend, zero Keycloak HTML." It is also, deliberately, the option this
organization has worked hardest to avoid: [ADR-0002](0002-passwordless-local-accounts.md)
keeps ecosystem-local accounts passwordless-first and requires "explicit
security/product review and migration evidence" to change that boundary;
`services/account_unification/app/relying_party.py` hard-rejects
`directAccessGrantsEnabled: true` for any RP that registers dynamically; and
`docs/CWL-MASTER-CONTEXT.md` states the ecosystem-wide direction as
"eliminate passwords." The product owner acknowledged this tension directly
when re-confirming the requirement, and accepted it explicitly for this one
integration: naruon's process may transiently hold a plaintext password in
memory for the single request that forwards it to Keycloak's token endpoint,
provided it is never logged, cached, or persisted.

## Decision

1. `naruon-web`'s `directAccessGrantsEnabled` is `true` in
   `deploy/keycloak/realm-cwl.json`. This is *this* ADR's "explicit
   security/product review" satisfying ADR-0002's own amendment clause — it
   is a scoped, named exception, not a reversal of ADR-0002's default.
2. No other change is made to `browserFlow`, `browser-passwordless-forms`,
   or `browser-passwordless-credentials`; `scripts/validate_realm.py` still
   passes unmodified, because none of its checks concern the direct-grant
   path.
3. The account-unification service's dynamic RP registration validator is
   **not** changed. It continues to hard-reject
   `directAccessGrantsEnabled: true` for every RP that registers through
   `POST /relying-parties` — `naruon-web` is a hand-authored client in the
   portable realm, not a dynamically-registered one, and this ADR does not
   extend the exception to any other or future RP.
4. Companion naruon-repo work (tracked there, not here) adds naruon's own
   email/password form and a backend route
   (`frontend/src/app/auth/password/login/route.ts`) that POSTs
   `grant_type=password` to Keycloak's token endpoint server-side, using the
   same SSRF-hardened token-endpoint client already used for the
   authorization-code exchange. The password exists only in that one
   request's memory; it is never logged (failures are recorded by a fixed
   reason string, never with the credential) and never written to a cookie,
   session, or datastore naruon controls.

## What this does *not* yet deliver

**Update (2026-09-02):** the credential-issuance gap this section describes
is now closed by [ADR-0015](0015-naruon-password-credential-issuance.md)
(`POST /registration/accounts/password`, gated by its own third bearer
token). The rest of this section is kept as written for the historical
record of what ADR-0014 alone did and did not deliver.

Flipping `directAccessGrantsEnabled` does not, by itself, let any real user
sign in. **No account in the `cwl` realm has a password credential today.**
`POST /registration/accounts` explicitly refuses to accept or create one
(`docs/passwordless-policy.md`: "It does not accept or create a password"),
and `resetPasswordAllowed` stays `false`. Every Direct Access Grants attempt
against the current realm fails closed with `invalid_grant` — correctly and
safely, since there is nothing to authenticate against — regardless of
whether naruon's client code is exactly right.

Making the flow function end-to-end needs one more, separately-reviewable
keyverse change: some way for a user to obtain a password credential — a new
registration path that also sets a password, an admin-driven credential
reset, or a self-service "add a password" action on an already-passwordless
account. That change is a materially bigger, more security-relevant
decision than this one (it decides whether Keyverse issues passwords to
local accounts at all, which is the exact boundary ADR-0002 protects) and is
explicitly **out of scope for this slice**. It is recorded here as the
tracked blocker for the next iteration, not implemented.

## Consequences

- naruon's login form and backend route are real and correctly built against
  the standard OAuth2 ROPC contract; they will start authenticating real
  users the moment a keyverse-side credential-issuance path exists, with no
  further naruon-side change required.
- Until that path exists, naruon's password login always returns a generic
  "invalid credentials" error — indistinguishable, by design, from an
  actually-wrong password (the token endpoint's non-2xx responses are
  collapsed into one message to avoid a user-enumeration or
  configuration-probing oracle).
- `naruon-web` now accepts two authentication paths with different trust
  models: Direct Access Grants for naruon-native local accounts (this ADR),
  and the existing `browser-passwordless`/authorization-code redirect for
  federated identity (employer ADFS, external IdPs) — federation cannot use
  ROPC, since a brokered identity has no local password to submit. Both
  remain available in naruon's UI, serving different account types.
- If a future genuine "naruon renders 100% of a WebAuthn ceremony" capability
  is built, it would most likely require a custom Keycloak REST resource
  provider (a real SPI/Java development effort, plus the image-build and
  provider-pinning process that implies) — a candidate for later work, not
  assumed available today.

## References

Hodges, J., Jones, J. C., Jones, M. B., Kumar, A., & Lundberg, E. (Eds.).
(2021, April 8). *Web Authentication: An API for accessing Public Key
Credentials Level 2* (W3C Recommendation), §7 WebAuthn Relying Party
Operations — the registration and authentication ceremonies Keycloak
implements as server-orchestrated flows, not as a public headless API.
https://www.w3.org/TR/2021/REC-webauthn-2-20210408/

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749),
§4.3 Resource Owner Password Credentials Grant.
https://doi.org/10.17487/RFC6749

Keycloak. (n.d.). *Server administration guide* (Version 26.7.1), Direct
Access Grants. https://www.keycloak.org/docs/latest/server_admin/
