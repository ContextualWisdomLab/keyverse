# naruon password-login ROPC standards correction

**Date:** 2026-09-03
**Status:** Implementation evidence for the active PR (`keyverse#128`); not
protected-main or live Keycloak acceptance

## Scope

This record documents disabling `naruon-web`'s Direct Access Grants
(ADR-0014) and the `POST /registration/accounts/password` signup endpoint
that depended on it (ADR-0015), and the cascading fix once disabling the
grant alone left password-only signups unable to authenticate. It adds no
new authentication mechanism -- the underlying "naruon renders its own
login/signup UI, Keyverse stays the identity backend" product requirement is
unchanged and remains a real, open successor-design question (Authorization
Code + PKCE in an in-app browser view, or a custom Keycloak REST resource
provider for headless passkey/WebAuthn), tracked against ADR-0014, not
resolved here.

## Interpretation

- **Standards requirement:** RFC 9700 §2.4 states clients and authorization
  servers MUST NOT use the OAuth 2.0 Resource Owner Password Credentials
  (ROPC) grant. RFC 10017 §7.3 independently repeats that prohibition for
  browser-based OAuth/OIDC applications specifically and requires a
  redirect-based flow such as Authorization Code + PKCE instead. Both
  post-date RFC 6749 (which merely defined the ROPC grant in 2012, before the
  subsequent decade of threat-model findings that led to its deprecation).
- **Why the earlier acceptance didn't settle it:** ADR-0014's original
  Decision treated the naruon product owner's explicit risk acceptance as
  satisfying ADR-0002's "explicit security/product review" amendment clause.
  A documented risk acceptance can record an organizational deviation from a
  stylistic or architectural preference; it cannot make a MUST-NOT-prohibited
  grant type standards-compliant. `keyverse#128` was still a mutable,
  unreleased contract when this was found -- nothing live depended on the
  grant staying enabled -- so the correct move was to repair the boundary
  before release rather than accept the debt permanently by merging it.
- **The cascading bug this record's fix addresses:** disabling
  `directAccessGrantsEnabled` alone (first pass) is standards-correct but
  incomplete on its own -- `POST /registration/accounts/password` still
  created accounts with `required_actions=[]`, which was only safe when an
  immediately usable password credential could actually authenticate via
  ROPC. With the grant off, those accounts had no path in: not ROPC (blocked),
  not the bound `browser-passwordless` flow (accepts only passkeys,
  `services/account_unification/tests/test_realm_policy.py::test_bound_browser_flow_rejects_password_authenticator`).
  A standards-compliance fix is not complete until every artifact that
  depended on the disabled mechanism being live is re-examined, not only the
  artifact the original finding named.
- **Policy choice:** fail closed. The endpoint now returns `503` before any
  Keycloak work, rather than create an account nothing can authenticate into.
  `scripts/validate_realm.py` independently rejects a silent future
  re-enable of the realm flag, so the two artifacts (code gate, realm config)
  cannot drift back out of sync with each other or with the ADR's own status.
- **Implementation behavior:** both gates are single, deliberately flippable
  points (`PASSWORD_CREDENTIAL_LOGIN_AVAILABLE` in
  `services/account_unification/app/password_registration.py`,
  `directAccessGrantsEnabled` in `deploy/keycloak/realm-cwl.json`) rather than
  a rewrite of the account-creation, rollback, or rate-limiting logic
  underneath, which stays intact and fully tested via monkeypatch for when a
  replacement mechanism ships.

## Evidence

- **RED (conceptual, pre-fix state):** `directAccessGrantsEnabled: true` in
  the committed realm export, `docs/adr/README.md`'s index showing ADR-0014
  as a bare "Accepted", and `POST /registration/accounts/password` creating
  `required_actions=[]` accounts -- all present simultaneously, together
  describing a live ROPC grant plus a signup path that assumed it worked.
- **GREEN, pass 1 (`79fe43d`):** `directAccessGrantsEnabled` set to `false`;
  ADR-0014's index row and `deploy/keycloak/README.md` updated to match the
  ADR's own status line.
- **GREEN, pass 2 (`44f0cb9`):** `PASSWORD_CREDENTIAL_LOGIN_AVAILABLE = False`
  added, gating `register_account_with_password` before any account-creation
  work; `test_registration_fails_closed_by_default` added
  (`services/account_unification/tests/test_password_registration.py`)
  covering the new default branch, with the existing happy-path/rollback/
  rate-limit tests preserved by monkeypatching the constant `True`;
  `scripts/validate_realm.py` gained a `directAccessGrantsEnabled` check for
  `naruon-web`, covered by
  `test_naruon_direct_access_grants_stays_disabled`
  (`services/account_unification/tests/test_realm_policy.py`); ADR-0015
  gained a Correction section mirroring ADR-0014's.
- **Measured boundary:** `coverage run --branch --source=app -m pytest -q`
  followed by `coverage report --show-missing --fail-under=100` reported 100%
  statement and branch coverage (2,873 statements, 772 branches); `interrogate`
  reported 100% docstring coverage; `ruff check app tests tools` passed
  clean; `python scripts/validate_realm.py deploy/keycloak/realm-cwl.json`,
  `make test`, `make validate-realm`, and
  `tests/test_documentation_contract.py` all passed.
- **Not claimed:** this is not a standards-compliant replacement login
  mechanism -- naruon's password-signup surface stays unavailable (`503`)
  until one ships. Whether an Authorization Code + PKCE in-app-browser-view
  flow or a custom Keycloak REST resource provider for headless
  passkey/WebAuthn is buildable against Keycloak's `login-actions`-bound
  ceremony (which has no public REST pair for the login ceremony specifically,
  per ADR-0014's own Context section) is a real, separately-scoped design
  question this record does not resolve.

## References

Hardt, D. (Ed.). (2012). *The OAuth 2.0 authorization framework* (RFC 6749),
§4.3 Resource Owner Password Credentials Grant. Internet Engineering Task
Force. https://doi.org/10.17487/RFC6749

Internet Engineering Task Force. (2025, January). *OAuth 2.0 security best
current practice* (RFC 9700, BCP 240), §2.4 Resource Owner Password
Credentials Grant. https://www.rfc-editor.org/rfc/rfc9700.html

Internet Engineering Task Force. (2026, August). *OAuth 2.0 for browser-based
applications* (RFC 10017), §7.3 Resource Owner Password Credentials Grant.
https://www.rfc-editor.org/rfc/rfc10017.html

Individual author attribution for both RFCs is intentionally omitted above:
this record cannot independently verify the exact editor list for either
document (RFC 10017 in particular predates no available training/knowledge
cutoff verification), so both are cited by issuing organization rather than
risk misattributing named individuals. Confirm the editor list directly from
the RFC Editor page before citing either document with named authors
elsewhere.
