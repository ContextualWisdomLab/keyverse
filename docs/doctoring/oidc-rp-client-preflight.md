# OIDC relying-party client preflight — doctoring record

## Scope

This record documents Keyverse's authenticated, side-effect-free validation of
a rendered Keycloak OpenID Connect client representation. It covers a closed
first profile for exact HTTPS web redirects, authorization code plus PKCE,
public/confidential client consistency, bounded token policy, portable scopes,
and non-reflective error handling.

It does not claim formal OAuth, OpenID Connect, Keycloak, FAPI, or native-app
conformance. It does not create a client, contact Keycloak, validate DNS or TLS,
perform an authorization flow, prove domain ownership, or establish that an RP
protects its own session and tokens correctly.

## Evidence categories

- **Standards requirements**: redirect matching, PKCE, public-client treatment,
  and client registration metadata.
- **Vendor behavior**: Keycloak client representation fields, exact redirect
  matching, web-origin configuration, and supported client authentication.
- **Product policy**: stricter HTTPS-only URLs, no wildcards, exact origin
  closure, exact portable scopes, bounded token lifetime, and no credential
  fields in the submitted representation.
- **Measured evidence**: exact-head tests, production statement/branch coverage,
  docstring gate, package build, template validation, and security workflows.
- **Residual assumptions**: deployment-controlled private Keycloak access and a
  separately verified post-apply login test.

## Redirect and origin policy

RFC 9700 requires exact string matching of registered redirects except the
narrow native localhost port exception. OpenID Connect Dynamic Client
Registration also requires a registered redirect to exactly match the
authorization request. Keycloak permits wildcard patterns but warns against a
full wildcard in production. Keyverse therefore implements a deliberately
stricter first profile:

- HTTPS only;
- no wildcard or `+` expansion;
- no userinfo, query, fragment, backslash, control character, ambiguous
  whitespace, invalid percent escape, encoded control, encoded separator, or
  dot path segment;
- canonical ASCII/punycode DNS names or valid IP literals;
- explicit non-default TLS ports and canonical IPv6 accepted;
- CORS origins equal the set of redirect origins;
- logout uses a registered origin.

The first profile does not accept native private-use schemes or loopback HTTP.
RFC 8252 remains the design source for a future separately reviewed native
profile; the current rejection is product scope, not a claim that those standard
patterns are insecure.

## Flow and client authentication policy

Authorization code is the only enabled browser grant. Implicit and direct
resource-owner-password-style access are disabled. PKCE `S256` is mandatory for
public and confidential clients. RFC 7636 defines PKCE as mitigation for
authorization-code interception; RFC 9700 extends PKCE guidance to all OAuth
clients when practical.

Public clients use `clientAuthenticatorType=none`; confidential web clients use
`client-secret`. The submitted representation cannot include a client secret,
registration access token, or arbitrary Keycloak field. Secret generation and
storage happen only after private apply.

## Scope and claim policy

The accepted portable default scope set is exactly `basic`, `profile`, and
`email`. Deployment-specific roles, audience, organization, or workspace claims
remain server-owned mapper policy. Keeping those concerns separate prevents an
RP registration from silently widening authorization semantics.

## Non-reflective errors and side effects

Untrusted JSON is manually shape-checked before Pydantic model construction.
Unknown field names and values are never copied into error messages. Validation
uses only deterministic local parsing. The endpoint has no reference to the KV
store, Keycloak API, DNS, HTTP client, secret generator, or filesystem.

## Verification contract

Merge requires all of the following on the exact current head:

- authenticated success for realistic confidential and public clients;
- no Keycloak calls for successful or rejected requests;
- hostile JSON shape and secret-reflection regression tests;
- flow, authentication, URI, origin, attribute, scope, IPv6, and port tests;
- committed template render-and-preflight test;
- Ruff and Python compilation;
- production docstrings 100%;
- production statement coverage 100%;
- production branch coverage 100%;
- full pytest and package build;
- realm, Compose, and JSON validation;
- CodeQL, Semgrep, Security Scan, current-head review, and zero unresolved
  actionable threads.

## References — APA 7th

Denniss, W., & Bradley, J. (2017). *OAuth 2.0 for native apps* (BCP 212,
RFC 8252). Internet Engineering Task Force. https://doi.org/10.17487/RFC8252

Keycloak. (n.d.). *Server Administration Guide*. Retrieved August 6, 2026,
from https://www.keycloak.org/docs/latest/server_admin/

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (BCP 240, RFC 9700). Internet Engineering Task
Force. https://doi.org/10.17487/RFC9700

Sakimura, N., Bradley, J., & Agarwal, N. (2015). *Proof key for code exchange
by OAuth public clients* (RFC 7636). Internet Engineering Task Force.
https://doi.org/10.17487/RFC7636

Sakimura, N., Bradley, J., & Jones, M. (2023). *OpenID Connect Dynamic Client
Registration 1.0 incorporating errata set 2*. OpenID Foundation.
https://www.openid.net/specs/openid-connect-registration-1_0-39.html
