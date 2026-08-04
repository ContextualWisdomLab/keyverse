# OIDC Federation Preflight Design

## Problem

Keyverse now rejects unsafe SAML federation desired state before persistence,
but `oidc` and `keycloak-oidc` registrations still receive only the generic
alias, size, and unresolved-template checks. An operator can therefore persist
an unpinned issuer, cleartext network endpoints, disabled token-signature
validation, disabled JWKS retrieval, an OAuth-only scope set without `openid`,
or an authorization-code flow without PKCE. Keycloak reports some of those
problems only during a user login, after the configuration has become active.

For an enterprise identity control plane, an invalid upstream OpenID Provider
must fail before desired-state storage and before a Keycloak Admin REST call.
The validation must remain deterministic and side-effect free: it must not turn
the operator preflight endpoint into a discovery-fetch or SSRF surface.

## Scope

This slice extends the existing provider-neutral endpoint:

`POST /federation/identity-providers:validate`

The same validation is applied by the existing `PUT` route before persistence.
It covers both Keycloak provider IDs used for generic OpenID Connect brokering:
`oidc` and `keycloak-oidc`.

In scope:

- explicit, pinned OpenID Provider metadata supplied as desired state;
- HTTPS-only issuer and protocol endpoints;
- exact issuer-shape validation;
- signature verification through an explicit JWKS URL;
- mandatory PKCE using `S256`;
- confidential-client authentication using a bounded client ID and secret;
- RFC 6749 scope-token validation with exactly one `openid` scope;
- redacted operator output;
- a deployment template and operator guidance;
- complete statement, branch, and docstring coverage.

Out of scope:

- fetching `/.well-known/openid-configuration`;
- DNS resolution, endpoint probing, redirect traversal, or TLS certificate
  inspection inside the preflight service;
- dynamic client registration;
- `private_key_jwt`, mutual TLS, or other asymmetric broker-client
  authentication methods;
- OIDC claim-mapper authoring;
- automatic trust of upstream email assertions;
- an administrative web UI.

## Security Contract

### Side-effect boundary

Preflight performs no KV write, Keycloak request, DNS lookup, discovery fetch,
or redirect traversal. Operators or deployment controllers may render explicit
configuration from discovery metadata outside Keyverse, but the values admitted
into desired state are fixed and reviewable.

Remote discovery import keys such as `fromUrl` and `discoveryEndpoint` are
rejected. This prevents an operator payload from delegating configuration
selection or network retrieval to a later execution phase.

### Required OIDC configuration

For `provider_id` equal to `oidc` or `keycloak-oidc`, the following fields are
required:

- `issuer`
- `authorizationUrl`
- `tokenUrl`
- `jwksUrl`
- `clientId`
- `clientSecret`
- `clientAuthMethod`
- `validateSignature`
- `useJwksUrl`
- `pkceEnabled`
- `pkceMethod`
- `defaultScope`

`userInfoUrl` and `logoutUrl` remain optional. When present, they receive the
same network-location validation.

### URL and issuer rules

`issuer` must be a bounded absolute HTTPS URL with no query or fragment. Paths
and non-default ports remain valid because OpenID Providers can be hosted below
a path or on a deployment-specific TLS port.

Authorization, token, JWKS, optional UserInfo, and optional logout endpoints
must be bounded absolute HTTPS URLs without fragments. Query components remain
allowed because standards-valid endpoint metadata can include a fixed query.
Credentials, backslashes, whitespace, raw C0 controls, DEL, percent-encoded
controls, malformed authorities, and invalid ports remain rejected by the
shared URI validator.

The service does not dereference an endpoint. Deployments must separately limit
Keycloak egress to approved HTTPS hosts and reject redirect downgrade.

### Cryptographic and flow rules

- `validateSignature` must be the strict boolean string `true`.
- `useJwksUrl` must be the strict boolean string `true`.
- `pkceEnabled` must be the strict boolean string `true`.
- `pkceMethod` must be exactly `S256`.
- `clientAuthMethod` may be `client_secret_basic` or `client_secret_post`.
- `clientId` and `clientSecret` must be non-empty, bounded strings without
  surrounding whitespace or control characters.

The first slice deliberately does not accept asymmetric client authentication.
Adding `private_key_jwt` requires a separate key-ownership, rotation, algorithm,
and audit contract rather than treating it as another string enum.

### Scope rules

`defaultScope` is parsed according to the RFC 6749 ASCII `scope-token` grammar.
Tokens are separated by one ASCII space. Empty tokens, duplicate tokens,
non-ASCII values, quotes, backslashes, controls, and malformed separators are
rejected. The case-sensitive token `openid` must occur exactly once, preventing
an OAuth-only upstream from being configured as an OpenID Connect provider.

### Redaction

`clientSecret` and every unknown configuration value remain `<redacted>` in
preflight, list, get, and update responses. The following non-secret operational
values become explicitly visible for diagnosis:

- `clientId`
- `clientAuthMethod`
- `jwksUrl`
- `pkceEnabled`
- `pkceMethod`

The existing safe endpoint, issuer, scope, and validation flags remain visible.

## Architecture and Data Flow

The implementation stays in `app/federation.py` beside the SAML policy and the
shared provider-registration boundary.

1. FastAPI authenticates the operator bearer token.
2. Pydantic validates the closed `IdentityProviderRegistration` shape.
3. Generic alias, size, and unresolved-template checks run.
4. `_validate_oidc_registration` enforces the OIDC contract for either OIDC
   provider ID.
5. Preflight returns `IdentityProviderValidationResult` with a redacted view.
6. `PUT` executes the same validation before taking the convergence lock or
   writing desired state.

Small pure helpers validate required text, the issuer, scopes, choices, and
HTTPS endpoints. They do not depend on storage or the Keycloak client, keeping
the standalone service and an embedded CWL/Naruon module behavior identical.

## Error Handling

Invalid configuration returns HTTP 400 with one bounded field-oriented message.
Errors name the field and requirement but never echo the supplied value. A
failure performs no persistence and no Keycloak call.

Temporary Keycloak unavailability remains an apply-time concern. Valid desired
state can still be stored with `applied_to_keycloak=false` and retried through
the existing convergence endpoint.

## Testing

The test-first sequence proves:

- unsafe OIDC input is accepted before the implementation, establishing RED;
- valid `oidc` and `keycloak-oidc` registrations return a redacted 200 result;
- preflight performs no storage or Keycloak operation;
- every required field is enforced;
- direct HTTP and malformed HTTPS endpoints fail closed;
- issuer query and fragment components fail closed;
- remote discovery-import keys fail closed;
- false and malformed security booleans fail closed;
- `plain` or missing PKCE fails closed;
- unsupported client authentication fails closed;
- malformed, duplicate, non-ASCII, and OAuth-only scope sets fail closed;
- optional UserInfo and logout endpoints may be absent, but are validated when
  present;
- `PUT` rejects invalid OIDC desired state before mutation;
- the committed template renders into a valid registration while retaining
  `trust_email=false` by default;
- existing SAML, registration, SCIM, merge, storage, and lifecycle tests remain
  green;
- production statement, branch, and docstring coverage remain 100%.

## Compatibility and Release

The HTTP API is additive only in validation strictness. Existing valid SAML
registrations are unchanged. Existing unsafe OIDC registrations may fail during
startup parsing or reconciliation after upgrade; this is intentional fail-closed
behavior and is documented as a migration requirement.

This feature is recorded under `[Unreleased]`. It does not independently justify
a `0.2.0` release because issue #2 still includes LDAP federation, complete
cross-IdP account-linking policy, live end-to-end evidence, and release-artifact
provenance.

## Authoritative References

- Hardt, D. (2012). *The OAuth 2.0 authorization framework* (RFC 6749).
  Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc6749
- Jones, M., Sakimura, N., & Bradley, J. (2015). *OAuth 2.0 authorization server
  metadata* concepts later standardized in RFC 8414; endpoint and issuer
  metadata are applied here through the OpenID Connect profile.
- Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
  practice for OAuth 2.0 security* (RFC 9700, BCP 240). Internet Engineering
  Task Force. https://www.rfc-editor.org/rfc/rfc9700
- OpenID Foundation. (2023). *OpenID Connect Discovery 1.0 incorporating errata
  set 2*. https://openid.net/specs/openid-connect-discovery-1_0.html
- Sakimura, N., Bradley, J., & Agarwal, N. (2015). *Proof key for code exchange
  by OAuth public clients* (RFC 7636). Internet Engineering Task Force.
  https://www.rfc-editor.org/rfc/rfc7636
- Keycloak. (2026). *Server Administration Guide: OpenID Connect identity
  providers*. https://www.keycloak.org/docs/latest/server_admin/
