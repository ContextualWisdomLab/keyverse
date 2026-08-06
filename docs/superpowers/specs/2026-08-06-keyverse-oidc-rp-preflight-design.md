# Keyverse OIDC RP preflight design

## Problem

The deployment template previously went directly to private Keycloak Admin
REST. It contained broad web-origin expansion, synthetic comment fields,
unresolved placeholders, and a scope shape that was not owned by a Keyverse
policy boundary. A deployment mistake could therefore create an unsafe or
non-portable client before operators received a stable product-level error.

## Decision

Add authenticated `POST /clients/relying-parties:validate` to the modular
account-unification service. The route accepts a closed Keycloak
`ClientRepresentation`, performs deterministic local validation, and returns an
alias-preserving readiness receipt. It performs no mutation or network access.

```text
private rendered RP payload
        |
        v
operator authentication + path boundary
        |
        v
manual non-reflective JSON shape parser
        |
        v
closed OIDC / URI / origin / scope policy
        |
        +----> bounded HTTP 400 or 422
        |
        v
ready_to_apply=true receipt
        |
        v
deployment-owned private Keycloak apply
```

## Invariants

1. Only authorization code plus PKCE `S256` is enabled.
2. Redirect, origin, and logout URLs are exact HTTPS values.
3. Web origins exactly cover redirect origins; logout belongs to that set.
4. Public and confidential client authentication fields are consistent.
5. No credential or arbitrary vendor field enters the payload.
6. Default scopes are exactly `basic`, `profile`, and `email`.
7. Unknown names and submitted values are not reflected in errors.
8. Validation has no KV, Keycloak, DNS, HTTP, secret, or filesystem side effect.
9. The same module works standalone and when embedded by CWL or Naruon.

## Non-goals

- automatic Keycloak client creation or update;
- client-secret generation or retrieval;
- native loopback or private-use redirect profiles;
- live TLS, DNS, domain-ownership, login, logout, or token validation;
- dynamic discovery or external metadata fetch;
- deployment-specific role or audience claim policy.

## Verification

The original TDD RED commit expected a readiness receipt but observed HTTP 404.
Production implementation follows that failing behavior test. Additional tests
exercise every production statement and branch, hostile JSON, URI ambiguity,
origin closure, public/confidential variants, template rendering, authentication,
and absence of Keycloak calls.
