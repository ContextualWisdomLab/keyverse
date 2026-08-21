# ADR-0013: Provide MCP-compatible OAuth client authorization through Keyverse

**Status:** Proposed
**Date:** 2026-08-21
**Issue:** ContextualWisdomLab/keyverse#114
**Depends on:** ADR-0008 and the current Keyverse authorization-plane hardening
**Figma file ID:** N/A — this is a protocol and trust-boundary change with no user-interface slice.

## Context

LineageWeave MCP clients need a supported passwordless path to a protected
resource. A long-lived MCP API key would create a second issuance, rotation,
deprovisioning, and audit system outside Keyverse. A client ID, repository
relationship, email address, or Keycloak mapper is not authorization evidence
by itself.

Keyverse already uses Keycloak as the ecosystem identity and protocol engine.
The account-unification service owns deterministic desired state and operator
boundaries; it is not a second token issuer. The existing relying-party profile
is intentionally secret-free, authorization-code based, and PKCE protected.

The MCP authorization specification requires protected-resource metadata,
authorization-server discovery, OAuth 2.1 security measures for clients, and a
canonical `resource` parameter. RFC 9700 requires exact redirect handling and
PKCE for public clients. RFC 8707 binds an authorization request to an
absolute resource URI. RFC 9728 makes the protected resource the owner of its
metadata. These protocol roles must remain separate from Keyverse's private
operator API and from LineageWeave's resource authorization policy.

## Decision

### 1. Keycloak remains the authorization server

Keyverse will not introduce a bespoke token issuer, password grant, static MCP
bearer key, or LLM-based authorization decision. Keycloak remains the issuer
and signing-key authority for the configured public issuer.

The deployment contract will provide one exact HTTPS issuer, for example:

```text
https://keyverse.example/realms/cwl
```

The issuer string is compared exactly, including its path and trailing-slash
policy. The implementation must publish and test both discovery forms needed
by MCP clients:

```text
{issuer}/.well-known/openid-configuration
https://{host}/.well-known/oauth-authorization-server/{issuer-path}
```

The second URL uses the RFC 8414 path-aware well-known construction. The
metadata documents must agree on the exact `issuer`, authorization endpoint,
token endpoint, JWKS URI, supported response type (`code`), and
`S256` code-challenge method. An endpoint that reports a different issuer or
an unapproved host is invalid. OIDC discovery remains the vendor-backed
source of truth; an RFC 8414 projection may be served by the public edge only
when it is byte-for-byte consistent on security-relevant fields.

The public discovery surface must not expose operator configuration, private
Keycloak Admin REST, secret references, tenant inventories, or user data.

### 2. The MCP resource owns protected-resource metadata

LineageWeave, as the protected MCP resource, owns:

```text
GET {resource-origin}/.well-known/oauth-protected-resource
```

and any path-aware equivalent required by RFC 9728. Its metadata must contain
the one canonical MCP `resource` URI and the exact Keyverse issuer in
`authorization_servers`. A protected `401` response must advertise the same
metadata URL through `WWW-Authenticate` when the client needs discovery.

Keyverse does not proxy or silently rewrite LineageWeave metadata. Keyverse's
integration tests verify that the resource metadata points to the configured
issuer, while LineageWeave tests verify that it accepts only the advertised
resource and authorization server.

### 3. Public clients use authorization code plus PKCE

The first MCP client profile is a public OAuth client using authorization code
and mandatory `S256` PKCE:

- no password, implicit, or direct-access grant;
- exact registered HTTPS redirect URI, with no wildcard or string expansion;
- `redirect_uri` is identical in the authorization and token requests;
- a fresh high-entropy `state` and PKCE verifier for every authorization;
- the authorization request and token request contain exactly one canonical
  `resource` URI;
- scopes are an allowlisted subset of the resource's registered least-
  privilege scopes;
- access tokens are accepted only after checking the configured issuer, subject,
  expiry, and required scopes; the JWT `aud` claim is the canonical MCP
  resource URI, while RFC 9068 `client_id` is checked separately against the
  registered public client ID. If `azp` is present, it is validated under the
  same client profile. A Keycloak audience-mapper client ID must never be
  reused as the MCP resource audience.

Keyverse reuses the existing closed secret-free relying-party lifecycle for
pre-registration. The MCP client representation is a separately named,
reviewed profile because resource-bound audience semantics are a new trust
boundary. It may not broaden the existing mapper allowlist by configuration
alone. No client secret is accepted, generated, returned, or persisted in this
profile.

There is no open dynamic-registration endpoint in this decision. A deployment
may pre-register an approved public client and exact redirect through the
Keyverse desired-state boundary. If a real MCP client cannot operate with
pre-registration and requires a Client ID Metadata Document or RFC 7591
registration, that mechanism requires a follow-up ADR with SSRF, metadata
freshness, redirect ownership, registration abuse, and audit controls before
implementation.

### 4. Resource indicators and least privilege are enforced together

Each MCP protected resource has one deployment-owned canonical absolute URI.
The URI has no fragment; its query policy is explicit; and its trailing-slash
spelling is stable. Keyverse rejects a missing, duplicated, differently
spelled, or unregistered `resource` parameter.

The token audience and resource authorization decision must bind to that exact
URI. A valid Keyverse login or client registration cannot authorize a token
for another LineageWeave instance. The resource owns the initial scope list;
Keyverse stores and enforces only the reviewed, least-privilege list. Wildcard,
unregistered, role-like, or administrative scopes are rejected.

The first implementation must record the exact resource-to-client-to-scope
binding and prove:

```text
resource URI  ->  one public client  ->  bounded scopes  ->  one RP verifier
```

No name-only `Partner`, `Supplier`, person, or organization attribution is
introduced by this protocol contract.

### 5. Revocation and audit remain centralized

Keycloak remains the authority for user disablement, session termination,
token revocation, signing-key rotation, and authentication audit events.
Keyverse records authorization intent and non-secret outcome/audit references;
it never records bearer tokens, authorization codes, PKCE verifiers, or client
secrets.

LineageWeave must prove revoked/deprovisioned access is denied. Local JWT
signature validation alone is insufficient for that acceptance claim while a
token remains unexpired. The implementation must use an approved active-token
or revocation check, or a separately accepted short-lived-token contract with
measured revocation bounds. This is a resource-server integration requirement,
not a reason to create a second user identity or API-key issuer.

### 6. Device authorization is explicitly deferred

RFC 8628 is not implemented speculatively. It may be evaluated only when a
real MCP client has no usable browser callback and supplies a concrete device
flow requirement, abuse model, polling/backoff limits, user-code lifecycle,
and revocation tests. Until then, browser-assisted authorization code plus
PKCE is the only supported client path.

## Required negative evidence

The implementation PR must test and retain evidence for denial of:

| Input | Required result |
|---|---|
| wrong issuer or discovery host | deny before resource authorization |
| wrong or missing audience/resource | deny |
| unregistered redirect or redirect mismatch | deny |
| missing, duplicated, or unregistered scope | deny |
| missing/invalid PKCE or state | deny |
| expired, revoked, disabled-user, or malformed token | deny |
| token for another tenant/workspace/resource | deny |
| password/direct-access/device flow before its own ADR | deny |
| static MCP API key | unsupported and deny |

## Consequences

Positive consequences:

- MCP clients use the existing passwordless Keyverse identity authority;
- LineageWeave remains a protected resource with its own ABAC/RBAC boundary;
- resource indicators prevent a token issued for one MCP resource being reused
  at another resource;
- operator credentials, user tokens, and deployment secrets remain separate;
- discovery, revocation, and audit have one explicit ownership model.

Costs and limitations:

- a public issuer and WAF routing contract must be deployed and tested;
- resource-bound audience support requires a distinct Keyverse MCP profile and
  downstream verifier changes;
- pre-registration is an operational dependency until a separately reviewed
  registration mechanism is justified;
- revocation evidence may require protected-resource introspection or a
  measured bounded-lifetime contract;
- this ADR does not claim a live Keycloak, browser, or LineageWeave acceptance
  result.

## Implementation and evidence gates

Before implementation, update the issue-linked specification and doctoring
record. The implementation PR must reconcile PRD, TRD, Architecture, UML, ERD,
Threat Model, Test Strategy, Operability, Traceability, onboarding, and
`CHANGELOG.md` only when the runtime contract actually changes. It must use
real browser/client integration evidence, a non-secret test resource, exact
current-head coverage/docstring gates, and protected review/checks.

No version, release, Figma artifact, Storybook artifact, dependency, realm
secret, or dynamic-registration endpoint is created by this design record.
