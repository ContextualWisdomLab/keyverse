# MCP-compatible OAuth client authorization — doctoring record

## Scope and current evidence

This record interprets the current MCP authorization contract for Keyverse,
Keycloak, and a LineageWeave protected MCP resource. It is a design record for
issue #114, not proof that the runtime feature is deployed.

Observed on the protected-main base used for this record:

- Keycloak is the existing OIDC/OAuth protocol engine and signing authority.
- Keyverse already has a closed, secret-free authorization-code plus PKCE
  relying-party lifecycle.
- The account-unification service has a private operator bearer boundary; it
  must not become the public OAuth token endpoint or discovery authority.
- No protected-main browser/client MCP flow, resource metadata endpoint,
  resource-bound token, revocation check, or LineageWeave end-to-end result was
  observed in this design pass.

Therefore all runtime behavior below is a target contract. `implemented-main`
must not be reported until exact-head tests and controlled integration evidence
exist.

## Interpretation categories

### Standards requirements

- MCP clients discover the authorization server through protected-resource
  metadata and support OAuth authorization-server metadata or OIDC discovery.
- Public clients use OAuth 2.1 security measures and PKCE.
- Authorization requests and token requests carry one canonical RFC 8707
  resource indicator.
- The protected resource publishes RFC 9728 metadata and advertises it through
  a bearer challenge when required.

### Vendor behavior

Keycloak owns the realm issuer, authorization endpoint, token endpoint, JWKS,
sessions, user state, and protocol execution. Keycloak's native OIDC discovery
is authoritative for vendor endpoints. Any RFC 8414 metadata projection must
be checked against that discovery document and the configured public issuer.

### Keyverse product policy

- Keyverse remains the identity authority; no static MCP API key or second user
  issuance system is allowed.
- Public MCP clients are pre-registered through the existing secret-free
  desired-state boundary until a separate registration ADR is accepted.
- Exact HTTPS redirects, authorization code, `S256` PKCE, exact issuer, exact
  resource, bounded scopes, and deny-first authorization are mandatory.
- Existing RP preflight remains side-effect-free: it must not fetch discovery,
  protected-resource metadata, DNS, or remote Keycloak state. Runtime discovery
  during an actual client/resource flow is a separate acceptance boundary.
- Discovery and metadata are public; operator tokens, client secrets, bearer
  tokens, authorization codes, PKCE verifiers, and protected user data are not.

### Measured evidence

No MCP runtime evidence exists in this record. The required evidence is listed
below and must be attached to the implementation PR at the exact current head.

### Assumptions and limitations

- The deployment supplies one stable public HTTPS issuer and WAF route.
- LineageWeave supplies the canonical protected-resource URI and scope list.
- A JWT signature check without an active revocation check cannot prove
  immediate revocation denial before token expiry.
- A successful discovery document or Keycloak client receipt cannot prove
  downstream tenant/resource authorization.

## Target discovery contract

For a configured issuer `https://keyverse.example/realms/cwl`, publish and test:

```text
https://keyverse.example/realms/cwl/.well-known/openid-configuration
https://keyverse.example/.well-known/oauth-authorization-server/realms/cwl
```

Both documents must contain the same exact `issuer`, authorization endpoint,
token endpoint, and JWKS URI. Each authorization-server metadata document must
publish these as separate RFC 8414 members: `response_types_supported: ["code"]`,
`grant_types_supported: ["authorization_code"]`,
`code_challenge_methods_supported: ["S256"]`, and
`scopes_supported: [<explicitly registered scope set>]`.
The documents must not expose client secrets, registration tokens, private
Keycloak URLs, tenant inventories, or user data.

The tests must reject a document whose issuer, host, endpoint origin, or JWKS
origin is changed to an attacker-controlled value. They must also reject
discovery that is returned from an admin-only route or that causes an operator
credential to be sent.

## Target protected-resource contract

LineageWeave must publish RFC 9728 metadata for each MCP resource containing:

```json
{
  "resource": "https://lineageweave.example/mcp",
  "authorization_servers": ["https://keyverse.example/realms/cwl"],
  "scopes_supported": ["<reviewed-resource-scope>"]
}
```

The concrete scope value is deployment/product data and must be reviewed in
the LineageWeave integration. It must not contain credentials or PII. The
resource must send a 401 bearer challenge with its metadata URL when a client
has no usable access token. The resource must reject a token whose issuer,
audience/resource, subject, expiry, scope, tenant, workspace, or revocation
state does not match its own policy.

## Target authorization sequence

```text
MCP client -> LineageWeave: request without token
LineageWeave -> client: 401 + RFC9728 resource_metadata challenge
client -> resource metadata: discover exact resource and Keyverse issuer
client -> Keyverse discovery: obtain code/token/JWKS endpoints
client -> Keyverse authorization: code + exact redirect + S256 + resource + scopes
user -> Keyverse: passwordless browser/passkey authentication
Keyverse -> client: authorization code
client -> Keyverse token: code + verifier + same redirect + same resource
Keyverse -> client: resource-bound access token
client -> LineageWeave: Bearer access token
LineageWeave -> Keyverse/resource policy: verify issuer, signature, expiry,
  audience/resource, scopes, tenant/workspace, and active/revocation state
```

The sequence must never send a password, static MCP API key, operator bearer,
authorization code, or PKCE verifier to LineageWeave. The resource must not
infer tenant or privilege from a client ID, email, UUID, or unverified header.

## Resource and token binding

The canonical resource URI is an absolute URI without a fragment. It is stored
with one deliberate trailing-slash spelling and compared as an exact value;
Keyverse must not silently normalize two resource identities into one. The
authorization request and token request each contain exactly that one value.

The implementation must prove that the resulting access token's audience (or
equivalent resource authorization evidence) is bound to the same URI. It must
also prove that a token issued for resource A is rejected by resource B, even
when the same user, client, role, or scope name appears in both deployments.

## Registration and headless boundary

The first profile uses Keyverse pre-registration with an exact public client ID
and exact redirect list. It has no client secret and no general dynamic
registration endpoint. A real client that requires Client ID Metadata Documents
or RFC 7591 must trigger a new security review covering URL fetch/SSRF,
redirect ownership, registration abuse, cache freshness, and audit.

RFC 8628 is a documented follow-up only. It must not appear in metadata or be
accepted by the token endpoint until a real callback-less client requirement,
bounded polling contract, user-code lifecycle, abuse limits, and revocation
tests are accepted.

## Revocation and audit contract

Keycloak remains authoritative for disabled identities, sessions, signing-key
rotation, and token revocation. The resource must use an active-token or
equivalent revocation check when claiming immediate revoked-token denial; a
local JWT check alone is insufficient. Audit records contain only non-secret
correlation identifiers, client/resource/scope decisions, actor class, outcome,
and timestamps. No bearer material is logged or persisted.

## Required implementation evidence

- discovery and RFC 8414/OIDC document agreement on exact issuer/endpoints;
- resource metadata and 401 challenge agreement;
- real browser-assisted passkey authorization-code/PKCE flow;
- exact redirect, state, verifier, resource, and scope checks;
- wrong issuer/audience/resource/scope/redirect/PKCE/expiry/revocation denial;
- cross-tenant and cross-workspace denial at the LineageWeave boundary;
- disabled-user/session and key-rotation behavior;
- no password grant, static API key, or premature device flow;
- no discovery/network side effect in existing preflight tests;
- secret/log/response/artifact scans;
- full 100% statement/branch/docstring gates and current-head protected Checks.

## References — APA 7th

Internet Engineering Task Force. (2018). *OAuth 2.0 authorization server
metadata* (RFC 8414). https://doi.org/10.17487/RFC8414

Internet Engineering Task Force. (2015). *Proof key for code exchange by OAuth
public clients* (RFC 7636). https://doi.org/10.17487/RFC7636

Internet Engineering Task Force. (2025). *OAuth 2.0 protected resource
metadata* (RFC 9728). https://doi.org/10.17487/RFC9728

Internet Engineering Task Force. (2020). *Resource indicators for OAuth 2.0*
(RFC 8707). https://doi.org/10.17487/RFC8707

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (BCP 240, RFC 9700). Internet Engineering Task
Force. https://doi.org/10.17487/RFC9700

Model Context Protocol. (2025, November 25). *Authorization*.
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

OpenID Foundation. (2014). *OpenID Connect discovery 1.0 incorporating errata
set 2*. https://openid.net/specs/openid-connect-discovery-1_0.html

Internet Engineering Task Force. (2019). *OAuth 2.0 device authorization grant* (RFC 8628).
https://doi.org/10.17487/RFC8628

## Source limitations

These references establish standards and protocol interpretation only. They do
not prove Keycloak vendor conformance, LineageWeave authorization correctness,
browser success, token revocation latency, or production readiness. Those are
measured in the implementation and deployment evidence described above.
