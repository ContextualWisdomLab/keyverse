# App Start-Login Helper — Evidence and Standards Doctoring

## Scope

This record documents why Keyverse offers a start-login helper instead of
moving federation ownership into each relying application. It does not claim
OpenID Connect or Keycloak brokering conformance.

## Normative and authoritative evidence

OpenID Connect Core defines the authorization endpoint and authorization-code
flow. RFC 9700 requires public clients to use PKCE to prevent authorization
code injection (Lodderstedt et al., 2025). The helper only composes that
endpoint with `client_id`,
`redirect_uri`, `response_type=code`, `scope=openid`, and Keycloak's
`kc_idp_hint` parameter (Keycloak Project, 2026). The RP must still add
PKCE, `state`, and `nonce`.

SAML and OIDC preflight in this repository already forbid metadata and
discovery fetches. The helper preserves that boundary: it reads the local
desired-state registry, rejects `.well-known` or metadata URLs, and accepts
only the configured Keycloak public issuer. Start-login is a runtime
front-channel helper rather than an operator-admin route.

The authorization endpoint is also bound to the configured public Keyverse
issuer (or the configured Keycloak realm URL when no public override exists).
The request cannot redirect an RP to an arbitrary host. This is a Keyverse
trust-boundary policy, not a network-fetch claim.

NIST SP 800-63C treats the federation authority as distinct from the
application (Grassi et al., 2017). The helper therefore stays Keyverse-owned
and does not become a new IdP.

## Measured repository evidence

### Shared-token comparison representation

Python's `hmac.compare_digest` accepts bytes or ASCII-only strings (Python
Software Foundation, n.d.). A synthetic raw non-ASCII runtime header reproduced
HTTP 500 at the actual start-login ASGI consumer while an otherwise-valid ASCII
credential returned HTTP 200. The same defect was reproduced at operator and
registration bearer consumers. These guards now encode both compared strings
as UTF-8 bytes without trimming beyond their existing bearer extraction or
Unicode normalization. Invalid headers retain fixed HTTP 403; no configured
credentials are issued, changed, or logged by this repair.

`test_token_header_safety.py` records separate runtime and sibling RED→GREEN
slices, each with authorized handler positives. This is offline synthetic HTTP
consumer evidence, not deployed identity, issuer, RP login, or release evidence.
The runtime dependency policy is unchanged. The root README test setup now
selects the existing optional `dev` extra; its manifest/setup regression does
not claim a clean hosted dependency installation.

`services/account_unification/tests/test_start_login.py` proves single-IdP
auto-selection, multi-IdP hinting, disabled-provider omission, discovery-URL
rejection, HTTPS redirect policy, empty-registry behavior, and the
`metadata_fetch_performed=false` contract. The same tests prove that
percent-encoded `.well-known`, `metadataUrl`, and `discoveryEndpoint` markers
are normalized before the no-fetch policy check. The service only constructs a
response URL; it does not dereference the supplied issuer, so a security scan's
SSRF label is recorded here as a URL-normalization policy defect rather than
live server-side network evidence.
They also prove untrusted issuer rejection and authenticated runtime embedding.

## Assumptions and limitations

The constructed authorization URL is not production login evidence. Controlled
authorization-code acceptance still belongs to the RP and deployment
controller.

## References

Grassi, P. A., Nadeau, E. M., Richer, J. P., Squire, S. K., Fenton, J. L.,
Lefkovitz, N. B., Danker, J. M., Choong, Y.-Y., Greene, K. K., & Theofanos,
M. F. (2017). *Digital identity guidelines: Federation and assertions*
(NIST Special Publication 800-63C). National Institute of Standards and
Technology. https://doi.org/10.6028/NIST.SP.800-63c

Keycloak Project. (2026). *Identity brokering* (Keycloak Server
Administration Guide 26.x).
https://www.keycloak.org/docs/latest/server_admin/#_identity_broker

OpenID Foundation. (2023). *OpenID Connect Core 1.0 incorporating errata set
2*. https://openid.net/specs/openid-connect-core-1_0.html

Python Software Foundation. (n.d.). *hmac: Keyed-hashing for message
authentication* (Python 3.12 documentation).
https://docs.python.org/3.12/library/hmac.html#hmac.compare_digest

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (RFC 9700; BCP 240). RFC Editor.
https://www.rfc-editor.org/rfc/rfc9700
