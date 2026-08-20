# App Start-Login Helper — Evidence and Standards Doctoring

## Scope

This record documents why Keyverse offers a start-login helper instead of
moving federation ownership into each relying application. It does not claim
OpenID Connect or Keycloak brokering conformance.

## Normative and authoritative evidence

OpenID Connect Core defines the authorization endpoint and requires the RP
to perform the authorization-code flow, including PKCE when public (OpenID
Foundation, 2023). The helper only composes that endpoint with `client_id`,
`redirect_uri`, `response_type=code`, `scope=openid`, and Keycloak's
`kc_idp_hint` parameter (Keycloak Project, 2026). The RP must still add
PKCE, `state`, and `nonce`.

SAML and OIDC preflight in this repository already forbid metadata and
discovery fetches. The helper preserves that boundary: it reads the local
desired-state registry and rejects `.well-known` or metadata URLs.

NIST SP 800-63C treats the federation authority as distinct from the
application (Grassi et al., 2017). The helper therefore stays Keyverse-owned
and does not become a new IdP.

## Measured repository evidence

`services/account_unification/tests/test_start_login.py` proves single-IdP
auto-selection, multi-IdP hinting, disabled-provider omission, discovery-URL
rejection, HTTPS redirect policy, empty-registry behavior, and the
`metadata_fetch_performed=false` contract. The same tests prove that
percent-encoded `.well-known`, `metadataUrl`, and `discoveryEndpoint` markers
are normalized before the no-fetch policy check. The service only constructs a
response URL; it does not dereference the supplied issuer, so a security scan's
SSRF label is recorded here as a URL-normalization policy defect rather than
live server-side network evidence.

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
