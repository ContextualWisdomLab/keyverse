# OIDC RP Claim Mapper Profile — Evidence and Standards Doctoring

## Scope

This record documents the evidence used to define Keyverse's closed optional
`protocolMappers` profile for OIDC relying-party desired state. It separates
normative protocol requirements, Keycloak representation behavior, stricter
Keyverse policy, measured repository evidence, assumptions, and limitations.
It does **not** claim OpenID Connect, OAuth, JWT, or Keycloak conformance.

## Normative protocol evidence

### OpenID Connect ID-token audience

OpenID Connect Core defines the ID Token `aud` claim as the audience for which
the token is intended and requires the RP's `client_id` to be present. Keyverse
does not use the custom `keyverse-audience` mapper to satisfy this ID-token
requirement: the mapper deliberately sets `id.token.claim=false`. ID-token
audience validation remains part of the normal OpenID Connect token-validation
boundary and must be proved in controlled login acceptance.

### JWT access-token audience

RFC 9068 requires a JWT access token recipient to reject a token whose `aud`
does not identify that resource server. Keyverse therefore treats the
`keyverse-audience` access-token mapper as an explicit deployment contract, not
as a generic rule that every RP `client_id` is automatically a valid resource
indicator. The Naruon profile pins `included.client.audience` to `naruon-web`
only because the deployment contract expects that exact audience. A deployment
with a distinct resource-server identifier requires a separately reviewed
profile rather than widening this mapper.

### JWT recipient validation

RFC 8725 requires applications to validate the audience when a JWT is intended
for a particular relying party or application. Mapper configuration is only
issuer-side evidence. It does not prove that Naruon validates issuer, signature,
algorithm, token type where applicable, expiry, and audience at its receiving
boundary. Controlled acceptance must verify those behaviors independently.

## Keycloak representation evidence

Keycloak 26 exposes protocol mappers as `ProtocolMapperRepresentation` objects
and includes a list of them on `ClientRepresentation`. Keyverse accepts only the
small subset needed for the reviewed Naruon profile:

- exact fields: `name`, `protocol`, `protocolMapper`, `consentRequired`, and
  `config`;
- exactly one `oidc-audience-mapper` whenever any mapper is present;
- optional `oidc-hardcoded-claim-mapper` entries only for `role`, `org`, and
  `workspace`;
- canonical order: audience, role, org, workspace;
- no scripts, user-attribute lookup, groups, regex, arbitrary claim names,
  unknown mapper classes, or credential-bearing configuration.

Keycloak may add generated mapper `id` values or return mapper order differently
from the submitted representation. Keyverse therefore ignores only a valid
non-empty generated `id`, revalidates the remaining closed representation,
orders known mapper identities canonically, and then performs semantic drift
comparison. Unknown, malformed, or duplicate live mappers remain drift rather
than being silently discarded.

ADR-0009 adds one separate, exact `lineageweave-web` profile. It permits a
client-role mapper whose configured client ID equals the registration client ID,
has no role prefix, and emits multivalued `role`; it also permits two scalar
user-attribute mappers from `org` to `org` and `workspace` to `workspace`.
Keycloak documents these mapper IDs and their configuration properties. Keyverse
intentionally rejects every other user attribute, role source, aggregation,
group, script, audience, claim name, and destination.

### Account-profile requiredness

Keycloak's declarative user profile permits a required role of `admin` or
`user`. The LineageWeave `org` and `workspace` attributes use
`{"roles":["admin"]}` because the same profile makes those fields viewable and
editable only in administrator context. A user-context requirement would direct
an end user to repair attributes they cannot edit. This Keyverse policy proves
only the issuer-side provisioning constraint; receiving-application claim
validation is a separate operational-acceptance requirement.

## Stricter Keyverse product policy

The product policy is intentionally narrower than the vendor representation:

1. Mapper count is bounded to four.
2. The audience mapper is self-pinned to the validated registration
   `clientId`; arbitrary audiences are rejected.
3. Hardcoded claim names are limited to `role`, `org`, and `workspace`.
4. Hardcoded values are bounded visible routing data, not a secret channel.
5. Mapper names and token destinations are canonical and exact.
6. `consentRequired` must be false and protocol must be `openid-connect`.
7. Preflight performs no DNS, HTTP, Keycloak, storage, file, or secret side
   effect.
8. Desired state remains secret-free and write receipts are produced only after
   post-mutation re-observation.
9. The account-derived exception requires all three dynamic claims, forbids
   static/dynamic mixing, reserves `lineageweave-web` for that dynamic profile,
   and retains the same four-mapper maximum.

The hardcoded claims are not, by themselves, proof of user entitlement. A
consumer that uses them for authorization must still apply its independently
reviewed authorization model and token-validation policy.

## Measured repository evidence

The implementation is covered by production-shaped tests that exercise:

- the first Naruon mapper payload being rejected before mapper support existed;
- nested hostile shapes and non-reflective validation failures;
- wrong/duplicate audience and claim mappers;
- unsupported mapper classes and claim names;
- canonical mapper ordering and bounded claim values;
- rejection of hardcoded claims for the reserved `lineageweave-web` client;
- Keycloak-generated mapper IDs and vendor reordering;
- semantic drift for unknown, malformed, duplicate, or changed mappers;
- the committed `deploy/templates/oidc-rp-naruon.json` artifact after
  placeholder substitution;
- the LineageWeave account-role, account-attribute, non-mixing, and
  generated-ID/vendor-order reconciliation paths;
- the committed `deploy/templates/oidc-rp-lineageweave.json` artifact after
  HTTPS placeholder substitution;
- complete production statement and branch coverage in the repository CI gate.

The template test was intentionally introduced before the template. Hosted CI
then failed with `FileNotFoundError` for
`deploy/templates/oidc-rp-naruon.json`, establishing the missing-runtime-artifact
RED receipt before the template was added.

## Assumptions requiring operational evidence

- `naruon-web` is the audience expected by the Naruon resource boundary for the
  access token produced by this deployment profile.
- The deployment controller substitutes all HTTPS and routing-data placeholders
  before preflight and does not persist rendered values in source control.
- `role`, `org`, and `workspace` values are product routing/authorization data
  safe to disclose to the token holder and are not credentials or personal
  secrets.
- Downstream Naruon token validation rejects invalid issuer, signature,
  algorithm, expiry, and audience values.
- The deployed Keycloak version preserves the reviewed mapper semantics.
- A LineageWeave account has exactly one scalar `org` and `workspace` value and
  a least-privilege set of client roles for `lineageweave-web`.
- After normal token verification, LineageWeave must reject an absent, empty,
  or non-scalar `org` or `workspace` claim before tenant/resource ABAC and its
  bounded product-role mapping. This downstream behavior requires its own
  implementation and runtime acceptance evidence; it is not established by
  Keyverse mapper validation or reconciliation alone.

## Limitations and follow-up

This slice does not prove a live authorization-code/PKCE exchange, downstream
audience acceptance, user/session migration, or clean-realm recovery. Those are
runtime evidence boundaries. It also does not remove runtime application
clients from the portable realm; that migration remains a separate reviewed
change. Any new mapper type, claim name, token destination, resource audience,
or native-client redirect profile requires explicit design and regression
coverage rather than extension by configuration alone.

The account-derived profile also does not prove that a real Keyverse account
has been provisioned, its confidential credential has been placed, or its
LineageWeave login/tenant/role lifecycle has been accepted in production.

## References

Bertocci, V. (2021). *JSON Web Token (JWT) profile for OAuth 2.0 access tokens*
(RFC 9068). RFC Editor. https://www.rfc-editor.org/rfc/rfc9068

Jones, M. B., Hardt, D., & Campbell, B. (2020). *JSON Web Token best current
practices* (BCP 225, RFC 8725). RFC Editor.
https://www.rfc-editor.org/rfc/rfc8725

Keycloak Project. (2026). *ClientRepresentation* (Keycloak Docs Distribution
26.x API). https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/representations/idm/ClientRepresentation.html

Keycloak Project. (2026). *ProtocolMapperRepresentation* (Keycloak Docs
Distribution 26.x API). https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/representations/idm/ProtocolMapperRepresentation.html

Keycloak Project. (2026). *Protocol mappers*. Retrieved August 13, 2026, from
https://www.keycloak.org/admin-api/protocol-mappers

Keycloak Project. (2026). *Server Administration Guide* (User profile).
Retrieved August 14, 2026, from https://www.keycloak.org/docs/latest/server_admin/

OpenID Foundation. (2023). *OpenID Connect Core 1.0 incorporating errata set 2*.
https://openid.net/specs/openid-connect-core-1_0.html
