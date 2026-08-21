# Hierarchical Authorization Plane — Evidence and Standards Doctoring

## Scope

This record documents the evidence used to define Keyverse's issuer-side
hierarchical authorization plane. It separates standards requirements, vendor
behavior, measured repository evidence, policy choices, assumptions, and
limitations. It does not claim XACML, NIST, or OIDC conformance.

## Normative and authoritative evidence

NIST SP 800-162 describes attribute-based access control as a decision that
combines subject, resource, action, and environment attributes (Hu et al.,
2014). Keyverse uses that structure for menu decisions: the subject is the
opaque Keyverse subject plus org-path attributes, the resource is the
software unit and menu path, and environment attributes are the closed
`purpose` / `sensitivity` / `clearance` / `residency` set.

The tenant deployment is an additional closed scope attribute. A decision
snapshot must carry a validated `tenant_deployment_id`, and grants or SSO
combinations from another deployment are not candidates. This is a Keyverse
policy choice that operationalizes the tenant-qualified uniqueness described in
the ERD; it is not a claim that NIST SP 800-162 prescribes this storage key.

NIST SP 800-63C requires federation to keep identity proofing and
authentication distinct from relying-party authorization (Grassi et al.,
2017). Orgmetra therefore remains employment truth; Keyverse issues
attributes and decisions and does not become a second HR system of record.

RFC 8725 requires JWT recipients to validate audience and other registered
claims (Jones et al., 2020). ADR-0008 already places that duty on each RP.
The PDP API does not relax that requirement.

## Vendor behavior

Keycloak remains the session and token issuer. This plane does not add
Keycloak group mappings for the org tree and does not embed application
clients in the portable realm.

## Stricter Keyverse policy

1. Hierarchical claim names are not `role`, `org`, or `workspace`.
2. Inheritance is most-specific-wins with default deny.
3. Secrets and PATs never inherit.
4. Decision evaluation performs no Orgmetra, DNS, or Keycloak I/O.
5. Decision metadata reports inheritance for a strict org-path or menu-path
   ancestor, so a menu prefix grant at the exact org node is not mislabeled as
   a specific decision.
6. Menu-path specificity is evaluated before org-path specificity. This is a
   measured policy choice: a narrower menu restriction wins over a narrower
   org grant when both are candidates.
7. Ambiguous same-name grant and combination administration is fail-closed
   without a tenant, while GET/DELETE APIs accept an explicit validated
   `tenant_deployment_id` for the intended record.

## Measured repository evidence

`services/account_unification/tests/test_org_authorization.py` and
`tests/test_authorization_plane.py` cover inheritance, restriction, software-
unit and menu ABAC/RBAC, tenant-isolated grants and combinations, reserved-name
rejection, and fail-closed storage. The focused
`test_menu_path_inheritance_is_reported_when_org_path_is_exact` regression
proves that a strict menu-prefix match sets `inherited=true` even when the org
path is exact. The HTTP regression suite also verifies that the authorization router
rejects an unauthenticated direct embedding and accepts only the configured
operator bearer. The router now owns both the operator-authentication and
privileged-path dependencies rather than relying only on the application
factory's include-site wiring.
The `test_ambiguous_grant_reads_and_deletes_accept_explicit_tenant` regression
proves that same-named grants remain ambiguous without scope but can be read
and deleted through the explicit tenant query parameter.

The operator bearer is intentionally coarse operator-admin authority. The
`actor_identity_id` field is grant and audit metadata selected by that operator;
it is not an end-user principal asserted by the bearer. The current service
does not claim per-operator actor ownership. Any future multi-principal admin
model must add an explicit authenticated-principal contract and negative
cross-principal tests before changing this boundary. This distinction explains
why a scanner proof of two end users presenting different body identities is
not, by itself, a measured exploit of the operator-only route; the hosted Strix
finding remains a required current-head security review until independently
revalidated.

## Assumptions and limitations

Callers supply a current Orgmetra snapshot with an explicit tenant deployment.
Grant and SSO evaluation filters that tenant before applying inheritance; a
software-unit grant cannot carry menu ABAC constraints. This slice does not
subscribe to Orgmetra change feeds. Production login acceptance remains a
separate runtime evidence boundary.

## References

Grassi, P. A., Nadeau, E. M., Richer, J. P., Squire, S. K., Fenton, J. L.,
Lefkovitz, N. B., Danker, J. M., Choong, Y.-Y., Greene, K. K., & Theofanos,
M. F. (2017). *Digital identity guidelines: Federation and assertions*
(NIST Special Publication 800-63C). National Institute of Standards and
Technology. https://doi.org/10.6028/NIST.SP.800-63c

Hu, V. C., Ferraiolo, D., Kuhn, R., Schnitzer, A., Sandlin, K., Miller, R.,
& Scarfone, K. (2014). *Guide to attribute based access control (ABAC)
definition and considerations* (NIST Special Publication 800-162).
National Institute of Standards and Technology.
https://doi.org/10.6028/NIST.SP.800-162

Jones, M. B., Hardt, D., & Campbell, B. (2020). *JSON Web Token best current
practices* (BCP 225, RFC 8725). RFC Editor.
https://www.rfc-editor.org/rfc/rfc8725
