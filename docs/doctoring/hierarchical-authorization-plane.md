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
`services/account_unification/tests/test_authorization_plane.py` cover
inheritance, restriction, software-unit and menu ABAC/RBAC, tenant-isolated
grants and combinations, reserved-name rejection, and fail-closed storage. The
focused `test_menu_path_inheritance_is_reported_when_org_path_is_exact`
regression proves that a strict menu-prefix match sets `inherited=true` even
when the org path is exact. The HTTP regression suite also verifies that the
authorization router rejects an unauthenticated direct embedding and accepts
only the configured operator bearer. The router now owns both the
operator-authentication and privileged-path dependencies rather than relying
only on the application factory's include-site wiring.
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

## Menu torn-read root cause and bounded repair

**Measured evidence:** Exact PR103 source `5ac33256229321e9fccbb14a460c7d6de984444a`
read software grants, released its read lock, then read menu grants. A fixture
using the actual SQLite store and a second SQLite connection commits a single
transaction changing `(software allow, menu deny)` to `(software deny, menu
allow)` between those reads. Both complete states deny; the old composition
returns allow and capabilities from the pair that never existed together.
The behavioral RED is preserved with exact source hashes in the private review
packet. The repaired composition returns the coherent before-state deny, and
a subsequent decision observes the after-state software denial.

**Vendor behavior:** Separate SQLite connections isolate committed transactions;
WAL readers keep their snapshot while another connection commits.[1] A separate
native-row callback test commits on the second connection during `fetchall`
and verifies both returned namespaces retain the old values without replacing
any persisted row or PDP result.

**Policy choice:** `get_all_namespaces` captures detached raw strings in one
SQLite SELECT with bound namespace parameters, or one in-memory lock. Missing
namespaces are empty, duplicates collapse, no namespaces yields an empty dict,
and unrequested namespaces are not returned. Existing single-namespace APIs
and every policy rule in `org_authorization.py` remain unchanged. All captured
rows are parsed before the canonical PDP, retaining malformed and semantically
invalid row rejection.

**Limits:** Read coherence alone does not make separately committed grant writes
one rollout, create monotonic manifests/revisions, establish issuer or current
Orgmetra membership authority, revoke already admitted RP work, or supply durable
cross-system write intent. Instance RLocks are not cross-process locks. A valid
allow captured before revocation can return after that revocation; the next
fresh decision denies. The private suite and changed-seam coverage are scoped
local evidence, not full repository/HTTP/Keycloak/hosted CI/merge acceptance.

## SSO definition/grants sibling and bounded successor

**Measured evidence:** On the immutable menu-repaired PR103 private candidate,
`decide_combination` still captured a definition and later read software grants.
The real SQLite/TestClient regression commits a complete definition-plus-grants
transaction through a second connection after actual definition capture. The
before suite (`naruon-web`, `common-web`) denies naruon; the after suite
(`clearfolio-web`, `common-web`) denies clearfolio. Both coherent generations
deny, but the old definition plus new grants falsely returns HTTP 200/Allow.
The retained RED has one intended assertion failure and zero errors/skips.
The unchanged race hook releases the writer at the real legacy or atomic read
boundary; GREEN captures the old definition and old grants together and denies.
The next fresh decision observes the committed after suite and also denies.
Stable nonempty Allow, all-row JSON/semantic corruption rejection, tenant/name
filtering, grant-key ordering and missing/ambiguous 404/409 controls are retained
through both canonical backends. Existing `get_combination` administration
semantics and the pure PDP are unchanged.

**Policy choice:** Reuse `get_all_namespaces` for combination definitions plus
software grants; parse all captured rows before tenant/name selection and PDP.
No transaction wrapper, new writer protocol, revision counter, or second PDP is
introduced. SQLite isolation evidence is the same authoritative source [1].

**Limits:** Actual TestClient routing is local ASGI evidence using synthetic
operator and assignment inputs, not deployed HTTP or authenticated end-user
acceptance. This successor addresses only read coherence. Current employment,
issuer/RP enforcement, cross-system authority, atomic rollout writers and
revocation of already admitted operations remain excluded. A captured valid
allow can still return after revocation, while the next fresh decision denies.
Independent whole-candidate review and exact-head hosted/release gates remain
separate from private tests; no production deployment or full-product approval
is established.

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

SQLite. (n.d.). *Isolation in SQLite*. Retrieved October 4, 2026, from https://www.sqlite.org/isolation.html

## Sources

[1] https://www.sqlite.org/isolation.html — Isolation in SQLite
