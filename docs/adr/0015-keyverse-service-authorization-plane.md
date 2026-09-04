# ADR-0015: Service-to-service ABAC/RBAC stays a separate Authorization Plane

**Status:** Proposed (design/recommendation only; no new code in this PR)
**Date:** 2026-09-02

## Context

The owner asked that Keyverse also function as a centralized
authorization/policy decision point (PDP) for **service-to-service** calls
across the ecosystem — not end-user authentication, which Keycloak already
owns — so another CWL service (`contextual-orchestrator`, `naruon`,
`noema`, `wardnet`, …) can ask "is principal X authorized to perform action
Y on resource Z," using either attribute-based (ABAC) or role-based (RBAC)
access control.

**Does Keycloak already offer this?** Yes, partially. Keycloak ships a
built-in *Authorization Services* feature per client: resources, scopes,
policies, and permissions, implementing the Kantara Initiative's
User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 (Keycloak, n.d.,
"Authorization Services Guide"). Direct inspection of this deployment's
portable realm export confirms it is **not currently enabled**:
`deploy/keycloak/realm-cwl.json` has no client with
`authorizationServicesEnabled: true` and no top-level `resources`,
`policies`, or `permissions` blocks.

**Is generic UMA 2.0 the right fit for CWL's actual requirement, though?**
Only partly. Keycloak's Authorization Services model resources, scopes, and
policies per client, evaluated largely flat (role/client/user/time/context
policies) and administered through the Keycloak Admin Console. It has no
native concept of the **hierarchical, tenant-scoped org-path inheritance**
this ecosystem's authorization model needs — CWL's org tree is owned by
Orgmetra (per this repo's own README: "Orgmetra owns employment and
organizational-tree truth. Keyverse does not copy Orgmetra tables"), and
authorization decisions here must walk that org-path hierarchy, not just
match a flat policy set. RBAC's original formal model (Sandhu et al., 1996)
and NIST's ABAC guidance (Hu et al., 2014) both describe role/attribute
evaluation abstractly enough to accommodate a hierarchy, but neither
Keycloak's shipped implementation nor a naive attribute policy set
provides org-path inheritance out of the box; it would have to be built as
custom policy logic layered on top of UMA regardless.

**Is this already being built?** Yes — as of this writing, PR
[`keyverse#103`](https://github.com/ContextualWisdomLab/keyverse/pull/103)
("feat(authorization): hierarchical PDP, start-login helper, and PATs",
open/Draft) already implements exactly this shape:
`services/account_unification/app/authorization_plane.py` and
`org_authorization.py` (674 and 644 added lines respectively), covering
software-unit ACL, menu-level ABAC + RBAC decisions, SSO combination
scopes, and tenant-scoped hierarchical org-path inheritance, each with its
own test suite and its own ADRs (0010–0012, reserved per
`docs/adr/README.md`'s numbering note). Its own boundary decision already
states the intended shape: "Keyverse is the issuer/PDP; relying parties
remain PEPs and must validate issuer, signature/algorithm, expiry,
subject, audience, tenant/resource constraints, and applicable decisions" —
the standard PDP/PEP split (policy decided centrally, enforced locally by
each relying party), not a request-time authorization proxy in the request
path of every call.

That PR is not mergeable as of 2026-09-02 per its own status note: "23
commits ahead and 34 commits behind live main… not mechanically
mergeable… every predecessor-head CI/review result is historical and the
current head has no executable merge evidence." Building a second,
competing authorization-plane implementation in this PR — rather than
reconciling that branch — would duplicate ~2,000 lines of already-written,
already-tested domain logic and create exactly the kind of
divergent-parallel-PR problem this org's own operating directive (§2 of
`docs/product-goal-directive.md` in `ContextualWisdomLab/.github`) asks
agents to avoid ("가능한 PR은 Stack하고 not-merge-ready를 merge-ready로
전환한다" — stack PRs where possible and convert not-merge-ready work to
merge-ready, rather than starting over).

## Decision

Service ABAC/RBAC is its **own bounded context** — an Authorization Plane —
separate from both the Keyvault secrets store (ADR-0014) and core IdP
identity/authentication. It shares only the Keycloak-adjacent principal/
token verification already common to every Keyverse-fronted API, per this
org's minimal-Shared-Kernel convention.

For this iteration:

1. **No new authorization-plane code is added here.** PR #103 already owns
   this capability's domain model, tests, and ADRs (0010–0012). The
   correct next action is reconciling and landing that branch, not
   building a parallel implementation.
2. **Keycloak's built-in Authorization Services (UMA 2.0) is not adopted
   as a substitute.** It would need custom policy logic for org-path
   hierarchy regardless, at which point PR #103's purpose-built
   `authorization_plane.py` is the more direct implementation of the
   actual requirement, not a reinvention of something Keycloak already
   solves.
3. **Consuming services stay PEPs.** Per PR #103's own boundary decision,
   a service asking "is X authorized for Y on Z" validates the returned
   decision locally (issuer, signature, audience, tenant/resource
   constraints) rather than treating Keyverse as an inline authorization
   proxy in every request's hot path — matching this repo's ADR-0008
   ("every non-fork RP explicitly validates Keyverse identity and manages
   ABAC/RBAC at its own boundary"), now extended from identity claims to
   PDP decisions.

## Consequences

- This ADR records the decision and its evidence trail; it does not
  change runtime behavior in this PR.
- The next concrete step for this capability is a separate, focused effort
  to reconcile PR #103 against current `main` (its own stated blocker),
  not new design work.
- If PR #103's branch-convergence blocker is not resolved in a reasonable
  time, revisit whether a smaller subset of its scope should be
  re-proposed fresh against current `main` — but that revisit belongs to
  whoever picks up PR #103's reconciliation, informed by this ADR's
  research, not to a second unreviewed rebuild.

## References

Hu, V. C., Ferraiolo, D., Kuhn, R., Friedman, A. R., Lang, A. J., Cogdell,
M. M., Schnitzer, A., Sandlin, K., Miller, R., & Scarfone, K. (2014).
*Guide to attribute based access control (ABAC) definition and
considerations* (NIST SP 800-162). National Institute of Standards and
Technology. https://doi.org/10.6028/NIST.SP.800-162

Keycloak. (n.d.). *Authorization services guide* (Version 26.7.1).
Retrieved September 2, 2026, from
https://www.keycloak.org/docs/latest/authorization_services/

Sandhu, R. S., Coyne, E. J., Feinstein, H. L., & Youman, C. E. (1996).
Role-based access control models. *Computer, 29*(2), 38–47.
https://doi.org/10.1109/2.485845
