# ADR-0010: Issue hierarchical authorization attributes and decisions without owning employment truth

**Status:** Accepted  
**Date:** 2026-08-18

## Context

Buyers need access control that follows the group-company, legal-entity,
business-unit, team, and person tree (Macro / Meso / Micro):

1. which software unit / relying party a subject may use;
2. menu-level ABAC plus RBAC inside that software;
3. one Keyverse SSO session covering a selected combination of software units;
4. higher-node grants that inherit downward unless a more-specific assignment
   restricts them.

Employment and org-tree *truth* is Orgmetra (`organization_unit` /
`assignment_record`). Keyverse is the authentication home and binds an opaque
Keyverse subject. Copying Orgmetra's tree into Keyverse as a second source of
record would split authority and drift.

Open PR #100 defines ADR-0009 and account-derived `role`, `org`, and
`workspace` claims for the unmerged LineageWeave profile. This plane must not
collide with or silently redefine those names.

ADR-0008 already requires every non-fork RP to validate the Keyverse token and
enforce ABAC/RBAC at its own boundary.

## Decision

1. Keyverse is the issuer/PDP of authorization **attributes and decisions**.
   Each relying party remains the PEP. ADR-0008 is unchanged: a decision
   receipt is issuer-side evidence, not a substitute for issuer, audience,
   signature, expiry, or subject validation at the RP.
2. Orgmetra remains employment SoR. Decision and grant APIs accept a caller-
   supplied assignment snapshot (`keyverse_subject`, `org_path`, optional
   `assignment_record_id`). Keyverse does not persist or synchronize the
   Orgmetra tree.
3. Hierarchical attributes use distinct names: `group_company`,
   `legal_entity`, `business_unit`, `team`, `person`, and structured
   `org_path`. `role`, `org`, and `workspace` stay reserved for the
   LineageWeave profile on ADR-0009 / PR #100. When that profile lands, the
   claims compose: LineageWeave routing claims identify product tenant
   context; `org_path` attributes describe Macro-to-Micro assignment
   evidence.
4. Inheritance: the most specific grant whose org path (and, for menus, menu
   path) is an ancestor of the snapshot wins. An ancestor allow applies to
   descendants; a more-specific deny or replacement grant restricts that
   subtree. Default is deny. Secrets and programmable application tokens
   never inherit.
5. SSO combination scopes are named sets of software units. A combination is
   allowed only when every member software unit is allowed for that snapshot.
   The Keycloak session remains Keycloak-owned; this plane only authorizes
   which RP set may share it.
6. Menu decisions apply software-unit ACL first, then ABAC constraints
   (`purpose`, `sensitivity`, `clearance`, `residency`), then remaining RBAC
   capability codes.

## Consequences

- Operators persist grants and combinations through authenticated Keyverse
  admin APIs and evaluate decisions without contacting Orgmetra or Keycloak.
- Downstream RPs must still prove ADR-0008 token validation. This slice does
  not claim production login or federation acceptance.
- ADR-0009 remains reserved for the unmerged LineageWeave claim profile.
