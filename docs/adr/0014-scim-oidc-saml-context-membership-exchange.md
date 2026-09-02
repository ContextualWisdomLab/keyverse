# ADR-0014: Own the SCIM, OIDC, and SAML adapters for the org-hierarchy/membership contract

**Status:** Proposed
**Date:** 2026-09-02

## Context

`context-graph-contracts` ADR-0001 (`docs/adr/0001-enterprise-org-hierarchy-membership-contract.md`,
commit `c37c465` on `claude/enterprise-org-hierarchy-membership-contract`, PR
[context-graph-contracts#23](https://github.com/ContextualWisdomLab/context-graph-contracts/pull/23))
defines the canonical internal shape for an enterprise customer's multi-root,
dynamically-ordered org hierarchy and concurrent (primary/secondary, TFT) membership:
`ContextAssertion` (subject/predicate/object/truth_status/interval/provenance) plus
one-to-sixteen `ContextMembership` entries (context_ref/membership_level/parent_context_ref),
with a registered predicate vocabulary `org_member_primary` / `org_member_secondary` /
`org_member_observed`. Orgmetra remains the org-tree and membership-fact source of
truth; `context-graph-contracts` is the versioned wire contract; Keyverse is the PDP
(`services/account_unification/app/org_authorization.py`, extending draft PR #103) — none
of that changes here.

What that ADR does not do is say how an enterprise customer's identity provider
actually gets this data in or out. Their IdP does not speak `ContextAssertion`. It
speaks SCIM (provisioning push), OIDC (ID-token/UserInfo claims a relying party reads),
or SAML (`<AttributeStatement>` on federated login). Keyverse is the only ecosystem
repository that terminates all three:

- `README.md`: "runs a **SCIM 2.0 server shim** for inbound provisioning," "**federates
  external IdPs in** — employer ADFS via SAML," "issues **OpenID Connect** ... to
  ecosystem relying parties."
- `services/account_unification/app/scim.py` (RFC 7644 inbound shim) — but its own
  module docstring says plainly: *"Supported: ... Users create/get/replace/patch/delete
  ... Groups are intentionally out of scope for this shim."* There is no `Group`
  resource today.
- `services/account_unification/app/federation.py` — inbound IdP registration
  (`IdentityProviderRegistration`), including the SAML path (`deploy/templates/saml-idp-employer-adfs.json`);
  it validates and applies IdP config, it does not currently map incoming attribute
  values to any org-hierarchy concept.
- `deploy/keycloak/realm-cwl.json` — checked directly, not assumed: **zero**
  `"groups"` occurrences in 397 lines. The only org-shaped claims that exist
  (`naruon-web`'s `org`/`workspace`/`role`) are three `oidc-hardcoded-claim-mapper`
  entries, each returning the same static string (`"org-cwl"`, `"workspace-org-cwl"`,
  `"member"`) for every user. There is no per-user, per-membership claim resolution
  anywhere in this realm today.

**This ADR is a target-state design.** Every mechanism below is new. Nothing in this
document describes something already deployed.

### Why this is not ADR-0009, and does not touch it

ADR-0009 (`docs/adr/0009-lineageweave-account-derived-rp-claims.md`) already ships a
closed, account-derived `org`/`workspace` claim profile — but scoped, explicitly and
narrowly, to the `lineageweave-web` client, with two **scalar** user attributes, and it
says so itself: *"The profile does not represent multiple memberships. ... A future
multi-membership or scalar-tenant profile requires a separate ADR, RED regression, and
downstream acceptance evidence."* This ADR is that reserved follow-up — for a
**different** claim (`cwl_context_memberships`, array-of-objects, not `org`/`workspace`)
and, when implemented, a **different** client profile. ADR-0009's four-mapper
`lineageweave-web` profile is unmodified by this design.

### Why this is not PR #103, and does not touch it

PR #103's `org_authorization.py` is the ABAC/RBAC **decision** engine (PDP): given a
caller-supplied `AssignmentSnapshot`, decide `allow`/`deny`. This ADR is the **fact
delivery** layer: how the caller (a relying party, or Keyverse itself before it calls
the PDP) obtains that assignment data from a protocol an external IdP or an ecosystem
RP actually speaks. The two are adjacent and eventually connect (a resolved
`cwl_context_memberships` claim is exactly PDP input shape, once mapped to
`AssignmentSnapshot.memberships`), but PR #103 is itself draft and `mergeable_state:
dirty`; this ADR does not modify it, matching `context-graph-contracts` ADR-0001's own
reconciliation stance.

## Decision

### 1. Ownership

Keyverse owns all three protocol adapters (SCIM ingest/egress, OIDC claim emission,
SAML attribute ingest). `context-graph-contracts`'s `ContextAssertion`/
`ContextMembership` (its ADR-0001, including the "SCIM, OIDC, and SAML exchange"
section added there alongside this ADR) is the single schema authority each adapter
projects from or into — this ADR does not redefine any field, only how Keyverse
carries it over each protocol. Every adapter below serializes the same
**membership-projection record**:

```
{assertion_id, context_ref, parent_context_ref, membership_level, predicate, valid_from, valid_to}
```

one row per `ContextAssertion` (`assertion_id`, `predicate`, `interval.valid_from`/
`valid_to`) joined to its matching `ContextMembership` entry (`context_ref`,
`parent_context_ref`, `membership_level`).

### 2. SCIM (RFC 7643 §4.2, RFC 7644 §3.3)

Extend `scim.py`'s shim — currently `User`-only by explicit design choice — with a
`Group` resource:

- **Tree shape → nested groups.** A parent org unit's `members[]` lists its child
  org-unit `Group`s (`"type": "Group"`, RFC 7643 §4.2) — core SCIM, no extension
  needed, and the natural inverse of `ContextMembership.parent_context_ref`.
- **Fields SCIM core has no slot for → a custom extension** (RFC 7644 §3.3), split
  across two resources because tree shape and per-person fact have different change
  frequency:

  `urn:ietf:params:scim:schemas:extension:cwl-context-membership:2.0:Group`
  ```json
  {
    "contextRef": "urn:cwl:tenant_001:orgmetra:organization_unit:0195...-team-a",
    "parentContextRef": "urn:cwl:tenant_001:orgmetra:organization_unit:0195...-part-a",
    "membershipLevel": 5,
    "orgUnitTypeCode": "team"
  }
  ```

  `urn:ietf:params:scim:schemas:extension:cwl-context-membership:2.0:User`
  ```json
  {
    "contextMemberships": [
      {
        "assertionId": "0195eb2c-...",
        "contextRef": "urn:cwl:tenant_001:orgmetra:organization_unit:0195...-team-a",
        "predicate": "org_member_primary",
        "validFrom": "2026-01-01T00:00:00Z",
        "validTo": null
      }
    ]
  }
  ```

  `contextRef`/`parentContextRef` validate against the same canonical-asset-uri
  grammar as `context-graph-contracts`; `membershipLevel` is `ContextMembership
  .membership_level` unchanged (0-15); `predicate` is one of the three registered
  values; `assertionId` is the source `ContextAssertion.assertion_id` (UUIDv7),
  carried for traceability, not re-derived.

- **Ingest is asymmetric by construction.** A CWL-aware pusher (a future connector
  that knows this extension) supplies exact values; a generic HR/IGA tool's bare
  RFC 7643 `Group` (`displayName` + `members[]`, no extension) does not, because
  SCIM core has no primary/secondary concept for its own author to fill in. For the
  bare case: `membershipLevel` and `parentContextRef` are inferred structurally
  (nesting depth, parent Group's `members[]` back-reference); every direct `User`
  member becomes `predicate: "org_member_observed"` — never guessed as
  `org_member_primary`. Both cases produce `truth_status: "observed"`
  `ContextAssertion`s (never `authoritative` — an adapter does not generate assertions
  by owning-domain command) with `provenance.evidence_ref`/`sha256` over the inbound
  SCIM request, published for Orgmetra (or an equivalent reconciliation workflow) to
  accept, reject, or reclassify. Keyverse does not write these into Orgmetra directly
  or treat them as authoritative itself — same non-source-of-record boundary
  `README.md` already states for the org tree generally.

### 3. OIDC (Core 1.0 §5.1)

§5.1 Standard Claims has nothing shaped like org membership; this is a non-standard,
issuer-RP-agreed claim, the same category `role`/`org`/`workspace` already are in this
realm. Because a scalar claim cannot hold concurrent primary+secondary membership, the
new claim is an array:

```json
"cwl_context_memberships": [
  {
    "assertion_id": "0195eb2c-...",
    "context_ref": "urn:cwl:tenant_001:orgmetra:organization_unit:0195...-team-a",
    "parent_context_ref": "urn:cwl:tenant_001:orgmetra:organization_unit:0195...-part-a",
    "membership_level": 5,
    "predicate": "org_member_primary",
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_to": null
  }
]
```

**Mechanism, reusing what Keycloak already does, not a new SPI.** Keycloak's built-in
`oidc-usermodel-attribute-mapper`, with `jsonType.label: "JSON"`, parses a user
attribute's string value as JSON and embeds the parsed structure — object or array —
directly into the claim, not as a quoted string. So: the account-unification service
computes the current `cwl_context_memberships` array for a user (from the
`ContextAssertion`s Orgmetra/`context-graph-contracts` publish for that subject) and
writes it, JSON-serialized, to one Keycloak user attribute; one attribute mapper on the
relying client emits it as a real array-of-objects claim. This is the same "closed,
reviewed mapper profile bound to one client" shape ADR-0009 already established
(audience-pinned, no generic mapper editor) — a new, separate profile for whichever
client first needs full multi-membership fidelity, not an extension of ADR-0009's
`lineageweave-web` profile. The write side (a membership-sync module in
`services/account_unification/app/`, analogous to the existing merge service's
`list_group_memberships` calls) is new code, not built by this ADR.

Only the immediate `context_ref`/`parent_context_ref` travel in the token — not
`ContextAssertion.memberships[]`'s full ancestor closure. An "is subject under org unit
X" ABAC decision stays server-side in Keyverse's PDP (PR #103's extension, per
`context-graph-contracts` ADR-0001's evaluation sketch), which already holds the full
closure without a token round-trip; carrying a 6-level ancestor chain in every token per
membership was considered and rejected as unneeded token growth for a query the issuer
answers more cheaply itself.

### 4. SAML (V2.0 Core §2.7)

**Ingest** (the live path: employer ADFS federating in via `federation.py`) is the
harder direction and is only partially solved here. An external IdP's
`<AttributeStatement>` carries **its own** vocabulary (AD group DNs, ADFS claim URIs),
never `urn:cwl:claims:context_membership` — only Keyverse emits that. There is no
generic algorithm mapping arbitrary third-party attribute names to a `context_ref`;
that is inherently per-tenant deployment configuration. The natural extension point is
`federation.py`'s existing `IdentityProviderRegistration` (already the per-tenant "which
IdP, what config" record) gaining a per-tenant raw-attribute-name/value →
`context_ref` mapping table — **not designed further here**, only identified as where it
belongs. Once resolved to a `context_ref`, the result is the same as SCIM's bare-push
case: `predicate: "org_member_observed"`, `truth_status: "observed"`, provenance
pointing at the SAML assertion (`evidence_ref` + `sha256` over its canonicalized bytes).

**Egress** (Keyverse issuing SAML assertions to a downstream RP) has no current
consumer — no ecosystem RP requires Keyverse as a SAML IdP today; the README's "SAML
broker" language describes Keycloak's dual-direction *capability*, not a used one. If
and when an RP needs it, the shape mirrors OIDC exactly — natively better suited to it,
since §2.7 supports multiple `<AttributeValue>` elements per `<Attribute>` without an
array-shaped workaround:

```xml
<saml2:Attribute Name="urn:cwl:claims:context_membership"
                  NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                  FriendlyName="CWL Context Membership">
  <saml2:AttributeValue xsi:type="xs:string">{"assertion_id":"0195eb2c-...","context_ref":"urn:cwl:tenant_001:orgmetra:organization_unit:0195...-team-a","parent_context_ref":"urn:cwl:tenant_001:orgmetra:organization_unit:0195...-part-a","membership_level":5,"predicate":"org_member_primary","valid_from":"2026-01-01T00:00:00Z","valid_to":null}</saml2:AttributeValue>
</saml2:Attribute>
```

one JSON-string `AttributeValue` per concurrent membership — `AttributeValue` is
text-typed unless the receiving SP opts into structured `xsi:type` content, which is
not assumed here. `urn:cwl:claims:context_membership` is a SAML attribute name, not a
canonical asset URI, and must never be validated against
`canonical-asset-uri.schema.json`'s tenant/authority/object-type/UUIDv7 grammar. Egress
is flagged **deferred** below precisely because it has no current consumer to design
against.

### 5. Why no standalone JSON Schema file is added in this PR

`context-graph-contracts` ADR-0001's own follow-up (task item 6) allows "a very small,
safe, additive first step (e.g., just defining the SCIM schema extension's JSON Schema
file)." Considered and **not done here**: this repository has no existing
`*.schema.json` convention anywhere — every wire shape in `org_authorization.py`
(`AssignmentSnapshot`, `AuthorizationGrant`, …) is a Pydantic model, not a packaged JSON
Schema file, and `context-graph-contracts` (a different, schema-first repository) is
already the right home for genuinely shared schemas. Adding an orphan `.schema.json`
file here with no consumer, no test, and no precedent would be exactly the
untested-scaffolding shape this org's own engineering discipline warns against. The two
SCIM extension shapes and the OIDC/SAML record are instead fully specified inline
above (copy-pasteable field-for-field); at implementation time they become Pydantic
models in `services/account_unification/app/`, matching this repository's existing
pattern, not new schema files.

## Consequences

- Implementing this ADR touches: `scim.py` (new `Group` resource + extension parsing),
  a new membership-sync module (writes the JSON-serialized user attribute Keycloak's
  mapper reads), `deploy/keycloak/realm-cwl.json` (new user-attribute mapper, scoped to
  one relying client — not `naruon-web`'s existing hardcoded profile), and
  `federation.py` (per-tenant attribute-mapping config, for SAML ingest). None of that
  is implemented in this PR.
- Any field/predicate change still goes through `context-graph-contracts` ADR-0001
  first — this ADR carries no schema authority of its own, only the protocol
  projections of an authority that lives elsewhere.
- ADR-0008's boundary is unchanged and still governs: a `cwl_context_memberships` claim,
  a SCIM extension attribute, or a SAML `AttributeValue` is a **carried fact**, not an
  authorization decision. Every relying party still validates issuer/signature/
  audience/expiry and applies its own tenant/resource ABAC before any RBAC read of
  these claims, exactly as ADR-0008 already requires for `org`/`workspace`/`role`.
- `org_member_observed` assertions (SCIM/SAML ingest) are never authorization-ready on
  arrival. A relying party or the PDP that treats `org_member_observed` as equivalent to
  `org_member_primary` violates this ADR and `context-graph-contracts` ADR-0003's
  no-promotion rule.

## Acceptance evidence (required before this leaves `Proposed`)

None yet — this ADR has no implementation. Before promotion to `Accepted`: a `Group`
resource RED-to-GREEN test suite in `scim.py` mirroring its existing `User` coverage;
a live Keycloak 26.3.2 acceptance run proving the `jsonType.label: "JSON"` mapper emits
a real nested array (not a quoted string) in both access and ID tokens, following
ADR-0009's own acceptance-evidence pattern; and at least one downstream RP's exact
claim-shape acceptance test before this is cited as deployed anywhere.

## References

Hunt, P., Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System for Cross-domain
Identity Management: Core schema* (RFC 7643). Internet Engineering Task Force.
https://doi.org/10.17487/RFC7643

Hunt, P., Grizzle, K., Ansari, M., Wahlstroem, E., & Mortimore, C. (2015). *System for
Cross-domain Identity Management: Protocol* (RFC 7644). Internet Engineering Task
Force. https://doi.org/10.17487/RFC7644

Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2023, December
15). *OpenID Connect Core 1.0 incorporating errata set 2*. OpenID Foundation.
https://openid.net/specs/openid-connect-core-1_0.html

Cantor, S., Kemp, J., Philpott, R., & Maler, E. (Eds.). (2005, March 15). *Assertions
and protocols for the OASIS Security Assertion Markup Language (SAML) V2.0* (OASIS
Standard, document identifier saml-core-2.0-os). Organization for the Advancement of
Structured Information Standards. https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

Keycloak Project. (2026). *Protocol mappers*. Retrieved September 2, 2026, from
https://www.keycloak.org/admin-api/protocol-mappers
