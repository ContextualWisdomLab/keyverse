# Keyverse Architecture

## Purpose

Keyverse is the ContextualWisdomLab identity control plane. It operates as a
standalone Keycloak-based identity provider and as a reusable module in CWL,
Naruon, and sibling products. The design keeps portable realm configuration,
customer-specific federation, account unification, SCIM provisioning, relying-
party lifecycle, and review/development automation behind explicit trust
boundaries.

## Runtime topology

```text
                              public / WAF edge
                                      |
                 +--------------------+--------------------+
                 |                                         |
          Keycloak OIDC/SAML                         Admin + SCIM API
                 |                                         |
                 +--------------------+--------------------+
                                      |
                         idp_edge_network (bounded)
                                      |
                +---------------------+---------------------+
                |                     |                     |
        idp_engine              account_unification   deployment controller
        Keycloak 26             FastAPI service       KV-render/secret owner
                |                     |
                +----------+----------+
                           |
                  idp_internal_network
                           |
                     idp_database
                     PostgreSQL 17
```

TLS normally terminates at the WAF edge for public Keycloak endpoints. The
Keycloak Admin REST API, database, bootstrap store, and deployment controller
remain private. The FastAPI operator and SCIM surfaces are exposed only through
explicit WAF policy.

## Component responsibilities

### Keycloak engine

- portable `cwl` realm import;
- OIDC/OAuth and SAML protocol execution;
- passwordless WebAuthn authentication;
- external identity-provider brokering;
- LDAP user-storage components;
- OIDC relying-party clients;
- user, session, role, and group system of record.

The portable realm contains no customer-specific SAML, OIDC, LDAP source, or
application relying-party registration.

### Account-unification service

**PR103 source maturity:** PR #103 is active-PR, unmerged candidate source:
hierarchical authorization plane, start-login helper, and programmable
application tokens are not protected-main or deployed readiness. Descriptions
of those modules below retain candidate design and implementation boundaries;
they do not claim protected integration, issuer acceptance, or membership authority.

- account inspection, linking, and survivor-wins merge;
- verified-email and exact-subject match policy;
- tombstone-safe SCIM provisioning;
- password-free registration action-email flow;
- SAML/OIDC identity-provider desired-state validation and reconciliation;
- LDAP/Active Directory component preflight and desired-state reconciliation;
- OIDC relying-party preflight and secret-free desired-state reconciliation;
- audit and user-operation lock boundaries;
- hierarchical software-unit, menu, inheritance, and SSO-combination
  authorization decisions consumed from Orgmetra assignment snapshots;
- app start-login / IdP discovery helper for relying parties;
- hashed programmable application tokens scoped to one software unit and API.

The hierarchical authorization router carries the existing operator bearer and
privileged-path dependencies itself, so an embedding application cannot make
grant administration public by mounting the module without the application
factory's outer dependency list. The operator credential is a coarse
operator-admin boundary; ``actor_identity_id`` on a grant is policy metadata,
not an end-user principal extracted from that bearer request.

The core merge and SCIM layer depends on the narrow `AdminApi` protocol.
Product extensions are isolated behind `ProductAdminApi`; relying-party client
CRUD is further narrowed behind `RelyingPartyAdminApi`. Deterministic preflight
modules require neither protocol nor any network client.

Menu decisions capture software-unit and menu namespace rows through one
`KvStore.get_all_namespaces` read. SSO-combination decisions likewise capture
the combination definitions and software-unit grants together through that
same seam. Both paths validate every captured row before invoking the unchanged
canonical PDP and preserve legacy grant-key sorting. Combination selection uses
validated name and tenant, with the existing missing/ambiguous 404/409 errors.
SQLite uses one parameter-bound SELECT; in-memory storage uses one store lock.
The service/SQLite instance RLocks do not serialize independent connections or
processes. This is read coherence, not a grant-write manifest, current-membership
verification, or revocation of already admitted operations.

### Deployment controller

- resolves every `{{placeholder}}` from KV or a secret manager;
- owns private bearer, bind, client-secret, and certificate files;
- invokes Keyverse preflight and desired-state endpoints;
- applies SAML/OIDC identity-provider desired state through Keyverse;
- applies LDAP and OIDC relying-party desired state through Keyverse;
- provisions confidential relying-party credentials through a separate approved
  secret-management port;
- enforces approved-host egress, TLS trust, controlled acceptance tests, and
  rollback.

### Persistence

- Keycloak state: PostgreSQL;
- Keyverse configuration: `idp_config_entries` or the configured KV backend;
- directory intent and receipt:
  `directory_federation_sources`, `directory_federation_apply_receipts`;
- relying-party intent and receipt:
  `relying_party_sources`, `relying_party_apply_receipts`;
- merge audit: `account_merge_audit`;
- cross-process user mutation lock sidecar:
  `user_operation_lock_state`;
- hierarchical authorization grants:
  `authorization_software_unit_grants`, `authorization_menu_grants`;
- SSO combination scopes: `authorization_sso_combination_scopes`;
- hashed programmable tokens: `application_access_tokens`.

Database objects and namespaces use descriptive two-word-or-longer snake_case
names.

## Federation boundaries

### SAML and external OIDC

The Keyverse federation registry is desired state:

```text
private rendered payload
    -> authenticated side-effect-free preflight
    -> KV/DB desired-state write
    -> Keycloak reconciliation
    -> redacted status
```

Validation never fetches metadata or discovery documents. Deployment egress
policy and Keycloak perform remote interaction only after explicit apply.
Reconciliation compares desired observable fields exactly; the fixed Keycloak
mask for the known non-observable `clientSecret` field is the sole exception and
does not prove secret equality. Missing, changed, or unknown fields remain
drift.

### LDAP and Active Directory

Directory sources use a separate private desired-state lifecycle:

```text
private rendered component
    -> authenticated local preflight
    -> KV/DB private desired state
    -> exact Keycloak component reconciliation
    -> redacted observable status
    -> controlled bind/search/login evidence
```

Preflight performs no DNS lookup, socket connection, bind, search, store write,
or Keycloak call. It requires LDAPS, read-only operation, no trusted-email
auto-linking, no Kerberos, bounded timeouts, valid RFC 4514 DN syntax, and a
closed config shape. Reconciliation stores intent before network I/O, fails
closed on duplicates, re-observes mutations, and deletes remote-first.

### OIDC relying-party clients

Relying-party registration is deployment data rather than portable realm code:

```text
secret-free rendered client representation
    -> authenticated local Keyverse preflight
    -> KV/DB desired state
    -> exact Keycloak client reconciliation
    -> observable apply receipt
    -> separate confidential-secret placement
    -> controlled login/logout acceptance evidence
```

The preflight route has no KV, Keycloak, DNS, HTTP, secret-generation, or file
side effect. It enforces authorization code plus PKCE `S256`, exact HTTPS
redirect/origin/logout policy, public/confidential client consistency, bounded
token metadata, and an exact portable scope set.

An optional closed `protocolMappers` profile carries exactly one self-pinned
`oidc-audience-mapper` plus zero to three canonical hardcoded claims named
`role`, `org`, and `workspace`. Mapper count, names, classes, destinations,
claim values, and ordering are bounded; scripts, user attributes, groups, regex,
arbitrary claims, unknown fields, and credential material are rejected.
`deploy/templates/oidc-rp-naruon.json` is the reviewed public-client instance of
that profile. Its routing claim values are deployment data and must not contain
credentials or personal secrets.

Stateful reconciliation keys intent by validated `clientId`, classifies zero,
one, or multiple exact Keycloak clients, and never mutates duplicates. Create or
update is re-observed before a canonical receipt is written. Delete is remote-
first. For mapper comparison, Keyverse ignores only a valid generated mapper
`id`, canonicalizes the known mapper order, revalidates the closed shape, and
treats unknown, malformed, duplicate, or semantically changed mappers as drift.
The accepted representation has no client-secret field; credential provisioning
remains an independent secret-management responsibility.

Native loopback/private-use redirects, different resource audiences, and claim
expansion beyond `role`, `org`, and `workspace` remain separate reviewed
profiles.

Each downstream RP is a separate trust boundary. The RP must validate the
Keyverse issuer, signature/algorithm, expiry, subject, and audience, map the
verified tenant (`org`/deployment mapping), apply resource and purpose ABAC,
and then apply bounded role/scope/group RBAC. A registered client, accepted
mapper receipt, or Keyverse PDP decision never grants authorization by itself;
see ADR-0008 for the non-fork application matrix and remediation gates.
ADR-0010 adds issuer-side hierarchical attributes (`group_company`,
`legal_entity`, `business_unit`, `team`, `person`, `org_path`) and decisions.
Those names are distinct from the unmerged LineageWeave `role`/`org`/`workspace`
profile reserved as ADR-0009 on PR #100. Orgmetra remains employment truth;
Keyverse binds an opaque subject and does not copy the Orgmetra tree.

Relying applications start brokered login through the Keyverse start-login
helper (ADR-0011) and may present software-unit-scoped programmable tokens
(ADR-0012) that are hashed at rest, never inherit org-tree grants, and cannot be
rotated after revocation, prior rotation, or expiry. Rotation compares the captured predecessor and absent replacement while writing
both records atomically. SQLite uses a short `BEGIN IMMEDIATE` transaction;
memory uses one store lock. A unique lifecycle generation distinguishes repeated
retirements even at the same timestamp. Audit runs after that transaction closes,
not atomically with the database. Audit failure restores the predecessor only
when the exact written pair is still current; conflicts preserve independent
retirements and remove only a still-owned replacement. Storage cleanup errors
preserve the original audit error and require operator recovery.

Rotation emits one `application_token_rotated` event correlated to the successor.
Its existing `application_token_id` and `lifecycle_status_code` describe the
successor (active at cutover); `replaced_token_id` and
`replaced_token_lifecycle_status_code` describe the captured predecessor row
written by that cutover (rotated). IDs and lifecycle codes are non-secret product
data. These are historical captured states, not a guarantee of current lifecycle.
Issue/revoke payload shapes are unchanged. Generic `events_for` still matches
only `audit_id` exactly; predecessor metadata does not provide predecessor
lineage retrieval. Audit and KV remain non-atomic.

The runtime PAT router contains request-schema validation before the endpoint.
It returns a fixed HTTP 422 without serializing submitted values, keys, or error
locations, including when another application embeds that router directly.
Authentication and non-validation service failures retain their existing gates.

## Account and provisioning invariants

1. Matching precedence is exact `(identity_provider, subject)`, then verified
   email, then explicit operator link.
2. Unverified email never authorizes linking or merge.
3. Merge, SCIM replacement, and `PATCH active=false` deprovisioning share one user-operation lock.
4. Merged duplicates remain disabled tombstones with a survivor pointer.
5. Registration creates no password and rolls back if enrollment initialization
   fails.
6. Privileged dynamic path segments are validated before transport.
7. Secrets never appear in operator responses, logs, command arguments, source,
   or desired-state templates.
8. Preflight readiness is not reported as deployment or login success.
9. Mutation receipts are written only after exact live re-observation.
10. Mapper configuration is issuer-side evidence only; downstream token
    signature, issuer, expiry, and audience validation remain separate runtime
    acceptance boundaries.

## Deployment modes

### Standalone

`docker-compose.yml` or `helm/cwl-idp` provides Keycloak, PostgreSQL, and the
admin service with readiness probes and persistent audit/lock/configuration
storage.

### CWL/Naruon module

Parent systems may include the Compose definition, depend on the Helm chart, or
call the stable HTTP and protocol boundaries. Parent systems must not bypass
Keyverse validation or reach private Keycloak Admin REST except through an
explicitly documented deployment-controller responsibility.

## Automation boundaries

- Protected PR maintenance belongs to the organization's central
  `pr-review-merge-scheduler.yml`; Keyverse's local hourly steward was removed
  in #140. Exact-head approvals and required Checks remain mandatory. The local
  product-development workflow does not own review or merge authority.
- The hourly product-development workflow runs OpenCode through
  `NVIDIA_NIM_API_KEY`, not Copilot Agent Tasks or `COPILOT_GITHUB_TOKEN`.
- The model workspace has no Git metadata, GitHub credential, Actions OIDC,
  publication token, or upstream NIM credential.
- Generated text patches are bounded, digest-sealed, independently verified on
  a fresh checkout, and published only as a draft PR.
- Existing review agents and their credential system remain independent.
- Neither automation path may self-approve, bypass protection, merge unverified
  work, tag, or publish a release.

## Quality and release gates

- Ruff and Python compilation;
- production docstrings: 100%;
- production statement coverage: 100%;
- production branch coverage: 100%;
- realistic behavioral, concurrency, protocol, and deployment tests;
- package, realm, Compose, Helm, and template validation;
- CodeQL, Semgrep, dependency and security scanning;
- current-head review and unresolved-thread gates;
- `CHANGELOG.md`, version, image digest, SBOM, provenance, and rollback evidence
  before release.

## Decision records

Detailed decisions and evidence are maintained under:

- `docs/adr/` — accepted architecture decisions (0001–0008 plus 0010–0012;
  0009 reserved for the unmerged LineageWeave profile);
- `docs/superpowers/specs/` — approved feature architecture;
- `docs/superpowers/plans/` — executable implementation plans;
- `docs/doctoring/` — standards interpretation and APA 7th traceability;
- `docs/operations/` — operator procedures and recovery;
- `CHANGELOG.md` — user-visible unreleased and released changes.

## Explicit tenant-required PAT rotation lineage (private PR103 candidate)

`ApplicationTokenService.rotation_audit_for(token_id, tenant_deployment_id=tenant)`
reads historical rotations through a separate optional typed audit capability.
Both inputs are required exact strings: token IDs are `tok-` plus 16 lowercase
hex digits and tenants use the issuing service's slug grammar. The service does
not consult KV, mint credentials, append events, or expose an HTTP route.
Tenant scope restricts data; the shared operator boundary is not per-tenant
membership authorization. Stored actor metadata is not an authenticated human
principal. Future HTTP exposure requires a separately reviewed privileged route,
never runtime verification or the generic merge audit route.

Memory copies rotation rows under one lock. SQLite captures them with one bound
SELECT in physical append order. Both validate **every captured rotation before
selecting tenant or token**, deliberately failing all reads on a corrupt rotation
in any tenant. This is an explicit availability tradeoff, not per-tenant corruption
isolation. Malformed nonrotation JSON stays opaque under generic exact correlation.
Unknown keys, partial/null lineage, duplicate JSON keys, nonfinite constants and
scalar exponent overflow, invalid types and contradictory metadata fail closed.

Results are closed frozen DTOs with an ordered tuple of secret-free events and
an exact Boolean `predecessor_lookup_complete`. The current six-key legacy payload
projects as `legacy_missing` with null predecessor fields; any requested-tenant
legacy row makes completeness false, including on an empty/unrelated lookup.
Other-tenant legacy rows do not affect that flag. A modern row projects recorded
successor-active/predecessor-rotated historical states. Prefix, hash, plaintext,
capabilities and raw payload JSON are not projected. Allowed opaque actor/identifier
metadata is not a guarantee against a malicious caller placing secrets there.

Successor OR recorded predecessor matches once per physical row. A→B→C gives B
its two adjacent events, A and C only their adjacent event; no transitive walk or
correlation-ID deduplication occurs. Physical duplicates remain visible. Generic
`AuditSink` enumeration and `AuditLogger.events_for` exact bytes/semantics are
unchanged; rotation still appends only one successor-correlated event.

Custom reader output is revalidated at logger and service boundaries for exact
shape, event semantics, tenant, ID match and contradictory legacy completeness.
Those facades cannot prove a custom reader captured all unseen storage rows.
Unsupported readers and unavailable storage raise fixed typed errors, never empty
success. Errors omit raw driver/validation details and raw cause/context; this does
not claim erasure of temporary interpreter memory or traceback locals. BaseException
interruption is not caught.

A post-capture independent append appears on the next read, not the current one.
Instance locks do not lock independent connections/processes. Reads scan and
validate all stored rotations, O(rotation rows), without JSON1, DDL/index changes,
pagination, truncation, cache or a resource-bound promise. Completeness describes
legacy coverage of that captured set, not retention, audit loss, current validity,
or authenticated evidence. KV and audit remain non-atomic; a read between cutover
and append can return no row. Audit append-then-error and crash uncertainty remain.

The repository-discoverable `test_pat_rotation_audit_read.py` covers real memory
and SQLite close/reopen, actual service issue/rotate, query-before-access, strict
JSON/metadata, legacy/cross-tenant/facade controls, secret/error containment and
independent committed append barriers without sleeps. First-GREEN characterization
of already working boundaries is distinguished from reader behavioral RED→GREEN.
Local private results do not establish independent whole-union review, protected
integration, issuer acceptance or deployment readiness.

### F1/F2 containment successor (private, pending whole-source review)

The custom typed-error code is acquired once under an ordinary-Exception guard;
only exact builtin strings in the existing vocabulary survive. Malformed,
missing or failing-property codes become fixed `storage_unavailable`, without
formatting raw args/str/repr. Fixed errors are raised after handlers exit and
carry no original cause/context; BaseException interruptions remain uncaught.
Memory checks exact AuditEvent/discriminator shape before filtering and the
rotation decoder guards acquisition of all seven stored fields. Missing fields
or ordinary descriptor failures produce fixed `corrupt_rotation_event`, never
silent row loss. Nonrotation JSON, global rotation-before-selection policy,
generic enumeration and service delegation remain unchanged. These controls
cover deliberately malformed stored-memory objects, not physical SQLite damage.
Permanent regressions are in `test_pat_rotation_containment.py`; historical
NONPASS remains retained until fresh independent accumulated-source review.
