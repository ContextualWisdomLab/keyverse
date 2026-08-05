# LDAP Directory Desired-State Reconciliation — Doctoring Record

## Scope

This record documents Keyverse's durable lifecycle for a rendered Keycloak LDAP
user-storage component. It covers validation, private desired-state storage,
exact component discovery, create/update/delete ordering, rebuild reconciliation,
redacted status, and failure recovery.

It does not claim to validate a live LDAP bind, directory search, certificate
chain, DNS answer, schema, replication topology, or login service level.

## Evidence categories

The implementation separates the following evidence classes:

- **Standards requirements** — LDAP protocol, authentication, information model,
  distinguished-name, and filter semantics from the RFC 4511 family.
- **Vendor behavior** — Keycloak Admin REST component CRUD and LDAP provider
  configuration.
- **Product policy** — Keyverse's LDAPS-only, read-only, no-Kerberos,
  no-trusted-email first profile and duplicate fail-closed behavior.
- **Measured evidence** — repository tests, exact-head coverage, package and
  deployment validation, and GitHub security checks.
- **Assumptions** — one active process-local reconciler per deployment until a
  shared lock backend exists.
- **Limitations** — live bind-secret bytes are not observable through Keycloak,
  so current secret equality cannot be proven.

No formal RFC, NIST, SLSA, or Keycloak conformance claim is made.

## Stable desired identity

Keycloak generates component IDs. A generated ID can change after realm import,
restore, migration, or component recreation, so Keyverse does not treat it as
the desired-state key.

Stable desired identity is the conjunction of:

- validated component `name`;
- `providerId=ldap`; and
- `providerType=org.keycloak.storage.UserStorageProvider`.

Reconciliation classifies the exact live set:

- zero matches → create one component;
- one match → compare observable state and update when required;
- more than one match → `ambiguous`, with no mutation.

The component ID is returned only as diagnostic operational state.

## Storage and receipt model

Private desired state is serialized into the existing KV abstraction under:

```text
directory_federation_sources
```

The last successfully applied private revision is represented by a canonical
SHA-256 digest under:

```text
directory_federation_apply_receipts
```

Both names are descriptive multi-word snake_case. The underlying standalone
SQLite object remains `idp_config_entries`; no new database schema is introduced.

The digest is calculated over alias-preserving JSON with sorted object keys and
compact separators. Equivalent mappings therefore produce one stable receipt
regardless of request key order. The receipt contains no reversible credential
material and is not an authentication secret.

## Secret-observation contract

Keycloak does not return the stored bind credential in a form that can prove
byte equality. Keyverse therefore reports:

```text
secret_observation = not_observable
```

`in_sync` requires:

1. exactly one live component;
2. every observable non-secret desired field matches; and
3. the canonical private desired revision matches Keyverse's last successful
   apply receipt.

This is evidence that Keyverse last applied the exact private revision, not a
claim that an administrator has not changed the secret out of band. Secret
rotation changes the canonical private revision and forces one update even when
all observable fields are unchanged.

## Locking and failure semantics

Two process-local locks have separate responsibilities:

- the state lock protects KV read, write, delete, snapshot, and receipt access;
- the convergence lock serializes create/update/delete/reconcile decisions.

Keycloak network requests execute only after the state lock is released. This
prevents a slow or unavailable Admin REST endpoint from blocking local
configuration snapshots.

Desired state is stored before a PUT convergence attempt. Temporary Keycloak
failure therefore preserves operator intent and yields a bounded status:

- `unavailable` for observation failure;
- `apply_failed` for create/update failure;
- `ambiguous` for duplicate exact components.

Deletion is remote-first. Local desired state and its receipt are removed only
after the exact remote component is absent or successfully deleted. A remote
delete failure retains recovery data.

## LDAP standards relationship

RFC 4511 defines LDAP protocol operations and result behavior. RFC 4513 defines
authentication and security mechanisms and explains why authentication material
requires confidentiality protection. The inherited preflight therefore accepts
only LDAPS locations in the first product profile.

RFC 4512 defines LDAP descriptors and numeric object identifiers used in the
component's attribute and object-class fields. RFC 4514 defines the string
representation of distinguished names. Keyverse validates a bounded lexical
profile without canonicalizing or comparing DN equivalence because those
operations depend on directory schema and matching rules.

RFC 4515 defines search-filter string representation. The first profile does not
accept a custom filter, avoiding an additional parser and operator-controlled
filter-injection surface. A later filter feature requires its own RFC 4515 parser,
realistic tests, and security review.

## Keycloak vendor relationship

Keycloak Admin REST exposes realm component collection and individual component
operations. Keyverse uses the collection with fixed user-storage component type
and validated name, then uses only validated opaque component IDs for individual
update and delete paths.

The component adapter reuses the existing Keycloak HTTP client and one-shot 401
reauthentication boundary. It does not create a second bearer-token cache.

The first Keyverse profile allows Keycloak's documented directory vendor values
but fixes mutation policy to `READ_ONLY`, disables registration sync, Kerberos,
and trusted email, and requires truststore use and bounded timeouts. These are
Keyverse product policies, not assertions that other Keycloak modes are invalid.

## Verification contract

The repository proves the lifecycle with realistic Active Directory payloads
and adversarial cases:

- empty-realm create;
- idempotent repeated PUT;
- private credential rotation;
- observable timeout drift repair;
- Keycloak outage with retained desired intent;
- realm-rebuild recreation;
- duplicate fail-closed behavior;
- remote-first delete failure and success;
- deterministic sorted redacted inventory;
- malformed stored-state handling without reflection;
- blocked remote call while another stored-state read reaches its own network
  boundary;
- authenticated HTTP CRUD and reconcile;
- canonical receipt independence from JSON key order;
- fixed component query parameters, Location parsing, unsafe component-ID
  rejection, exact update/delete routes, and malformed list responses.

Exact completion requires:

- Ruff;
- Python compilation;
- production docstrings 100%;
- production statement coverage 100%;
- production branch coverage 100%;
- complete pytest;
- package build;
- realm, Compose, and template validation;
- CodeQL, Semgrep, Security Scan, current-head review, zero unresolved threads,
  and protected merge policy.

## Modularity

The same HTTP and representation contract supports:

- standalone Keyverse with SQLite-backed KV;
- CWL platform KV/DB integration; and
- Naruon or sibling deployment controllers embedding the module.

The pure preflight remains independently callable. Stateful reconciliation
requires only the existing `KvStore` and `ProductAdminApi` boundaries. No LLM,
`NVIDIA_NIM_API_KEY`, `COPILOT_GITHUB_TOKEN`, or review-agent credential is used
for deterministic directory logic.

## Residual risk and follow-up

- Multiple Keyverse replicas need one active reconciler until a shared
  advisory-lock implementation is added.
- Live credential and certificate correctness require controlled post-apply
  tests.
- Out-of-band secret changes cannot be detected from Keycloak's redacted view.
- Manual component creation can cause an `ambiguous` hold requiring operator
  cleanup.
- A future scheduler should add bounded retry/backoff and explicit reconciliation
  metrics without hiding persistent failure.
- A release still requires exact-main E2E, immutable image digest, SBOM,
  provenance, backup/restore, rollback rehearsal, and operational SLO evidence.

## References — APA 7th

Harrison, R. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Authentication methods and security mechanisms* (RFC 4513). Internet
Engineering Task Force. https://doi.org/10.17487/RFC4513

Keycloak. (n.d.-a). *Keycloak Admin REST API*. Retrieved August 5, 2026, from
https://www.keycloak.org/docs-api/latest/rest-api/index.html

Keycloak. (n.d.-b). *Server Administration Guide: LDAP and Active Directory*.
Retrieved August 5, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
The protocol* (RFC 4511). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4511

Smith, M., & Howes, T. (2006). *Lightweight Directory Access Protocol (LDAP):
String representation of search filters* (RFC 4515). Internet Engineering Task
Force. https://doi.org/10.17487/RFC4515

Zeilenga, K. (Ed.). (2006a). *Lightweight Directory Access Protocol (LDAP):
Directory information models* (RFC 4512). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4512

Zeilenga, K. (Ed.). (2006b). *Lightweight Directory Access Protocol (LDAP):
String representation of distinguished names* (RFC 4514). Internet Engineering
Task Force. https://doi.org/10.17487/RFC4514
