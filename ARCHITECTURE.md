# Keyverse Architecture

## Purpose

Keyverse is the ContextualWisdomLab identity control plane. It operates as a
standalone Keycloak-based identity provider and as a reusable module in CWL,
Naruon, and sibling products. The design keeps portable realm configuration,
customer-specific federation, account unification, SCIM provisioning, and
review/development automation behind explicit trust boundaries.

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
        Keycloak 26             FastAPI service       KV-render/apply owner
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
- user, session, role, and group system of record.

The portable realm contains no customer-specific SAML, OIDC, or LDAP source.

### Account-unification service

- account inspection, linking, and survivor-wins merge;
- verified-email and exact-subject match policy;
- tombstone-safe SCIM provisioning;
- password-free registration action-email flow;
- SAML/OIDC desired-state validation and reconciliation;
- LDAP/Active Directory component preflight;
- audit and user-operation lock boundaries.

The core merge and SCIM layer depends on the narrow `AdminApi` protocol.
Product extensions are isolated behind `ProductAdminApi`; deterministic LDAP
preflight does not require either protocol or any network client.

### Deployment controller

- resolves every `{{placeholder}}` from KV or a secret manager;
- owns private bearer, bind, client-secret, and certificate files;
- invokes Keyverse preflight endpoints;
- applies SAML/OIDC desired state through Keyverse;
- applies the current LDAP component payload directly to private Keycloak Admin
  REST only after Keyverse preflight succeeds;
- enforces approved-host egress, TLS trust, and rollback.

### Persistence

- Keycloak state: PostgreSQL;
- Keyverse configuration: `idp_config_entries` or the configured KV backend;
- merge audit: `account_merge_audit`;
- cross-process user mutation lock sidecar:
  `user_operation_lock_state`.

Database objects use descriptive two-word-or-longer snake_case names.

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

### LDAP and Active Directory

The first LDAP increment is a preflight boundary around the existing Keycloak
component representation:

```text
private rendered component
    -> authenticated local preflight
    -> redacted readiness receipt
    -> deployment-owned private Keycloak component apply
```

Preflight performs no DNS lookup, socket connection, bind, search, store write,
or Keycloak call. It requires LDAPS, read-only operation, no trusted-email
auto-linking, no Kerberos, bounded timeouts, valid RFC 4514 DN syntax, and a
closed config shape. Desired-state CRUD and reconciliation are a later module.

## Account and provisioning invariants

1. Matching precedence is exact `(identity_provider, subject)`, then verified
   email, then explicit operator link.
2. Unverified email never authorizes linking or merge.
3. Merge and SCIM replacement share one user-operation lock.
4. Merged duplicates remain disabled tombstones with a survivor pointer.
5. Registration creates no password and rolls back if enrollment initialization
   fails.
6. Privileged dynamic path segments are validated before transport.
7. Secrets never appear in operator responses, logs, command arguments, source,
   or templates.

## Deployment modes

### Standalone

`docker-compose.yml` or `helm/cwl-idp` provides Keycloak, PostgreSQL, and the
admin service with readiness probes and persistent audit/lock storage.

### CWL/Naruon module

Parent systems may include the Compose definition, depend on the Helm chart, or
call the stable HTTP and protocol boundaries. Parent systems must not bypass
Keyverse validation or reach the private Keycloak Admin REST API except through
the deployment-controller contract.

## Automation boundaries

- The hourly PR steward advances only trusted same-repository PRs with exact-head
  approvals and required Checks.
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

- `docs/superpowers/specs/` — approved feature architecture;
- `docs/superpowers/plans/` — executable implementation plans;
- `docs/doctoring/` — standards interpretation and APA 7th traceability;
- `docs/operations/` — operator procedures and recovery;
- `CHANGELOG.md` — user-visible unreleased and released changes.
