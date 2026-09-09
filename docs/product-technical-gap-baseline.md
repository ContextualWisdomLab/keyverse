# Keyverse product and technical gap baseline

**Updated scope:** CWL Key Vault migration, 2026-09-09.
**Status:** observed evidence and open gaps, not a release acceptance record.
**Organization migration:** ContextualWisdomLab/.github#2063.

## Evidence map

The product baseline retains identity, federation, relying-party authorization,
SCIM, operational and release obligations alongside the new secret context.
A scoped vault repair must not remove those continuing acceptance obligations.

- [Key Vault implementation and gap register](keyvault_credential_gap_baseline.md):
  exact parent/source blobs, 42 local focused cases, root bootstrap and remaining
  workload/KMS/version/rotation/consumer gates.
- [Historical 2026-08-21 baseline](product-technical-gap-baseline-2026-08-21.md):
  preserved byte-for-byte; its PR counts, Checks and approval observations are
  historical, not fresh release evidence.
- [Identity and standards doctoring](doctoring/product-technical-gap-baseline.md):
  continuing protocol interpretation; it does not certify a running deployment.
- [Vault decision](adr/0014-keyverse-keyvault-bounded-context.md) and
  [operations](operations/keyvault.md): Proposed design and controlled migration.

## Current implementation evidence

Canonical vault #129 was inspected at
`0f10ac556a318c3c3f5ce7eab0802573ecce0c4c`. Its encrypted store and
metadata/write administrator API are not a released workload read API.
Child #151 implemented protected root bootstrap at
`4caafd0fa56b9ca377c93d78299bfe82dbec8faf`, with documentation at
`bc81fed1c3e9f431bc17c6f24ab36eb518cd2286`. No consumer was switched to this
unmerged branch and no production credentials were inspected or changed.

The first hosted run for that child was `34366116385`, merge revision
`02408cf12f940a2bd0cb55ccd9d0295b446e819b`. Realm and Compose validation,
locked dependency installation, Ruff, docstrings (100%) and compilation passed.
Documentation contracts failed 1/7 because the scoped rewrite removed explicit
RFC 9068/RFC 9207 obligations from this root index. Full service tests and
coverage were therefore skipped, not passed. This documentation repair restores
those active obligations without weakening or deleting the test. Any new head
requires fresh verification; predecessor successes are not reused as approval.

## Continuing product gates

### Identity and relying-party acceptance

Prove a controlled real login and token lifecycle, not just a Keycloak mapper
receipt. Every relying party verifies exact issuer, signature, allowed algorithm,
audience, subject, expiry, `iat`, exact resource and tenant before applying its
own purpose-bound access-control policy. Keyverse identity, the authorization
plane and secret custody retain separate bounded contexts. Unknown or ambiguous
membership fails closed; a raw header or decoded JWT is never verified identity.

### MCP protocol contract

The retained version-pinned baseline is MCP Authorization 2026-07-28; this is
not a claim that a later specification has been re-audited in this vault change.
RFC 9068 defines the JWT access-token profile used by the existing design:
verify the allowed token/header type, claims, signature, issuer, audience and
time bounds. RFC 9207 requires comparison of the authorization-response issuer
before accepting its code; an issuer mismatch rejects the authorization code.

Retain authorization code plus PKCE S256, exact redirects, RFC 8707 resource
binding, RFC 9728 protected-resource metadata, discovery, revocation and
verifier-unavailable negative tests. A future vault workload verifier must not
weaken this identity boundary or treat a generic administrator token as a
namespace-scoped workload credential. Real end-to-end MCP/resource acceptance
remains unclaimed by the bootstrap repair.

### Tenant, SCIM and persistent state

Downstream applications own tenant/resource/purpose enforcement and bounded
RBAC, not merely issuer-side role mappers. Preserve cross-tenant denial,
concurrent SCIM deactivation/merge locking, durable audit, schema compatibility,
PostgreSQL migration/rollback and backup/restore evidence. Local SQLite tests do
not establish those deployment guarantees.

### Key Vault and consumers

Keyverse owns secret custody, authorized resolution, versions, leases,
rotation/revocation and audit. Non-secret settings remain typed configuration.
The legacy bootstrap child rejects plaintext config-store roots and dotenv
fallback; its protected supervisor file is a root-only self-bootstrap exception,
not KMS/HSM custody or a second application-secret authority.

Complete Rust-native workload resolution, cryptographic context binding,
external KMS/HSM, versioned storage and lifecycle/restore tests before releasing
the owner API. Only then may CO use its existing CredentialBackend port and other
consumers retire their dotenv loaders with clean-install, outage, revocation,
rotation and rollback evidence. No sibling DB/source reads or mutable PR-head
runtime dependencies are permitted.

### Review, operation and release

Inventory, review, causal RED/fix/GREEN, exact-head checks, independent approval,
protected merge and immutable release remain the order of work. Preserve valid
predecessor delta and active writers. Queued, skipped, cancelled, stale and
rate-limited results are not GREEN evidence. Waiting for review is not permission
to bypass it, nor a reason to stop independent safe repair.

A release needs immutable artifacts, SBOM/provenance, deployment and recovery
acceptance, current coverage/docstrings and downstream contract verification.
Neither a document, an open PR, a local test count nor an issue is certification
of SOC 2/CSAP, commercial readiness or organization-wide migration completion.

## Protocol references retained from the governing baseline

Bertocci, V. (2021). *JSON Web Token (JWT) profile for OAuth 2.0 access tokens*
(RFC 9068). https://doi.org/10.17487/RFC9068

Meyer zu Selhausen, K., & Fett, D. (2022). *OAuth 2.0 authorization server issuer
identification* (RFC 9207). https://doi.org/10.17487/RFC9207

The source interpretations and remaining runtime limitations stay linked in the
identity and vault doctoring records above.
