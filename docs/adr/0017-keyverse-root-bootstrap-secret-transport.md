# ADR-0017: Independent Keyverse custody and self-bootstrap; files are not migration

**Status:** Proposed; owner requirement clarified, runtime acceptance outstanding.
**Date:** 2026-09-10.
**Related:** Keyverse #129, #151, #153; ContextualWisdomLab/.github#2063.

## Problem and correction

The owner requires Keyverse to replace dotenv-dependent secret management across
CWL and to be usable itself as the KMS/cryptographic trust service on which other
systems depend. A mandatory external vault or KMS would make Keyverse only an
adapter. Replacing a static dotenv password with a static mounted password does
not implement custody, authorization, rotation, revocation or audit.

The previous revision of this ADR, at
`cf8498dd33b7d64363a8359d76cab4cb47577ba9`, incorrectly selected protected host
files as the solution and required eventual external KMS/HSM custody. That
architecture direction is superseded by this correction. Its useful no-logging,
no-argv, no-dotenv-discovery and least-disclosure controls remain requirements;
no valid source delta or deployment data is discarded.

The same revision of PR #153 deletes `.env.example`, mounts three static host
files, uses `POSTGRES_PASSWORD_FILE`, and exports Keycloak passwords from an
entrypoint. These are implemented transport changes only. The producer of those
files has no implemented Keyverse lifecycle contract. The deployment-contract
tests check wiring; they do not prove Keyverse-managed credentials. Current
Compose still reflects that earlier design and is NOT accepted as the final
standalone profile. No rollout or completion may be inferred from a GREEN test
of that wiring.

## Alternatives and choice

1. Mandatory external KMS/HSM: reject as the default product dependency. Keep
   provider integration as an optional, explicitly selected protection profile.
2. Static credentials in a different file or Kubernetes Secret: reject as the
   target architecture. Files may only be a narrowly justified transport for a
   legacy client, never the authority or proof of migration.
3. Independent Keyverse custody with explicit initialization, seal/unseal,
   native key operations and governed workload credentials: selected direction.
   The implementation remains Proposed, not an accepted or released capability.

## Responsibility and product boundaries

Keyverse remains the canonical owner. Its identity/federation, authorization,
secret lifecycle, cryptographic key operations, and root custody are separate
bounded contexts with narrow interfaces. New key custody and cryptographic
runtime are implemented in Rust using reviewed cryptographic implementations;
do not create a new cipher, KDF or threshold scheme. Existing Python adapters
are compatibility surfaces, not the new cryptographic engine.

The custody core must be independently startable inside the Keyverse product.
Its sealed-state administration must not require a live Keycloak, a PostgreSQL
password supplied by that same locked vault, an external vault, or another
Keyverse deployment. Otherwise the circular dependency has only been moved.
Minimal local durable storage may contain encrypted key material, authenticated
metadata and public trust anchors, not the plaintext key that unlocks it. If a
relational backend is later attached, the bootstrap record and storage-connection
path must still pass the no-circular-dependency acceptance test.

Org/product domain truth is not moved here. `.github` owns reusable verification,
AppGuardrail owns source detection, and enterprise-architecture-core records the
cross-context map. Consumers use immutable released contracts, not this branch,
Keyverse source copies or cross-service SQL. Authorization-plane #103 remains
its existing owner line.

## Independent initialization and recovery

The standalone software profile generates root key material inside the custody
boundary with a cryptographically secure random source. It supports an explicit
lifecycle: uninitialized -> sealed -> unsealed -> sealed, with a separate
recovery/rekey workflow. Before unseal, only the authenticated local or pinned
administrative initialization/status/unseal surface is available; general
secret reads, key operations and credential issuance are denied.

A reviewed threshold-unseal profile is a suitable standalone design: independent
custodians receive protected shares during initialization and provide a quorum
through an authenticated/pinned channel. The service does not write the complete
unseal key or enough shares to reconstruct it into its own persistent storage,
repository, environment or backup. Quorum values are deployment-policy decisions,
not an invented fixed security score. Quorum unseal is NOT threshold signing:
it can reconstruct a key in the custody process and must be documented as such.

Protect initial enrollment against takeover; bind it to operator presence and a
verified instance fingerprint. Do not use trust-on-first-network-request, an
unverified JWT payload, a shared static admin password or disabling TLS as the
initial identity solution. Local operating-system peer identity may be one
explicit administration profile, not a network `trust` authentication rule.

A fully unattended restart requires a separately available unlocking factor.
That factor may be locally hardware-sealed or held by an independently governed
cluster quorum; it need not be an external cloud KMS. Without hardware, an
independent live quorum or operator input, this design does not promise both
unattended full-cluster cold recovery and protection from an attacker possessing
all host state. External KMS/HSM and a separate Keyverse deployment can be optional
unseal providers, but dependency cycles must be rejected and the standalone
profile must remain usable with those integrations absent.

Software, locally hardware-backed and externally backed profiles must report
their actual protection boundary. A software cryptographic service, including
one exposing a PKCS#11-compatible interface, is not automatically a physical
HSM, tamper-resistant appliance or FIPS-validated module. Any hardware/FIPS claim
requires evidence for the exact module, version, configuration and environment.

## Key operations are distinct from secret retrieval

Key management supports generation, controlled import, versions, cryptoperiods,
rotation, disablement, recovery and authorized destruction. Managed root,
wrapping and signing private keys are non-exportable through the normal API.
Clients use an opaque key handle and scoped encrypt/decrypt, wrap/unwrap,
sign/verify or MAC operation; they do not fetch every key as a string. Public
verification material may be published. Envelope data-key export is a separate,
explicitly authorized capability, not implied by permission to use the wrapping
key. Cryptographic context binds tenant, environment, purpose and key version.

Secret management separately handles values that an external protocol actually
requires, such as a provider API credential. Only the authorized execution
boundary receives necessary plaintext for the allowed operation and lifetime.
CO retains the provider-execution boundary; siblings do not receive copies of
model-provider keys. Returned plaintext cannot be retroactively erased from a
compromised caller by revoking a Keyverse lease; actual upstream revocation and
credential lifetime must be part of the contract.

## PostgreSQL: replace the credential authority, not the filename

`POSTGRES_PASSWORD_FILE` in PR #153 supplies the image's database initialization
password. It is not a per-workload database login lease, and it does not issue,
rotate or revoke credentials. Database administrative initialization and later
application logins are separate contracts.

For consumer logins, prefer Keyverse-issued, narrowly mapped short-lived client
certificates where the actual PostgreSQL driver supports the complete TLS/key
integration. PostgreSQL `cert` authentication checks trusted client certificates
and the database-user mapping without requesting a password. Certificate signing
keys stay in Keyverse; any workload private key has a separate generated-key,
proof-of-possession, transport and destruction policy. Merely replacing a
password file with a static private-key file is not acceptance.

Where certificate authentication is incompatible, an explicit dynamic-role
profile may issue short-lived, least-privilege PostgreSQL credentials via a
Keyverse-owned database adapter. The adapter is the intentional privileged
integration boundary, not permission for arbitrary consumers to query sibling
DBs. Issuance, renewal, disablement, cleanup and audit must reflect observed DB
state. No long-lived shared superuser password is returned to applications.

Neither certificate expiry nor password expiration is treated as proof that an
already-authenticated pooled connection has ended. Define and test revocation
for new connections AND existing sessions, including pool draining/termination,
maximum session lifetime, outage and reconnect behavior. The adapter must also
have a separately authenticated initial provisioning path so its own login does
not recursively require an unavailable credential lease.

Prefer direct client integration or authenticated local IPC. A driver-mandated
file is only an optional compatibility sink after verified Keyverse issuance:
short-lived scoped material, private ephemeral storage, explicit replacement
and cleanup, no source authority, and no fallback after lease invalidation.
The current static host mounts satisfy none of that lifecycle by themselves.

## Acceptance and current gaps

| Gate | Required executable evidence | Current disposition |
| --- | --- | --- |
| Standalone custody | Initialize, seal/unseal and operate with external KMS/vault access denied and Keycloak/database authentication dependencies unavailable | Not implemented by #153 |
| Bootstrap integrity | Reject duplicate initialization, wrong/insufficient/replayed shares, unauthorized enrollment and tampered bootstrap records | Required native owner work |
| Non-exportable key use | Authorized operations succeed; private-key export, wrong tenant/purpose/version, disabled key and audit failure deny correctly | Required native owner work |
| Recovery | Full cold restart and restore work under the declared custody profile without plaintext unlock material in persisted state | Required native owner work |
| PostgreSQL lifecycle | Correct real driver/DB login, wrong-role denial, expiry, rotation, revocation of new and existing sessions, reconnect and cleanup | `_FILE` wiring is not acceptance |
| Client compatibility | Any ephemeral materialization is traceable to a valid issued lease and fails closed without static fallback | Current host files remain a gap |
| Consumer migration | Released owner version + exact consumer revision + real clean startup/outage/recovery evidence | Not delivered by deleting `.env.example` |

Keep #153 Draft. Do not close or discard #129/#151/#153 to conceal the gap.
Their existing regression/security controls remain valuable, but native custody
and lifecycle must replace or explicitly confine the compatibility behavior
before deployment. PRD/TRD/UML/ERD/operability and the product gap baseline must be
reconciled across those owner stacks before protected integration and release.

## References and interpretation

HashiCorp. (n.d.-a). *Seal stanza*. https://developer.hashicorp.com/vault/docs/configuration/seal

HashiCorp. (n.d.-b). *Seal/Unseal*. https://developer.hashicorp.com/vault/docs/concepts/seal

HashiCorp. (n.d.-c). *Transit secrets engine*. https://developer.hashicorp.com/vault/docs/secrets/transit

HashiCorp. (n.d.-d). *PostgreSQL database secrets engine*. https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql

PostgreSQL Global Development Group. (n.d.). *Certificate authentication (PostgreSQL 17)*. https://www.postgresql.org/docs/17/auth-cert.html

National Institute of Standards and Technology. (n.d.). *FIPS 140-3 standards*. https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards

These are primary-source architectural precedents and assurance boundaries,
not dependencies adopted by this ADR. They do not demonstrate that Keyverse has
implemented or passed the target controls. See the associated doctoring record.
