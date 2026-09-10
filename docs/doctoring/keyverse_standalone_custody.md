# Keyverse independent custody: correction and evidence boundary

Date: 2026-09-10. Status: design correction, not executable KMS acceptance.

## Owner correction

The owner explicitly rejected mandatory external KMS/HSM reliance and rejected
`POSTGRES_PASSWORD_FILE` as equivalent to completing the dotenv migration.
Keyverse itself must be usable as a key-management and cryptographic trust
service. The software-only, hardware-backed and external-provider deployment
profiles require distinct, honest assurance statements.

## Exact source evidence

PR #153 was read at `cf8498dd33b7d64363a8359d76cab4cb47577ba9`, tree
`767564c02bbd4953f91e912c1b7ddaf2bc9fef91`. It is open and Draft. Its ADR-0017
requires host materialization and eventual external KMS/HSM custody; its PR
body identifies PostgreSQL `_FILE` and three static host-mounted bootstrap
credentials. That is transport, not a native issuer or key-service boundary.

PR #151 was read at `0fe44cfcda9cbd1cf2d81f4b9360630449ea3a70`, open and
Draft. Its root-file protection remains an interim compatibility repair and
cannot become a required external-custody architecture merely because its file
checks pass. Preserve its hardening, tests and migration/recovery protections.

The central rollout issue is ContextualWisdomLab/.github#2063. Its former
external-provider preference and work-package wording require reconciliation
with independent native custody, not a new duplicate tracking issue.

## Primary-source findings versus design choices

HashiCorp's seal documentation makes external seal-provider configuration
optional and describes quorum-based unseal. This supports the feasibility of
independent software-vault startup; it is not a mandate to depend on HashiCorp
or evidence that Keyverse implements its algorithms.

The Transit documentation distinguishes remote cryptographic operations and
key management from retrieving application secret values. That distinction
informs the proposed Keyverse key-operation port, non-exportable root/wrapping
keys, and separately authorized data-key export.

PostgreSQL 17 certificate authentication documents a trusted client-certificate
and database-user mapping path without password prompting. HashiCorp separately
documents dynamically generated PostgreSQL credentials. These establish viable
alternatives to one static password file. Actual Keycloak/driver integration,
issuance authority, renewal, revocation and existing-session termination still
require executable acceptance; no driver compatibility is assumed here.

NIST CMVP describes testing and validation for concrete cryptographic modules.
A software service, a compatible API, or use of a cryptographic library does not
by itself establish physical HSM protection or product validation.

## Verification and remaining source repair

This correction changes ADR text, its index and this evidence record only. It
does not implement native unseal, key operations, workload attestation,
PostgreSQL certificate/role provisioning or deployment. Existing Compose and
entrypoint source remain unaccepted compatibility work and must not be promoted
by this documentation commit. No credentials were read, migrated or rotated.

A local clone attempt failed at DNS resolution for github.com. Repository reads
and publication use the connected GitHub API instead. No local full checkout,
unit-test, cryptographic-test, hosted-GREEN or release claim is made here.

The source owner must reconcile ADR-0014, its operations and gap baseline, the
#153 Compose/entrypoint behavior, and all consumer assumptions before protected
integration. Native custody starts before the dependent Keycloak/database
plane; a consumer secret-string resolver cannot stand in for a non-exportable
key-operation port. The acceptance matrix in ADR-0017 remains unfulfilled until
real exact-version tests and independent security review demonstrate it.

## References

The complete APA-style primary-source bibliography is in
[ADR-0017](../adr/0017-keyverse-root-bootstrap-secret-transport.md#references-and-interpretation).
All external documentation was consulted on 2026-09-10. Architecture precedents
are not a choice of runtime dependency, license or cryptographic implementation.
