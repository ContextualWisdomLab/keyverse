# Keyverse Architecture Decision Record Index

`Accepted` means the decision governs architecture; it does not imply an active PR has merged or a customer deployment has completed acceptance.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-keycloak-hub.md) | Keep Keycloak/Keyverse as the ecosystem identity hub | Accepted |
| [0002](0002-passwordless-local-accounts.md) | Passwordless-first local accounts without password authenticator | Accepted |
| [0003](0003-identity-matching.md) | Exact external subject → verified email → explicit link matching precedence | Accepted |
| [0004](0004-desired-state-reconciliation.md) | Side-effect-free preflight plus intent/reconcile/re-observe/receipt lifecycle | Accepted |
| [0005](0005-secret-ownership.md) | Deployment/KV owns secrets; portable desired state remains secret-minimized | Accepted |
| [0006](0006-user-operation-lock.md) | Merge and SCIM full replacement share one user-operation lock boundary | Accepted |
| [0007](0007-automation-authority.md) | Autonomous development remains separate from review/merge/release authority | Accepted |

## ADR triggers

Create or update an ADR for changes to authenticator policy, federation hub ownership, identity matching evidence, merge/tombstone semantics, SCIM authority, directory write/trust policy, RP credential/claim ownership, desired-state mutation order, persistent state, secret handling, or autonomous/release authority.

Each implementation PR should reconcile PRD/TRD/Architecture/UML/ERD/Threat/Test/Operability/Traceability and the relevant `docs/doctoring/`, `docs/papers/`, or `docs/operations/` research/standards/runbook record when those contracts move.