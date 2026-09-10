# Keyverse Architecture Decision Record Index

`Accepted` means the decision governs architecture; it does not imply an active PR has merged or a customer deployment has completed acceptance.

Accepted ADRs 0001–0007 are expanded in place with Context, Decision,
Consequences, and APA 7th references. The shared bibliography is
[`docs/REFERENCES.md`](../REFERENCES.md). ADR 0008 remains the RP
authorization boundary and is not rewritten by that expansion.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-keycloak-hub.md) | Keep Keycloak/Keyverse as the ecosystem identity hub | Accepted |
| [0002](0002-passwordless-local-accounts.md) | Passwordless-first local accounts without password authenticator | Accepted |
| [0003](0003-identity-matching.md) | Exact external subject → verified email → explicit link matching precedence | Accepted |
| [0004](0004-desired-state-reconciliation.md) | Side-effect-free preflight plus intent/reconcile/re-observe/receipt lifecycle | Accepted |
| [0005](0005-secret-ownership.md) | Deployment/KV owns secrets; portable desired state remains secret-minimized | Accepted |
| [0006](0006-user-operation-lock.md) | Merge/link, SCIM full replacement, and supported `PATCH active=false` share one user-operation lock boundary | Accepted |
| [0007](0007-automation-authority.md) | Autonomous development remains separate from review/merge/release authority | Accepted |
| [0008](0008-keyverse-rp-authorization-boundary.md) | Every non-fork RP explicitly validates Keyverse identity and manages ABAC/RBAC at its own boundary | Accepted |
| [0013](0013-mcp-oauth-client-authorization.md) | Use Keycloak-backed authorization code plus PKCE and exact resource binding for MCP clients | Proposed |
| [0017](0017-keyverse-root-bootstrap-secret-transport.md) | Independent Keyverse custody and self-bootstrap; external KMS is optional and static file transport is not migration | Proposed |

ADR numbering note: protected `main` currently ends at ADR-0008. ADR-0009 is
proposed in the open LineageWeave claim-profile PR, ADR-0010 through ADR-0012
are proposed in the authorization-plane PR, ADR-0013 is the open MCP decision,
and ADR-0014 through ADR-0016 are reserved by the Key Vault foundation stack.
ADR-0017 records self-bootstrap and the 2026-09-10 owner correction of the
external-KMS/static-file direction without allocating a conflicting ADR number.
Every proposed record must be reconciled after its owning PR lands; an absent
record is not accepted architecture on protected `main`.

The implementation scope of #153 remains transport-only until the native
custody and credential-lifecycle acceptance in ADR-0017 is demonstrated. The
owner's requirement supersedes earlier proposed external-KMS prerequisites;
it does not promote any open PR to Accepted or erase its valid source delta.

## ADR triggers

Create or update an ADR for changes to authenticator policy, federation hub ownership, identity matching evidence, merge/tombstone semantics, SCIM authority, directory write/trust policy, RP credential/claim ownership, desired-state mutation order, persistent state, secret handling, root custody, self-bootstrap, or autonomous/release authority.

Each implementation PR should reconcile PRD/TRD/Architecture/UML/ERD/Threat/Test/Operability/Traceability and the relevant `docs/doctoring/`, `docs/papers/`, or `docs/operations/` research/standards/runbook record when those contracts move.
