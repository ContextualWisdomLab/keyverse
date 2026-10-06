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
| [0014](0014-keyverse-keyvault-bounded-context.md) | Keyvault (namespaced encrypted-at-rest secrets store) is a separate bounded context from IdP identity/config, sharing only the KV pattern and auth/path-validation seams | Accepted |
| [0015](0015-keyverse-service-authorization-plane.md) | Service ABAC/RBAC stays its own Authorization Plane; continue PR #103 rather than duplicate it, and do not substitute generic Keycloak UMA for its hierarchical org-path requirement | Proposed |
| [0016](0016-keyverse-login-credential-store.md) | "Login Credential Store" = Keyvault (ADR-0014) plus each consuming service's own Anti-Corruption Layer, not a new bounded context | Accepted |

ADR numbering note: protected `main` currently ends at ADR-0008. ADR-0009 is
proposed in the open LineageWeave claim-profile PR, and ADR-0010 through
ADR-0012 are proposed in the open authorization-plane PR. ADR-0013 preserves
the next intended number without renumbering parallel work; it must be
reconciled after those PRs land, and none of the absent records is accepted
architecture on protected `main` yet. ADR-0014 through ADR-0016 (Keyvault,
service authorization plane, login credential store) are new as of
2026-09-02 and do not conflict with 0009–0013's reserved numbers.

## ADR triggers

Create or update an ADR for changes to authenticator policy, federation hub ownership, identity matching evidence, merge/tombstone semantics, SCIM authority, directory write/trust policy, RP credential/claim ownership, desired-state mutation order, persistent state, secret handling, or autonomous/release authority.

Each implementation PR should reconcile PRD/TRD/Architecture/UML/ERD/Threat/Test/Operability/Traceability and the relevant `docs/doctoring/`, `docs/papers/`, or `docs/operations/` research/standards/runbook record when those contracts move.
