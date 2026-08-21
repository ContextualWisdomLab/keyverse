# Keyverse Documentation Map

Keyverse already has strong feature-specific specifications, doctoring, federation/onboarding, topology, and operations records. This index makes the cross-cutting product and architecture graph explicit without replacing those slice documents.

| Area | Canonical document |
|---|---|
| Product requirements | [`docs/PRD.md`](docs/PRD.md) |
| Technical requirements | [`docs/TRD.md`](docs/TRD.md) |
| Architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Topology | [`docs/topology.md`](docs/topology.md) |
| UML/runtime/authority flows | [`docs/UML.md`](docs/UML.md) |
| Logical/physical ERD | [`docs/ERD.md`](docs/ERD.md) |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| Test strategy | [`docs/TEST_STRATEGY.md`](docs/TEST_STRATEGY.md) |
| Operability/recovery/release | [`docs/OPERABILITY.md`](docs/OPERABILITY.md) |
| Requirements/evidence traceability | [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) |
| Architecture decisions | [`docs/adr/README.md`](docs/adr/README.md) |
| Federation onboarding | [`docs/federation-onboarding.md`](docs/federation-onboarding.md) |
| Authorization onboarding | [`docs/authorization-onboarding.md`](docs/authorization-onboarding.md) |
| RP onboarding | [`docs/rp-onboarding.md`](docs/rp-onboarding.md) |
| Account merge/unification | [`docs/merge-unification-flow.md`](docs/merge-unification-flow.md) |
| Standards/APA 7 evidence | [`docs/doctoring/`](docs/doctoring/) and [`docs/papers/`](docs/papers/) |
| Operations | [`docs/operations/`](docs/operations/) |
| Security reporting | [`SECURITY.md`](SECURITY.md) |
| Agent instructions | [`AGENTS.md`](AGENTS.md) |
| Agent context | [`CLAUDE.md`](CLAUDE.md) |
| Product overview | [`README.md`](README.md) |
| Change history | [`CHANGELOG.md`](CHANGELOG.md) |

## Maturity vocabulary

- **implemented-main** — present on protected main with source/tests.
- **active-PR** — implemented only on an open PR and not yet a protected-main claim.
- **deployment-owned** — private tenant/customer secret/configuration behavior owned by deployment controller/secret store.
- **external-system** — Keycloak/ADFS/LDAP/external OIDC/HR/IGA behavior not implemented by Keyverse itself.
- **planned** — accepted target without executable implementation.

Open PR #72 OIDC RP claim mapper profile and PR #74 hourly GitHub API remediation remain active-PR until merged. Keyverse's current protected-main desired-state/reconciliation capabilities are documented independently from those changes.