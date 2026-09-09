# ADR-0016: "Login Credential Store" is Keyvault plus per-service ACLs, not a new bounded context

**Status:** Proposed (consumer migration and workload-read contract remain unimplemented)
**Date:** 2026-09-02
**Updated:** 2026-09-10

## Context

The owner asked that Keyverse also serve as a "Login Credential Store." Read
literally against Keyverse's passwordless-first direction, this cannot mean a
second end-user password database. The relevant category is **service-account /
machine credentials**: API keys, service-to-service tokens, and third-party
credentials that CWL services need for outbound integrations.

Two ecosystem capabilities must remain distinct:

1. PR #103's programmable application tokens are Keyverse-issued credentials
   for callers authenticating **to** Keyverse-fronted resources. They are an
   inbound identity/authorization concern.
2. `contextual-orchestrator`'s `CredentialBackend` is the consumer-side seam for
   provider credentials used **outbound**. It currently owns its own backend and
   credential semantics.

The organization-wide 2026-09-09 direction now makes Keyverse the canonical
secret-lifecycle authority and retires `.env` as a credential authority. That
does not move every consumer's credential taxonomy into Keyverse: DDD ownership
still requires a narrow storage/resolution contract and a consumer ACL.

## Decision

- **Keyvault (ADR-0014) owns secret custody and lifecycle.** A service credential
  is stored under an opaque namespace/key/version reference; Keyverse owns
  encryption, versions, rotation/revocation, leases, authorization and access
  audit, not the consumer's business meaning.
- **Each consuming service keeps its Anti-Corruption Layer.** For
  `contextual-orchestrator`, the existing `CredentialBackend` is the correct
  seam for a future `KeyverseCredentialBackend`.
- **Call-site compatibility is conditional, not automatic.** Existing consumer
  call sites can remain unchanged only after the adapter maps the complete
  backend contract—get/set/delete semantics, error behavior, metadata and actor
  audit—to a released Keyverse workload-read API and its authentication,
  namespace/key/version authorization, rotation/revocation and construction
  semantics. An administrator API or operator token is not a substitute.
- **Keyverse-side work is required before migration.** The current vault
  foundation supplies administrator metadata and mutation APIs, but it does not
  yet supply the signed workload resolution contract needed by CO, Naruon, or
  other consumers. That contract must be implemented, independently reviewed,
  merged and released first.
- **Consumers do not fall back to `.env`.** Once a consumer adopts the released
  Keyverse authority, authority outage, invalid identity, revoked credentials
  and expired leases fail according to the versioned contract; they do not
  silently reactivate a dotenv or plaintext local credential store.

Keyverse never needs to understand that a particular opaque entry is an OpenAI,
mail, database, or browser credential. Those semantics remain with the
consumer. Conversely, consumers may not query Keyverse persistence directly or
import source from an open PR; they consume an immutable released API/client.

## Consequences

The phrase "Login Credential Store" therefore does **not** create a fourth
undifferentiated Keyverse module. It denotes the Keyvault secret-lifecycle
bounded context plus workload-scoped resolution and per-service ACLs.

The migration order is owner-first:

```text
Keyverse storage foundation
→ signed workload identity and scoped read contract
→ version / rotation / revocation / lease behavior
→ immutable Keyverse release
→ consumer adapter + shadow verification
→ clean startup without dotenv
→ controlled retirement of legacy credential source
```

This increases explicit cross-service dependency but avoids credential fan-out,
shared administrator tokens, direct database coupling, and a second secret
authority in each product. Availability and rollback tests are required at each
consumer boundary.

No production credential migration is performed by this ADR. Existing values
must not be copied into issues, PRs, logs, fixtures, generated artifacts or LLM
context as part of migration evidence.

## References

Evans, E. (2003). *Domain-driven design: Tackling complexity in the heart of
software*. Addison-Wesley.

Vernon, V. (2013). *Implementing domain-driven design*. Addison-Wesley.
