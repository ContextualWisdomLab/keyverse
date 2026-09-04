# ADR-0016: "Login Credential Store" is Keyvault plus per-service ACLs, not a new bounded context

**Status:** Accepted (design decision; no migration performed)
**Date:** 2026-09-02

## Context

The owner asked that Keyverse also serve as a "Login Credential Store."
Read literally against Keyverse's own passwordless-first direction
(ADR-0002: FIDO2/passkeys default, password authenticator removed from the
bound browser flow), this cannot mean end-user login credentials — that
would contradict an already-Accepted ADR. The only credential category
this can honestly refer to is **service-account / machine credentials**:
API keys, service-to-service tokens, and third-party system login
credentials that CWL services need in order to authenticate *outbound* to
external systems (OpenAI, NVIDIA NIM, OpenRouter, Bytez, and similar).

Two things already exist in this ecosystem that could be mistaken for the
same capability, and are not:

1. **PR #103's programmable application tokens (PATs)** (ADR-0012, in
   flight) — Keyverse-*issued*, hashed-at-rest tokens scoped to software
   units and APIs, for a caller authenticating **to** a Keyverse-fronted
   resource. Per that PR's own boundary decision: "PATs are not
   password/WebAuthn substitutes… Application/runtime credentials remain
   separate from operator credentials." This is Keyverse as **issuer**,
   inbound trust direction.
2. **`contextual-orchestrator`'s `credentials.py`** (a sibling repo,
   inspected directly for this research) — a KV-backed provider-API-key
   registry with a `CredentialBackend` Protocol (`InMemoryCredentialBackend`
   default; pgcrypto-encrypted `PostgresCredentialBackend`), documenting
   the identical "No os.getenv, values from KV" principle this repo's own
   `kv_store.py` and the new `keyvault.py` (ADR-0014) already follow. This
   is a consuming service's **own outbound** credentials to external
   providers, stored and resolved entirely inside that service today.

The owner's "Login Credential Store" request is squarely category 2, not
category 1: it is about where a service's outbound third-party credentials
live, not about Keyverse-issued access tokens.

**Should this centralize into Keyverse as its own bounded context**, or
stay close to each consuming service? This is a real Domain-Driven Design
question, not a foregone conclusion. Centralizing storage *and* the
knowledge of what each secret means/is-used-for in one service risks
turning Keyverse into a "God service" that must be redeployed or
reconfigured whenever any other service's credential taxonomy changes —
exactly what an Anti-Corruption Layer exists to prevent when integrating
across bounded contexts (Evans, 2003, ch. 14; Vernon, 2013, ch. 3, on
"Open Host Service" and ACL patterns for a shared context boundary).

## Decision

Split the concern instead of centralizing the whole thing:

- **Keyvault (ADR-0014) is the shared storage primitive.** Its
  `KeyvaultStore`/`KeyvaultService` and
  `PUT`/`DELETE` and metadata APIs provide the administrative foundation for
  "a namespaced, encrypted-at-rest place to manage a secret, audited." A
  service-account credential is not a structurally different
  secret from any other Keyvault entry.
- **Each consuming service keeps its own Anti-Corruption Layer around
  that primitive.** Concretely, `contextual-orchestrator`'s existing
  `CredentialBackend` Protocol is the adapter seam: a future
  `KeyverseCredentialBackend(...)` implementing that same
  Protocol (alongside the existing `InMemoryCredentialBackend` and
  `PostgresCredentialBackend`) would let that service point at Keyverse's
  Keyvault with **zero call-site changes**, because `get_credential`/
  `register_credential` already resolve through a pluggable backend by
  design.
- **Keyverse never learns what `OPENAI_API_KEY` means to
  contextual-orchestrator.** It only stores and returns bytes under a
  namespace/key the calling service chose. This keeps the Aggregate
  boundary honest: Keyvault's invariants are about secrets-at-rest
  (encryption, audit, namespace isolation), not about any one service's
  credential semantics.
- **No migration is performed in this PR.** `contextual-orchestrator`'s
  provider credentials stay on its own local backend for now. Migrating
  any specific service onto Keyverse's Keyvault is a separate, later,
  per-service decision that service's own maintainers should make
  deliberately — it changes that service's availability dependency graph
  (a Keyverse outage would then affect credential resolution too) and
  needs its own rotation/rollback plan, which is out of scope for a design
  ADR.

## Consequences

- "Login Credential Store" is **not** a fourth Keyverse module. It is
  Keyvault (already built, ADR-0014) plus a documented integration pattern
  for consumers.
- This closes the risk of building an undifferentiated blob where
  identity, secrets, and every consumer's credential taxonomy live in one
  service — the exact anti-pattern this org's DDD convention (minimal
  Shared Kernel, Anti-Corruption Layer for external/legacy integration)
  warns against.
- The natural next step, for whichever team owns it, is a
  `contextual-orchestrator`-side `KeyverseCredentialBackend` PR — not
  Keyverse-side work — since the Protocol it would implement already
  exists and needs no change here. It also requires a Keyverse workload-read
  API that verifies signed identity and enforces namespace-bound authority;
  the shared operator credential is not suitable for that path.

## References

Evans, E. (2003). *Domain-driven design: Tackling complexity in the heart
of software*. Addison-Wesley.

Vernon, V. (2013). *Implementing domain-driven design*. Addison-Wesley.
