# Native custody maintenance boundary

This is an internal, unreleased Keyverse component, not a remote KMS service.
Read the repository's AGENTS.md and the corrected independent-custody ADR.

- Keep all new custody/crypto runtime in Rust. Do not introduce custom cipher, KDF, RNG or Shamir arithmetic.
- Do not add environment/file credential fallback, external-vault startup dependence, or a public plaintext-root export.
- Context authentication is not workload authorization. A network adapter needs verified identity, narrow policy and durable audit before invoking this library.
- Keep recovery shares separate from encrypted root storage. No automatic unseal by persisting the complete unlocking factor on the same host state.
- Inject entropy faults only through private test seams. Never expose deterministic production RNG configuration.
- Preserve actual RED/GREEN chronology. A queued job, a source review or the libsodium reference fixture is not Rust execution evidence.
- Commit a real reviewed Cargo lock, remove temporary lock generation, and run current-head tests, Clippy, documentation, complete coverage and security review before promotion.
- Record rollback/rekey, persistence/audit atomicity, enrollment and dependency-memory gaps explicitly. No deployment, HSM/FIPS claim or consumer adoption based on this component alone.
