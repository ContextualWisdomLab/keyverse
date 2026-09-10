# Keyverse custody component changelog

## Unreleased — not a published artifact

- Added native internal quorum initialization, sealed root-record reconstruction, unseal/reseal, and context-bound record protection without a root export API or external secret authority.
- Added 17 behavioral test functions plus one independent libsodium ciphertext interoperability test. They are written, not reported as passing: Rust execution and coverage remain unverified.
- Added a contents-read-only Draft verification job to existing product CI. Candidate dependency-lock generation must be removed after a real Cargo lock is captured and committed; a mandatory committed-lock gate prevents candidate resolution from being called complete.
- Kept the existing `.env`/static-mount migration incomplete. No remote KMS API, enrollment, authorization, durable audit, rollback resistance, PostgreSQL credential issuance or consumer cutover is delivered by this internal component.
