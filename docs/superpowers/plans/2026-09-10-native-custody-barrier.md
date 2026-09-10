# Independent custody barrier implementation plan

**Goal:** Implement the first native internal custody barrier in Keyverse, not another credential-file transport.

**Architecture:** A sealed root record and separately held recovery shares are the initial trust split. An unsealed, non-exported wrapping root authenticates bounded records and their explicit context. The module has no database, network, dotenv, filesystem credential source or external KMS client. It is an internal primitive, not an authenticated/audited remote KMS service.

**Spec:** `docs/adr/0017-keyverse-root-bootstrap-secret-transport.md` on this owner branch. Its number collides with #128's passkey proposal and must be reconciled before protected integration; this plan allocates no further ADR number.

**Tech stack:** Rust 1.97.1; pinned RustCrypto XChaCha20Poly1305, getrandom, sharks with zeroize_memory, zeroize, and rand_chacha 0.3 for the sharks rand-0.8 trait boundary. No custom cryptographic algorithms. A software implementation is not an HSM/FIPS certification.

## Task and test order

- [ ] Run the compiling, deliberately unavailable scaffold against the initialization assertion and record its actual assertion failure, not a missing-tool or compiler failure.
- [ ] Capture Cargo's generated dependency lock as public build metadata, commit it, and remove the temporary lock-generation step. Final verification is locked and must not rewrite source or dependency locks.
- [ ] Implement bounded quorum validation, random root/recovery factors, authenticated encrypted root record, separately encoded recovery shares and sealed-by-default reconstruction.
- [ ] Observe negative cases for insufficient/duplicate/mixed/corrupt shares, corrupted root metadata/ciphertext, sealed operations and oversized input. Never install recovered state until authentication succeeds.
- [ ] Implement context-bound record protection and verify wrong context/instance, nonce/ciphertext/header mutation and reseal/recovery. No root-export API.
- [ ] Run native tests, Clippy, rustdoc and actual coverage; retain exact-head receipts. Local source inspection is not execution evidence.
- [ ] Update the product baseline and architecture with the implemented boundary and unresolved authenticated enrollment, workload authorization, durable audit, atomic persistence, rollback resistance, credential issuance, secure memory/hardware and immutable release gates.

## Verification environment and integration

The current local container has no cargo/rustc and cannot resolve download hosts. The native job is added to the existing product `ci` workflow, with contents-read only, no credentials and no mutation/publication step. Draft runs are necessary to execute deliberate RED tests without claiming Ready. It does not duplicate central security/review/release workflows; reuse an appropriate published Rust verification contract when the central owner provides one.

All existing #153 changes remain on this branch. #154 is still an unmerged prerequisite and #143 is the older superset cleanup; neither is closed, auto-merged or silently discarded. #129/#151 retain their compatibility scope. No production deployment or consumer cutover occurs in this increment.
