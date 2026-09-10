# Keyverse native custody barrier

Internal, unreleased cryptographic component for the independent custody profile
in PR #153. Not a network service, identity verifier, secret-issuance authority,
or completed CWL migration. Consumers must not depend on this PR or copy this
crate into their repositories. `publish = false` is deliberate.

## Boundary

Initialization takes only a quorum policy. It generates an OS-random wrapping
root and an independent recovery factor, produces a root record protected by
XChaCha20Poly1305, and returns separately protected recovery shares. Initialization
returns a **sealed** barrier. Reconstructing a barrier from its record never
implicitly unseals it. The root has no export, Clone or serialization API.

A trusted operator must separately protect and distribute the returned shares.
Do not persist all shares with the encrypted root record. This crate does not
read/write `.env`, files, environment variables or networks; deployment enrollment
and authenticated custodian transport are not implemented here. Possession of
quorum shares authorizes local unseal, not arbitrary remote workload requests.

After successful quorum recovery and authentication of the complete root record,
the barrier can protect/open internal records with six exact associated context
dimensions: tenant, environment, namespace, key name, immutable version and
purpose. Context binding prevents ciphertext substitution; it is **not** caller
authorization. The eventual authenticated application service must validate
workload identity, authorize scope and durably audit before invoking this module.

## Encoding and resource limits

`KVC1` root record: 4-byte magic, required/total share counts, 16-byte random
instance ID, 24-byte nonce, 48-byte encrypted root and authentication tag. Total:
94 bytes. `KVS1` custodian share: same public policy/instance metadata and one
33-byte Shamir share; total 55 bytes. All sizes are checked before parsing.

`KVD1` protected data: magic, instance ID, nonce and ciphertext/tag. The complete
header and separately length-framed context are authenticated. Context fields
are bounded to 128 UTF-8 bytes and contain no whitespace/control characters;
plaintext is bounded to 1 MiB. These are explicit resource-admission constraints,
not a claim of cryptographic maximum message size or statistical accuracy.
The initial quorum profile supports 2 through 16 shares with threshold <= count.

Every selected share must have a unique nonzero in-range index and match the
root record's policy/instance. Malformed/mixed/duplicate inputs fail before
interpolation. Extra corrupt shares fail rather than trying combinations.
Recovery authenticates first, then installs the root. Resealing drops the
zeroizing root buffer. Returned plaintext and explicitly exported custodian
shares are redacted buffers requiring deliberate exposure by their owner.

## Explicit nonclaims and release gates

There is no durable transaction/audit adapter, monotonic anti-rollback anchor,
key catalogue/rotation, workload authentication/authorization, rekey ceremony,
credential issuance, PostgreSQL adapter, network listener or external KMS client.
A valid old record may be replayed: authenticated encryption is not rollback
protection. These are unimplemented gates, not optional production safeguards.

Rust-owned sensitive buffers are cleared on drop. Copies inside third-party
cryptographic/RNG/interpolation implementations, registers, crash dumps, swap,
allocator history and host compromise require independent memory review; this
module does not claim complete zeroization or hardware custody. Review the exact
resolved dependencies and their advisories, especially the Shamir implementation
and its older rand-trait dependency, before any release.

The CPU profile must meet the cipher implementation's constant-time assumptions.
No FIPS validation, CSAP certification, physical-HSM equivalence or fully unattended
cold recovery is claimed. Unit tests use only generated test material.

## Verification status

Source and tests are prepared. The test-first scaffold run is queued, so neither
observed RED nor GREEN is claimed. Rust compilation and all behavioral results
remain unverified until the hosted job actually executes.

## Reproduction

```sh
cd services/key_custody
cargo +1.97.1 test --locked --all-targets
cargo +1.97.1 clippy --locked --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +1.97.1 doc --locked --no-deps
```

The initial RED commit includes temporary dependency-lock preparation in CI.
That is not release-ready verification; final CI must consume the committed lock
without generating or changing it. A queued runner or inspected source is not a
passing test, and no historical Python coverage certifies this Rust module.

## Primary references

RustCrypto Contributors. (n.d.). *chacha20poly1305 0.11.0*.
https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/

sharks Contributors. (n.d.). *sharks 0.5.0: Source and feature flags*.
https://docs.rs/sharks/0.5.0/sharks/
https://docs.rs/crate/sharks/0.5.0/features

RustCrypto Contributors. (n.d.). *zeroize 1.9.0*.
https://docs.rs/zeroize/1.9.0/zeroize/

These sources document dependency behavior, not an audit of this new composition.
Shamir recovery is not threshold signing. The standalone architecture and its
broader key-operation/lifecycle acceptance remain in the governing custody ADR.
