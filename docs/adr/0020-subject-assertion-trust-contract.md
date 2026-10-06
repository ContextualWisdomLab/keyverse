# ADR-0020: Publish a versioned subject-assertion trust contract for durable RP binding

**Status:** Proposed
**Date:** 2026-10-06
**Issue:** [#155](https://github.com/ContextualWisdomLab/keyverse/issues/155)

## Context

Orgmetra (#297), ConceptWeave (#44), and CalendarWeave (#2) need to store a
Keyverse `(issuer, subject)` pair as a long-lived link to their own records.
Protected `main` gives them no owner-published rule for two questions:

1. Was this ID token verified under the exact Keyverse profile (issuer,
   signature and algorithm, audience, time claims, subject, tenant)?
2. May this subject be stored for durable correlation, or is it valid only for
   the current session?

OpenID Connect Core 1.0 §2 and §8 define `sub` as locally unique and never
reassigned for the `public` and `pairwise` subject types. The OpenID Connect
Ephemeral Subject Identifier 1.0 specification intentionally changes `sub`
across visits. A consumer that persists every syntactically valid `sub` would
create broken or misleading links under an ephemeral profile. Each consumer
currently refuses to invent a local `authenticated=true` receipt, so they fail
closed.

## Decision

1. Keyverse owns a closed, versioned contract named
   `keyverse.subject-assertion/v1`. Its parts are:
   - the pure offline verifier `services/account_unification/app/subject_assertion.py`;
   - the receipt JSON Schema `docs/contracts/subject-assertion-v1.schema.json`;
   - the conformance catalog `docs/contracts/subject-assertion-v1.fixtures.json`,
     produced by `tools/generate_subject_assertion_fixtures.py` with a
     throwaway key.
2. The deployment profile pins the exact HTTPS issuer, one audience, an
   allowed subset of `ES256`/`RS256`, a public JWK Set, the subject type, an
   optional canonical `org` tenant claim, and a clock leeway of 0–300 seconds.
   An unsafe profile fails at construction, before any token is read.
3. The verifier performs no discovery, JWKS fetch, DNS, socket, storage, or
   Keycloak call. Header members other than `alg`, `typ`, and `kid` are
   rejected, so `crit`, `jku`, `x5u`, `jwk`, and `x5c` never select a key.
   `typ` must be absent or the `application/jwt` media type, compared
   case-insensitively (RFC 7515 §4.1.9); the Keycloak payload `typ`, when
   present, must be `ID`. Access tokens (`at+jwt` or `Bearer`) are not subject assertions.
4. The audience rule follows OIDC Core §3.1.3.7: `aud` contains this RP, any
   other audience must be listed in the profile's
   `trusted_additional_audiences`, a multi-valued `aud` requires `azp`, and a
   present `azp` must equal this RP.
5. Correlation eligibility is a profile property, not a token claim.
   `public` and `pairwise` return `correlation: durable` plus a SHA-256
   `correlation_key` over `[contract_version, issuer, audience, tenant,
   subject]`. `ephemeral` returns `correlation: session_only` and no key.
6. A rejected receipt carries exactly one closed reason and no identity field.
   The receipt never contains raw token bytes.
7. Key rotation is a profile change: an RP keeps the old public key in the
   profile until tokens signed by it expire, then builds a new profile without
   it. A removed key yields `unknown_key`. The profile keeps a read-only deep
   copy of its key set, so editing the caller's dict cannot add or revoke trust.
8. Input hygiene is strict so that every conforming verifier makes the same
   decision. Segments must be canonical base64url. JSON must be strict UTF-8
   with no duplicate members and no lone surrogates. `sub` and `org` must not
   contain control, format, surrogate, or line/paragraph separator characters
   or edge whitespace. NumericDates are integers in 0..2^53-1, and `exp` must
   not be before `iat`. The caller's `now` must be an integer; a NaN or float
   clock raises `TypeError` instead of silently disabling the time checks.
9. Trusted RSA keys have 2048 to 8192 bits and a public exponent of at least
   65537. EC coordinates are exactly 32 bytes. `key_ops`, when present, is
   exactly `["verify"]`. The correlation key also binds the subject type, so
   changing a client between `public` and `pairwise` cannot reuse a key.

## Evidence boundary

| Claim | Status |
|---|---|
| Offline verifier, schema, and fixtures with 100% statement and branch coverage | `active-PR` |
| Real Keycloak 26 ID token accepted by this verifier | `gap-not-claimed` |
| Keycloak support for an ephemeral subject mode | `gap-not-claimed`; no supported Keyverse profile uses it today |
| Immutable release artifact, SBOM, provenance, rollback | `gap-not-claimed`; required by #155 and #158 before consumers pin it |
| Downstream ACL, tenant membership, and resource authorization | consumer-owned; ADR-0008 still applies |

## Consequences

- Consumers have one owner-defined rule for persistence eligibility and do not
  need a parallel receipt schema. #158 must reuse this contract rather than
  publish a second subject receipt.
- The contract does not change the closed RP mapper profile. It adds no claim,
  audience, or mapper.
- A verified receipt proves authentication evidence, not authorization. #160
  remains a separate runtime resource-decision contract.
- The release envelope (version, digest, SBOM, provenance) stays open. A
  merged PR is not a consumable release.

## Alternatives rejected

- **Online JWKS discovery in the verifier.** Violates the no-network preflight
  pattern and makes results depend on mutable remote state.
- **A token claim that says "durable".** The issuer would need a new mapper,
  which the closed mapper profile forbids, and a claim cannot describe how the
  issuer assigns subjects.
- **Persist `sub` without the tenant and audience.** A pairwise or
  multi-tenant deployment could then merge distinct identities.

See `docs/doctoring/subject-assertion-trust-contract.md` for the standards
interpretation and APA 7th references.
