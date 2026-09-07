# Keyverse LineageWeave Account-Derived Claim Profile

**Status:** Approved bounded implementation under ADR-0009.

## Purpose

Provide LineageWeave with claims derived from the real Keyverse account that
authenticated, while keeping Keyverse's relying-party desired-state surface
closed and secret-free.

## Contract

- Client ID is fixed to `lineageweave-web`; it is confidential and uses
  authorization code plus PKCE `S256`.
- The first mapper is the existing self-pinned audience mapper.
- `role` comes only from client roles assigned to that same client. It is a
  multivalued string claim with no prefix.
- `org` and `workspace` come only from user attributes bearing those exact
  names. They are scalar string claims.
- All three account-derived claims must appear together and cannot mix with
  hardcoded claims.
- The profile rejects scripts, groups, regex, arbitrary attributes, arbitrary
  roles, extra audiences, extra destinations, aggregation, secrets, and client
  secret generation/retrieval.

## Runtime prerequisites

1. Passwordless registration may create the identity-only account without
   `org` or `workspace`; that incomplete account is not eligible for routing.
2. An identity operator verifies the actual Keyverse account and assigns its
   `org` and `workspace` values and one or
   more recognized `lineageweave-web` client roles.
3. The private rendered template passes Keyverse preflight, is reconciled by
   Keyverse, and receives an exact observable receipt.
4. The confidential client credential is placed through the approved
   secret-management channel.
5. LineageWeave proves issuer/signature/expiry/audience validation, tenant and
   resource denial, role downgrade, logout, and rollback using that real
   account.

## Non-goals

- Generic Keycloak mapper administration.
- A claim-based bypass of LineageWeave resource ABAC.
- Static company or PU routing values.
- An assertion that a local or compose-only identity provider is Keyverse
  production evidence.
