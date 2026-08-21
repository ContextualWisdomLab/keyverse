# Product-technical gap baseline doctoring record

**Date:** 2026-08-21
**Scope:** Keyverse product, trust-boundary, PR queue, and release evidence

## Interpretation

This baseline separates deterministic repository evidence from live protocol,
consumer authorization, deployment, and release acceptance. Source/tests can
prove validators, reconciliation, locking, and documentation contracts; they
cannot prove a controlled passwordless login, downstream token acceptance,
production sizing, or immutable release provenance without an approved runtime
lane. Missing evidence is therefore `gap-not-claimed`, not synthetic success.

The mapper policy remains closed: `role`, `org`, and `workspace` are issuer-side
claims, not tenant authorization. Consumers must independently validate issuer,
signature/JWKS, expiry, audience, resource, tenant, purpose, and RBAC. The
LineageWeave profile keeps `org` as one opaque tenant key and `workspace` as one
child namespace; ambiguous membership denies before authorization.

## Current evidence interpretation

- The protected-main head observed for this snapshot is
  `ce207dfd42975db61c82a5963e206fc1db14ac2b`.
- The #112 root stack is at `31dd486cb97ca215da451151f618a954a07b0ea5` with
  hosted checks pending and `REVIEW_REQUIRED`; local 100% evidence does not
  replace hosted checks or independent approval.
- #104 was normally restacked onto #112 at `c623a3d8df6e0f6da0e9623b23e3178e0f0296f0`.
  Its documentation-only conflict resolution preserved both CHANGELOG entries;
  the baseline addition then advanced it to successor
  `8077aa46e120ea5977464f2e611d44ab44bab695`; fresh hosted checks are required
  for the successor and neither head is protected-main evidence.
- Central `.github#1203` has a cancelled scheduler predecessor and a queued
  retry. Cancellation is normal concurrency behavior; the observed age and
  evidence do not satisfy D1–D5 emergency bypass criteria.
- Open issues #114, #102, #99, #71, and #2 remain tracked. No issue is treated
  as implemented-main evidence merely because a design PR exists.

## Standards interpretation

OIDC exact issuer and audience validation, RFC 8725 token validation, RFC 9700
authorization-code and PKCE guidance, RFC 8707 resource indicators, RFC 9728
protected-resource metadata, RFC 9068 JWT access-token requirements, and RFC
9207 authorization-response issuer comparison are interpreted as consumer or
resource-server acceptance requirements where applicable. Keycloak mapper
configuration remains projection evidence only.

No new frontend behavior is claimed by this baseline. A future UI change must
record its Figma File ID and Storybook scene/edge-event, accessibility,
interaction, performance, responsive, typography/color, animation, form,
navigation, and chart acceptance in the owning ADR.

## Verification rule

Every refresh must re-query the exact PR head, base, open review threads, formal
review decision, required CheckRun conclusions, and merge state. A changed head
invalidates prior evidence. Protected merges remain normal PR merges; guarded
force merge is permitted only after all D1–D5 and emergency acceptance criteria
are independently proven. No bypass, force push, direct protected push, fake
status, or self-approval is part of this record.

## APA 7th references

- OpenID Foundation. (2014). *OpenID Connect Core 1.0*. https://openid.net/specs/openid-connect-core-1_0-18.html
- Internet Engineering Task Force. (2020). *JSON Web Token best current practices* (RFC 8725). https://www.rfc-editor.org/rfc/rfc8725.html
- Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current practice for OAuth 2.0 security* (RFC 9700). https://www.rfc-editor.org/rfc/rfc9700.html
- Internet Engineering Task Force. (2018). *OAuth 2.0 authorization server metadata* (RFC 8414). https://doi.org/10.17487/RFC8414
- Internet Engineering Task Force. (2020). *Resource indicators for OAuth 2.0* (RFC 8707). https://doi.org/10.17487/RFC8707
- Internet Engineering Task Force. (2025). *OAuth 2.0 protected resource metadata* (RFC 9728). https://doi.org/10.17487/RFC9728
- Model Context Protocol. (2026, July 28). *Authorization*. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
