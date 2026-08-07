# OIDC RP preflight implementation plan

## TDD evidence

- RED: commit `c044ac622efe461548d1757e9d8e3c8233788d61` submitted a realistic
  confidential Naruon client and expected HTTP 200; the route did not exist and
  returned HTTP 404.
- GREEN target: authenticated readiness receipt with an unchanged alias-shaped
  registration and zero Keycloak calls.
- REFACTOR target: closed helpers for shape, text, URI, hostname, origin,
  security-attribute, scope, and cross-field policy.

## Tasks

1. Add manual non-reflective parsing and typed response models.
2. Add exact HTTPS URI, hostname, encoded-delimiter, and origin validation.
3. Add flow, PKCE, public/confidential, token, logout, and scope policy.
4. Register the router under the existing operator and path-security boundary.
5. Replace the deployment template with a closed secret-free payload.
6. Rewrite RP onboarding around render → preflight → private apply.
7. Record architecture, standards interpretation, non-goals, and APA references.
8. Add realistic success, public IPv6, hostile input, reflection, and template
   tests until the new production module reaches 100% statement/branch coverage.
9. Run full locked CI, package, realm, Compose, JSON, SAST, and security gates.
10. Remove every one-shot publication artifact before review and protected merge.

## Completion rule

No predecessor-head check, local-only result, skipped required job, self-review,
or administrator bypass is merge evidence. The exact staging-free PR head must
pass current CI and security checks with zero unresolved actionable threads.
