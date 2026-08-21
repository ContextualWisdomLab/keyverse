# ADR-0012: Issue hashed, purpose-bound programmable application tokens

**Status:** Accepted  
**Date:** 2026-08-18

## Context

Buyers need machine credentials scoped to one software unit and specific API
capabilities (PAT / API key). These must not become a password substitute, must
not live in an RP environment as Keycloak secrets (ADR-0005), and must not
inherit down the org tree (ADR-0010).

## Decision

1. Keyverse issues programmable application tokens (`kvt_<prefix>_<secret>`).
   Only the SHA-256 hash, prefix, purpose, software unit, and capability codes
   are stored.
2. Closed purposes are `machine_api`, `integration_sync`, and
   `operator_export`. Password, WebAuthn, browser-login, and authenticator
   purposes are rejected.
3. Tokens are software-unit and API-capability scoped, time-bounded (60
   seconds to 90 days), rotatable, revocable, and auditable. Rotation validates
   the replacement before revoking the active token, so invalid replacement
   settings do not destroy a working credential.
4. The plaintext secret is returned only at issue or rotate time. List, get,
   verify, and revoke responses never include the secret or hash.
5. Verification does not consult org-tree grants. Tokens never inherit.
6. A token is not an authenticator. Browser passwordless policy (ADR-0002)
   remains unchanged.

## Consequences

- Relying applications store the plaintext token in their own secret manager
  and present it only to `POST /application-tokens:verify`.
- Keycloak client secrets and operator bearers remain separate credentials.
- This slice does not replace confidential RP client-secret placement.
