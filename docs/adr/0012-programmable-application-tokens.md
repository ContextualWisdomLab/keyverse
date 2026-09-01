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
   The durable record stores the SHA-256 hash, prefix, purpose, software unit,
   capability codes, `application_token_id`, `tenant_deployment_id`, lifecycle
   state, creation/expiry/revocation timestamps, `actor_identity_id`, and
   `replaced_token_id`. The plaintext secret is never stored.
2. Closed purposes are `machine_api`, `integration_sync`, and
   `operator_export`. Password, WebAuthn, browser-login, and authenticator
   purposes are rejected.
3. Tokens are software-unit and API-capability scoped, time-bounded (60
   seconds to 90 days), rotatable, revocable, and auditable. Rotation accepts
   only an active, unexpired predecessor, validates the replacement before
   revoking it, and uses atomic storage compensation for storage or audit
   failures, so invalid, incomplete, or retired-token replacement actions do
   not destroy or revive a credential.
4. The plaintext secret is returned only at issue or rotate time. List, get,
   verify, and revoke responses never include the secret or hash.
5. Verification does not consult org-tree grants. Tokens never inherit.
6. Tenant is explicit at issue, verify, and rotate time; a token is accepted
   only for its stored tenant. Management routes require the operator bearer.
   `POST /application-tokens:verify` is a separate runtime route authenticated
   with the least-privilege `X-Keyverse-Runtime-Token` service credential;
   `presented_token` in the request body is only the PAT being verified and is
   never the credential that authenticates the verification endpoint itself.
7. Issue, revoke, and rotate mutations roll back token state when audit
   persistence fails; rotation restores the predecessor and deletes its
   replacement in one KV-store operation. Expired or retired predecessors
   cannot be rotated.
8. A token is not an authenticator. Browser passwordless policy (ADR-0002)
   remains unchanged.

## Consequences

- Relying applications store the plaintext token in their own secret manager
  and present it only as the PAT under verification to
  `POST /application-tokens:verify`; the caller separately authenticates that
  runtime request with the provisioned `X-Keyverse-Runtime-Token`.
- Keycloak client secrets, runtime service tokens, programmable application
  tokens, and operator bearers remain separate credentials.
- This slice does not replace confidential RP client-secret placement.
