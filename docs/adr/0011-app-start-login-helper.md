# ADR-0011: Offer app start-login as a Keyverse-owned federation helper

**Status:** Accepted  
**Date:** 2026-08-18

## Context

Relying applications need a convenient way to start brokered login (IdP
discovery and a start URL) without each product becoming an identity provider
or fetching SAML/OIDC metadata itself. Federation ownership stays in Keyverse.
SAML/OIDC preflight already forbids metadata and discovery fetches.

## Decision

1. Keyverse exposes `POST /federation/identity-providers:start-login`.
2. The helper reads the local federation desired-state registry only. It
   performs no DNS, socket, Keycloak Admin, metadata, or discovery call.
3. The response is a redacted enabled-provider list plus, when a provider can
   be selected, a Keycloak authorization URL that includes `kc_idp_hint`.
4. The RP must add PKCE `S256`, `state`, and `nonce` locally, then redirect
   the browser. The helper does not mint secrets or replace the OIDC client.
5. A discovery-document or metadata URL in the request is rejected.

## Consequences

- Applications start federation through Keyverse without owning IdP
  registration, secrets, or metadata retrieval.
- Operators still register identity providers through the existing desired-
  state lifecycle. This helper is not a new IdP and is not production
  federation acceptance evidence.
