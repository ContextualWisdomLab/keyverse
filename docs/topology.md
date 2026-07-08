# Topology — cwl-idp as the ecosystem central IdP

cwl-idp is a **new standalone component built on Keycloak** (Apache-2.0). It is
the hub: it federates external identity providers *in*, and issues OIDC *out* to
ecosystem relying parties. The employer ADFS (`sts.hssmartdev.com`) is an
**external, proprietary** IdP and a **compatibility target — never the hub**.

```
                         INBOUND FEDERATION (external IdPs -> cwl-idp)
   ┌───────────────────────┐
   │ Employer ADFS         │  SAML 2.0 / WS-Fed   ┐
   │ sts.hssmartdev.com    │────────────────────► │
   └───────────────────────┘   (nameID: email,    │
                                 claims: upn/email)│
   ┌───────────────────────┐                       │
   │ Corporate LDAP / AD   │  LDAP(S) bind         │
   │ ad.corp.example       │────────────────────► ├───────────────────────────┐
   └───────────────────────┘                       │                           │
   ┌───────────────────────┐                       │      ┌────────────────────▼─────────────────┐
   │ Personal OIDC (opt.)  │  OIDC                 │      │           cwl-idp  (Keycloak)         │
   │ Google / Microsoft    │────────────────────► ┘      │                                       │
   └───────────────────────┘                              │  • OIDC / OAuth 2.1 Authorization    │
                                                          │    Server (issuer)                    │
   ┌───────────────────────┐   SCIM 2.0 (inbound)         │  • FIDO2 / passkeys (passwordless)     │
   │ Upstream HR / IGA     │─────────────────────────────►│  • Password flow DISABLED for local   │
   │ (provisioning source) │   /scim/v2/Users (shim)      │  • SCIM v2 shim -> Keycloak Admin API  │
   └───────────────────────┘                              │  • account-unification admin service  │
                                                          │  • Postgres (system of record)        │
                                                          └────────────────────┬──────────────────┘
                                                                               │ OIDC (issued)
                        OUTBOUND ISSUANCE (cwl-idp -> relying parties)          │
                                                     ┌─────────────────────────┼─────────────────────────┐
                                                     ▼             ▼           ▼            ▼            ▼
                                                 naruon      pg-erd-cloud  clearfolio  semantic-   contextual-
                                                                                       data-portal orchestrator
                                                                               │
                                                                        newsdom-api (via WAF edge)
```

## Trust directions

| Edge | Protocol | Role of cwl-idp |
| --- | --- | --- |
| Employer ADFS → cwl-idp | SAML 2.0 (HTTP-POST) / WS-Fed | Service Provider (SP) / broker |
| Corporate LDAP/AD → cwl-idp | LDAP(S) bind | User-storage / directory consumer |
| Personal OIDC → cwl-idp | OIDC | Client (optional) |
| HR/IGA → cwl-idp | SCIM 2.0 | SCIM **server shim** (inbound provisioning) |
| cwl-idp → RPs | OIDC / OAuth 2.1 | **OpenID Provider (issuer)** |

## Identity resolution on inbound login

1. **JIT provisioning.** First federated login creates a local Keycloak user
   (Keycloak's first-broker-login flow with the IdP's `isCreationAllowed`
   equivalent; JIT is on by default for brokered IdPs).
2. **Auto-link by verified email.** With `trustEmail: true` on the IdP/LDAP
   source, a *verified* email that matches exactly one existing account links
   the external identity to it via the first-broker-login flow. Never on an
   unverified email.
3. **Explicit link / merge.** Pre-existing duplicates are reconciled by the
   account-unification service — see `merge-unification-flow.md`.

## SCIM inbound provisioning

Keycloak's native SCIM support is experimental and the mature plugin is
commercial, so cwl-idp ships a small **Apache-2.0 SCIM v2 server shim**
(`services/account_unification/app/scim.py`). Upstream HR/IGA systems POST SCIM
`User` resources to `/scim/v2/Users`; the shim translates them into Keycloak
Admin REST API calls (create / replace / deactivate), provisioning into the
`cwl` realm. It sits behind the WAF edge alongside the merge API.

## Network posture

- `idp_internal_network`: Postgres + Keycloak + admin service. Not routed to the
  public edge.
- `idp_edge_network`: only Keycloak's OIDC endpoints and the admin/SCIM API are
  exposed, and only behind the WAF edge (as with `newsdom-api`).
- RP client registrations and secrets live in the **IdP DB / KV**, never in RP
  environment files.

## Standalone vs. embedded

- **Standalone:** `docker compose up -d` (or `podman compose`), or the Helm
  chart under `helm/`.
- **Submodule:** embed this repo and `include:` its `docker-compose.yml`, or add
  the Helm chart as a dependency. Readiness is uniform via
  `deploy/scripts/healthz.sh` and each component's `/healthz`-style probe.
