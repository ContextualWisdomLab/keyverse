# Topology — cwl-idp as the ecosystem central IdP

cwl-idp is a **new standalone component built on ZITADEL** (Apache-2.0). It is
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
   │ Personal OIDC (opt.)  │  OIDC                 │      │           cwl-idp  (ZITADEL)          │
   │ Google / Microsoft    │────────────────────► ┘      │                                       │
   └───────────────────────┘                              │  • OIDC / OAuth 2.1 Authorization    │
                                                          │    Server (issuer)                    │
   ┌───────────────────────┐   SCIM 2.0 (inbound)         │  • FIDO2 / passkeys (passwordless)     │
   │ Upstream HR / IGA     │─────────────────────────────►│  • Passwords DISABLED for local acct  │
   │ (provisioning source) │   /scim/v2/{orgId}           │  • SCIM v2 server (provisioning)       │
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
| Employer ADFS → cwl-idp | SAML 2.0 (HTTP-POST) / WS-Fed | Service Provider (SP) |
| Corporate LDAP/AD → cwl-idp | LDAP(S) bind | Directory consumer |
| Personal OIDC → cwl-idp | OIDC | Client (optional) |
| HR/IGA → cwl-idp | SCIM 2.0 | SCIM **server** (inbound provisioning) |
| cwl-idp → RPs | OIDC / OAuth 2.1 | **OpenID Provider (issuer)** |

## Identity resolution on inbound login

1. **JIT provisioning.** First federated login creates a local ZITADEL user
   (`isCreationAllowed`/`isAutoCreation` in the IdP templates).
2. **Auto-link by verified email.** If the assertion carries a *verified* email
   matching exactly one existing account, the external identity is linked to it
   (`AUTO_LINKING_OPTION_EMAIL`). Never on an unverified email.
3. **Explicit link / merge.** Pre-existing duplicates are reconciled by the
   account-unification service — see `merge-unification-flow.md`.

## Network posture

- `idp_internal_network`: Postgres + ZITADEL + admin service. Not routed to the
  public edge.
- `idp_edge_network`: only ZITADEL's OIDC endpoints and the admin API are
  exposed, and only behind the WAF edge (as with `newsdom-api`).
- RP client registrations and secrets live in the **IdP DB / KV**, never in RP
  environment files.

## Standalone vs. embedded

- **Standalone:** `docker compose up -d` (or `podman compose`), or the Helm
  chart under `helm/`.
- **Submodule:** embed this repo and `include:` its `docker-compose.yml`, or add
  the Helm chart as a dependency. Readiness is uniform via
  `deploy/scripts/healthz.sh` and each component's `/healthz`-style probe.
