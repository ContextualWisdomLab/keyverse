# Keyverse (cwl-idp)

Keyverse is the ContextualWisdomLab **identity leaf and hub**. It is the system of
record for **who a person is in this ecosystem**: local passwordless accounts,
inbound federation, inbound SCIM provisioning, and outbound OpenID Connect
tokens that relying parties consume.

It is **not** the employment or org-tree system of record. Orgmetra owns
employment and organizational-tree truth. Keyverse does not copy Orgmetra
tables. Composition hubs such as **naruon** and **gyeot** may call this leaf;
they are not required to boot it.

Keyverse must run **from this repository alone** (Compose or Helm in this repo)
and remain **callable** by relying parties over published OIDC/OAuth, SAML
broker, LDAP/AD user-storage, and SCIM contracts.

## What this IdP does

Built on [Keycloak](https://www.keycloak.org) (Apache-2.0) plus a Keyverse
account-unification admin service, the product:

- issues **OpenID Connect** on **OAuth 2.0** to ecosystem relying parties
  (`naruon`, `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`,
  `contextual-orchestrator`, and `newsdom-api` through the WAF edge);
- is **passwordless-first**: FIDO2 / passkeys are the default, and the
  **password authenticator is removed** from the bound browser flow for
  ecosystem-local accounts;
- runs a **SCIM 2.0 server shim** for inbound provisioning into Keycloak;
- **federates external IdPs in** — employer ADFS via SAML, corporate LDAP/AD,
  and optional personal OIDC — as **deployment data**, never as portable realm
  code; and
- links one human's many external identities and **merges** two pre-existing
  accounts into one survivor, never on an unverified email.

> Employer ADFS and corporate directories are **external compatibility
> targets**, not peer hubs. Customer-specific federation stays in the
> deployment controller and KV store.

OAuth 2.0 ([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)) is the official
authorization-framework record. [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
is an IETF Internet-Draft (`draft-ietf-oauth-v2-1-15`, work in progress) and
is not cited here as a final RFC.

RP client registrations and confidential values live in the **IdP DB / KV**,
never in an RP's environment. Authorized identity data stays usable under
purpose-bound access control, encryption, and audit.

## Architecture

```text
external IdPs  ──►  Keyverse (Keycloak + admin service)  ──►  OIDC to RPs
  ADFS (SAML)       passwordless OIDC / OAuth 2.0
  LDAP/AD           FIDO2 passkeys
  OIDC (opt)        SCIM 2.0 shim (inbound)
  HR/IGA (SCIM)     account-unification admin service

composition hubs (naruon, gyeot) MAY call this leaf
Orgmetra owns employment / org-tree truth (not copied here)
```

Trust boundaries: [`ARCHITECTURE.md`](ARCHITECTURE.md). Network diagram:
[`docs/topology.md`](docs/topology.md). Architecture decisions:
[`docs/adr/`](docs/adr/README.md). Standards bibliography:
[`docs/REFERENCES.md`](docs/REFERENCES.md).

## Run this repository alone

No sibling repository checkout is required. Docker or Podman with the compose
plugin is enough:

```bash
cp .env.example .env          # populate values from your KV (bootstrap transport)
cp deploy/bootstrap/bootstrap.example.yaml deploy/bootstrap/bootstrap.yaml

docker compose up -d          # or: podman compose up -d
./deploy/scripts/healthz.sh   # waits for Keycloak realm + admin service to be READY
```

- Keycloak console: `http://localhost:8080`
- Admin service health: `http://localhost:8099/healthz`

The stack imports the **passwordless-first** realm at first start
(`deploy/keycloak/realm-cwl.json`): a `browser-passwordless` flow with a
WebAuthn passwordless authenticator and **no password authenticator**, plus
`registrationAllowed:false` / `resetPasswordAllowed:false`.

Production-shaped clusters use [`helm/cwl-idp/`](helm/cwl-idp/).

### Optional parent include

A parent Compose or Helm chart **may** include this repo's
`docker-compose.yml` or depend on `helm/cwl-idp`. That is an optional
embed of **this** repository. Keyverse does not require naruon, gyeot,
Orgmetra, or any other sibling checkout in order to start.

## How a relying party calls Keyverse

Each RP is a separate trust boundary. A README listing, repository
relationship, or client ID is not authorization. The RP validates the issuer,
signature, allowed algorithm, audience, subject, expiry, `iat`, exact resource,
tenant, and purpose. All of those token and request-context checks must
complete before applying its own access-control policy, including RBAC
([ADR-0008](docs/adr/0008-keyverse-rp-authorization-boundary.md)).

Published operator contracts that already ship:

| Contract | Purpose |
| --- | --- |
| Keycloak OIDC endpoints on the WAF edge | Authorization, token, JWKS, and logout for registered RPs |
| `POST /clients/relying-parties:validate` | Side-effect-free RP client preflight |
| `PUT /clients/relying-parties/{client_id}` | Secret-free RP desired state and reconcile |
| `POST /federation/identity-providers:validate` | Side-effect-free SAML/OIDC IdP preflight |
| `PUT /federation/identity-providers/{alias}` | Persist and converge an external IdP |
| `POST /federation/user-directories:validate` | Side-effect-free LDAP/AD preflight (no DNS, socket, bind, search, store, or Keycloak call) |
| `PUT /federation/user-directories/{name}` | Persist and converge a directory component |
| `/scim/v2/Users` | Inbound SCIM 2.0 user lifecycle |
| `POST /registration/accounts` | Password-free account create plus enrollment email |
| `GET /users/{user_id}`, `POST /merges` | Inspect and merge accounts |

Confidential client secrets are placed by the deployment controller, not
returned in ordinary Keyverse responses. See
[`docs/rp-onboarding.md`](docs/rp-onboarding.md).

### Register external federation

The portable realm contains no employer ADFS, LDAP/AD source, or other
customer-specific federation. Render deployment values from KV and preflight
every private payload before apply.

LDAP preflight redacts `bindDn` and `bindCredential` and must never be used
as the apply payload; apply the original private file only. The first
directory profile is LDAPS-only, read-only, Kerberos-disabled, and
`trustEmail=false`.

See [`docs/federation-onboarding.md`](docs/federation-onboarding.md) and
[`docs/ldap-directory-onboarding.md`](docs/ldap-directory-onboarding.md).

## Account unification

Matching precedence is **exact `(identity_provider, subject)` → verified
email → explicit operator link**. The engine **never merges on an unverified
email**. Merged duplicates remain disabled tombstones with survivor lineage.
Design: [`docs/merge-unification-flow.md`](docs/merge-unification-flow.md).

## Configuration and secrets

Config and secrets are read from the **KV / DB store**, not from runtime
`os.getenv`. Environment variables are **bootstrap transport** only
(`CWL_IDP_BOOTSTRAP` → `deploy/bootstrap/bootstrap.yaml`). Database objects
use two-word-or-longer snake_case names (`idp_config_entries`,
`account_merge_audit`, `user_operation_lock_state`).

## Engine and licensing

- Engine: **Keycloak** (Apache-2.0). This repo: **Apache-2.0** (`LICENSE`).
- **Permissive OSS only** — no GPL/AGPL dependencies. The SCIM shim is
  Apache-2.0 code in this repository.

## Where decisions and standards live

| Path | What |
| --- | --- |
| [`docs/adr/`](docs/adr/README.md) | Accepted architecture decisions (0001–0008 on this branch) |
| [`docs/REFERENCES.md`](docs/REFERENCES.md) | APA 7th bibliography for ADR 0001–0007 |
| [`docs/doctoring/`](docs/doctoring/) | Feature-specific standards interpretation |
| [`docs/product-technical-gap-baseline.md`](docs/product-technical-gap-baseline.md) | Current buyer-visible product and technical gap register |
| [`docs/papers/`](docs/papers/README.md) | Offline copies of selected primary sources |
| [`docs/operations/`](docs/operations/) | Operator runbooks, including hourly product development |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Runtime topology and trust boundaries |
| [`docs/rp-onboarding.md`](docs/rp-onboarding.md) | RP onboarding |
| [`docs/passwordless-policy.md`](docs/passwordless-policy.md) | Passwordless realm invariants |

## Repository layout

| Path | What |
| --- | --- |
| `docker-compose.yml` | Standalone bring-up: Keycloak + Postgres + admin service (pinned by digest) |
| `deploy/keycloak/` | Portable Keycloak realm config-as-code and service-account bootstrap; application RPs are runtime desired state, not portable-realm content |
| `deploy/templates/` | Private deployment templates for preflight and desired state |
| `deploy/bootstrap/` | Bootstrap pointer to the KV/DB config store |
| `deploy/scripts/healthz.sh` | Cross-component readiness probe |
| `scripts/validate_realm.py` | Realm config-as-code validator |
| `services/account_unification/` | FastAPI admin service (link, merge, SCIM, federation, RP desired state) |
| `helm/cwl-idp/` | Helm chart for the same three components |
