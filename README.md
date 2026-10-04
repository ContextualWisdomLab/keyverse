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

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/keyverse)

**Central identity, federation, provisioning, and authorization control plane for the ContextualWisdomLab ecosystem.**

Keyverse is a standalone, embeddable identity platform built on Keycloak. It gives applications one standards-based place to consume passwordless authentication, external identity federation, SCIM provisioning, account unification, relying-party lifecycle, and issuer-side authorization decisions without making every product own Keycloak administration or identity-security policy.

Keyverse is designed for application teams, enterprise identity engineers, security operators, and integrators that need stable OIDC/OAuth identity contracts with explicit trust, secret, and authorization boundaries.

## What Keyverse provides

| Need | Keyverse responsibility |
| --- | --- |
| Passwordless local identity | WebAuthn/passkey-first authentication policy with no ordinary password authenticator for ecosystem-local accounts |
| Application identity | OIDC/OAuth relying-party lifecycle, exact redirect/origin validation, and downstream token-validation contracts |
| Enterprise federation | SAML/OIDC identity-provider onboarding and LDAPS directory integration through safe preflight and desired-state workflows |
| Provisioning | Inbound SCIM v2 lifecycle integration while preserving identity/merge invariants |
| Account continuity | Deterministic account linking, unification, and survivor-wins merge based on verified identity evidence |
| Authorization | Software-unit ACL, menu ABAC/RBAC decisions, SSO-combination scopes, and hierarchical org-path inheritance |
| Application credentials | Hashed-at-rest, purpose-bound programmable application tokens scoped to software units and APIs |
| Operations | Compose/Helm deployment, readiness, reconciliation, audit, rollback, and controlled configuration boundaries |

## Identity and authorization boundary

Keyverse is the **issuer and identity/authorization decision plane**. Relying parties remain responsible for enforcing application access.

Every application integrating with Keyverse must still validate the token and the application-specific decision context it consumes, including issuer, signature/algorithm, expiry, subject, audience, tenant/resource constraints, and the applicable authorization policy. Successful login is not by itself application authorization.

External employer/customer systems—ADFS, LDAP/Active Directory, other SAML/OIDC providers, HR/IGA systems—remain external sources. Customer-specific credentials and federation configuration are deployment data, not portable realm source.

```text
Enterprise identity sources
 SAML / OIDC / LDAP / SCIM
            │
            ▼
┌───────────────────────────────┐
│           Keyverse            │
│ identity + authorization      │
│ control plane                 │
├───────────────────────────────┤
│ Keycloak identity engine      │
│ passwordless policy           │
│ federation desired state      │
│ SCIM provisioning             │
│ account unification           │
│ RP lifecycle                  │
│ authorization decisions       │
│ audit / readiness             │
└───────────────┬───────────────┘
                │ OIDC/OAuth +
                │ bounded decisions
                ▼
     ContextualWisdomLab apps
           / customer RPs
```

Orgmetra remains the source of truth for employment and organization structure where that integration is used. Keyverse consumes bounded assignment snapshots for authorization; it does not become the authoritative organization database.

## Quick start

The standalone development stack uses Keycloak, PostgreSQL, and the Keyverse control service. Docker or Podman with a Compose-compatible workflow is supported by the repository configuration.

Trust boundaries: [`ARCHITECTURE.md`](ARCHITECTURE.md). Network diagram:
[`docs/topology.md`](docs/topology.md). Architecture decisions:
[`docs/adr/`](docs/adr/README.md). Standards bibliography:
[`docs/REFERENCES.md`](docs/REFERENCES.md).

No sibling repository checkout is required to start Keyverse.

```bash
cp .env.example .env
cp deploy/bootstrap/bootstrap.example.yaml deploy/bootstrap/bootstrap.yaml

docker compose up -d
./deploy/scripts/healthz.sh
```

With Podman:

```bash
podman compose up -d
./deploy/scripts/healthz.sh
```

Local endpoints in the default development stack:

- Keycloak administration surface: `http://localhost:8080`
- Keyverse control-service health: `http://localhost:8099/healthz`

The portable realm is passwordless-first and intentionally excludes customer-specific federation secrets and confidential relying-party credentials.

### Optional parent include

A parent Compose or Helm chart may include this repository's deployment
surfaces. Keyverse does not require naruon, gyeot, Orgmetra, or another sibling
checkout to start.

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

## Onboard a relying party

Start with [`docs/rp-onboarding.md`](docs/rp-onboarding.md). Relying-party desired state is secret-free; confidential client credentials remain a separate secret-management responsibility.

For authorization integration, use [`docs/authorization-onboarding.md`](docs/authorization-onboarding.md). Keyverse can make issuer-side decisions for:

- whether a subject may use a software unit / relying party;
- menu access after software-unit admission;
- closed ABAC constraints and capability-based RBAC;
- approved combinations of software units that may share one Keyverse session;
- org-path inheritance with more-specific assignment precedence and default deny.

Secrets and programmable application tokens do not inherit through the org hierarchy.

## Start brokered login from an application

An application backend can request a brokered-login start URL through the Keyverse helper:

```text
POST /federation/identity-providers:start-login
```

The helper resolves an enabled locally configured identity provider and returns a Keycloak authorization URL carrying `kc_idp_hint`. The relying party adds its PKCE material locally and performs the redirect. The helper does not fetch remote metadata or move federation ownership into the application.

Use the separately provisioned runtime token for this application-facing flow; operator credentials remain reserved for privileged administration and token-management operations.

## Programmable application tokens

Keyverse can mint purpose-bound application tokens for service/application workflows. Tokens are:

- stored only as hashes in the Keyverse-owned store;
- scoped to a software unit and explicit API capabilities;
- revocable and rotatable;
- auditable;
- separate from user password/passkey authentication and org-tree inheritance.

See [`docs/authorization-onboarding.md`](docs/authorization-onboarding.md) for the issue/verify/revoke lifecycle and the current public contract.

## External federation

The portable repository does not embed employer/customer federation configuration.

### SAML and external OIDC

Use Keyverse preflight and desired-state workflows to validate an external identity provider before apply. Trust policy, email-link behavior, endpoint profiles, and deployment-owned secrets remain explicit.

### LDAP / Active Directory

The current directory profile is LDAPS-only, read-only, Kerberos-disabled, and does not trust email by default. Preflight is deliberately side-effect-free: it does not perform DNS lookup, socket connection, bind, search, Keycloak mutation, or durable write.

LDAP preflight redacts `bindDn` and `bindCredential`; its redacted response
must never be used as the apply payload. Apply the original private file only.

See:

- [`docs/ldap-directory-onboarding.md`](docs/ldap-directory-onboarding.md)
- [`docs/federation-onboarding.md`](docs/federation-onboarding.md)
- [`deploy/keycloak/README.md`](deploy/keycloak/README.md)
- [`deploy/templates/README.md`](deploy/templates/README.md)

A successful preflight is configuration evidence, not proof that a production login or directory bind has succeeded.

## Account unification and merge

The account-unification service supports deterministic linking and survivor-wins merge while refusing weak identity evidence.

Matching precedence is:

```text
exact (identity provider, subject)
        ↓
verified email
        ↓
explicit operator link
```

Unverified email never authorizes automatic account linking or merge.

For local development of the service:

```bash
cd services/account_unification
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

See [`docs/merge-unification-flow.md`](docs/merge-unification-flow.md) for the lifecycle and audit model.

## Configuration and secret boundary

Runtime application code consumes configuration from the approved KV/DB boundary. Environment variables are bootstrap transport only; they are not the long-term source of truth for application secrets.

Portable realm/configuration source must not contain customer federation secrets, confidential RP credentials, raw programmable application tokens, or private apply payloads. Preflight responses and logs must not reflect protected credentials.

Database objects use two-word-or-longer snake_case names, such as
`idp_config_entries`, `account_merge_audit`, and `user_operation_lock_state`.

## Deployment modes

Keyverse is independently deployable through the repository's Compose and Helm surfaces and can also be integrated by a host through those published deployment contracts.

| Surface | Purpose |
| --- | --- |
| `docker-compose.yml` | Standalone Keycloak + PostgreSQL + Keyverse service stack |
| `helm/cwl-idp/` | Kubernetes-oriented deployment package |
| `deploy/keycloak/` | Portable Keycloak realm and identity configuration |
| `deploy/templates/` | Deployment preflight / desired-state templates |
| `deploy/bootstrap/` | Bootstrap pointer into the approved config/secret boundary |
| `services/account_unification/` | Keyverse-owned control service |

Deployment readiness distinguishes process/configuration reachability from complete external login, federation, provisioning, or RP acceptance evidence.

## Security posture

Keyverse is built around several non-negotiable identity invariants:

- passwordless-first local identity must not silently fall back to an ordinary password authenticator;
- exact provider subject identity is stronger evidence than email;
- unverified email cannot authorize automatic link/merge;
- issuer/audience/signature/expiry/subject validation is mandatory at relying parties;
- customer-specific secrets remain outside portable source;
- privileged desired-state mutation is separated from secret provisioning;
- duplicate or ambiguous remote identity/client/component matches fail closed;
- operation receipts are written only after re-observing the intended live outcome;
- tenant or application authorization is never inferred from client IDs, UUIDs, email, or federation source names alone.

Security and trust details live in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), and the [`docs/adr/`](docs/adr/) decision records.

## Verify the repository

The account-unification/control-service tests can be run from its package directory:

```bash
cd services/account_unification
uv sync --locked
uv run pytest -q
```

Repository CI additionally validates the portable realm and Compose configuration. Exact current-head protected checks and review evidence remain authoritative for integration; predecessor-head results do not transfer after source changes.

## Documentation map

| Goal | Start here |
| --- | --- |
| Product requirements | [`docs/PRD.md`](docs/PRD.md) |
| Technical requirements | [`docs/TRD.md`](docs/TRD.md) |
| Architecture and trust boundaries | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Architecture decisions | [`docs/adr/README.md`](docs/adr/README.md) |
| Relying-party onboarding | [`docs/rp-onboarding.md`](docs/rp-onboarding.md) |
| Authorization onboarding | [`docs/authorization-onboarding.md`](docs/authorization-onboarding.md) |
| Federation onboarding | [`docs/federation-onboarding.md`](docs/federation-onboarding.md) |
| Operability | [`docs/OPERABILITY.md`](docs/OPERABILITY.md) |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| Test strategy | [`docs/TEST_STRATEGY.md`](docs/TEST_STRATEGY.md) |
| Traceability | [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) |
| Documentation index | [`DOCUMENTATION.md`](DOCUMENTATION.md) |
| APA 7 standards bibliography | [`docs/REFERENCES.md`](docs/REFERENCES.md) |
| Product and technical gaps | [`docs/product-technical-gap-baseline.md`](docs/product-technical-gap-baseline.md) |
| Feature standards interpretation | [`docs/doctoring/`](docs/doctoring/) |
| Offline primary sources | [`docs/papers/`](docs/papers/README.md) |
| Operator runbooks | [`docs/operations/`](docs/operations/) |
| Passwordless invariants | [`docs/passwordless-policy.md`](docs/passwordless-policy.md) |
| Realm validation | [`scripts/validate_realm.py`](scripts/validate_realm.py) |
| Cross-component readiness | [`deploy/scripts/healthz.sh`](deploy/scripts/healthz.sh) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

## Contributing

Changes to identity, federation, provisioning, account merge, relying-party, or authorization behavior must preserve the repository's explicit trust boundaries and update tests, public contracts, architecture decisions, and operator documentation together. Contributor/agent procedure belongs in the repository's contributor guidance rather than the customer-facing product overview.

## License

Keyverse source is licensed under the [Apache License 2.0](LICENSE). The underlying Keycloak project is also Apache-2.0. Permissive OSS only: no GPL/AGPL dependencies. The SCIM shim is Apache-2.0 code in this repository. Third-party dependencies retain their own license terms and must remain compatible with ContextualWisdomLab's commercial-use policy.
