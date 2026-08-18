# cwl-idp — ecosystem central IdP

The **ContextualWisdom ecosystem's central Identity Provider**, a standalone
component built on [**Keycloak**](https://www.keycloak.org) (Apache-2.0). It:

- issues **OIDC / OAuth 2.1** to ecosystem relying parties (`naruon`,
  `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`, `contextual-orchestrator`,
  and `newsdom-api` through the WAF edge);
- is **passwordless-first**: FIDO2 / passkeys are the default and the **password
  authenticator is removed** from the login flow for ecosystem-local accounts;
- runs a **SCIM v2 server shim** for inbound provisioning into Keycloak;
- **federates external IdPs in** — employer ADFS via SAML, corporate LDAP/AD,
  and optional personal OIDC — while keeping unverified email ineligible for
  account linking; and
- adds an **account-unification** admin service to link one human's many external
  identities and to **merge** two pre-existing accounts into one.

> Employer ADFS and corporate directories are **external, proprietary**
> compatibility targets—not the hub. cwl-idp is the hub, and customer-specific
> federation remains deployment data rather than portable realm code.

RP client registrations and secrets live in the **IdP DB / KV**, never in an RP's
environment.

## Architecture

```text
external IdPs  ──►  cwl-idp (Keycloak)  ──►  OIDC to ecosystem RPs
  ADFS (SAML)       passwordless OIDC/OAuth
  LDAP/AD           FIDO2 passkeys
  OIDC (opt)        SCIM v2 shim (inbound)
  HR/IGA (SCIM)     account-unification admin service
```

Architecture and trust boundaries: [`ARCHITECTURE.md`](ARCHITECTURE.md). Full
network diagram: [`docs/topology.md`](docs/topology.md).

## Repository layout

| Path | What |
| --- | --- |
| `docker-compose.yml` | Standalone bring-up: Keycloak + Postgres + admin service (pinned by digest) |
| `deploy/keycloak/` | Portable Keycloak realm config-as-code, passwordless flows, shared scopes, concrete Naruon RP, and service-account bootstrap |
| `deploy/templates/` | Private deployment templates split between Keyverse preflight/desired state and explicit Keycloak Admin REST apply contracts |
| `deploy/bootstrap/` | Bootstrap pointer to the KV/DB config store |
| `deploy/scripts/healthz.sh` | Cross-component readiness probe |
| `scripts/validate_realm.py` | Realm config-as-code validator (CI gate) |
| `services/account_unification/` | FastAPI admin service (link + merge + SCIM + federation validation/desired state) with unit tests |
| `helm/cwl-idp/` | Helm chart (templated Keycloak + Postgres + admin service) |
| `docs/operations/` | Scheduled maintenance and product-development operating procedures |
| `docs/doctoring/` | Standards interpretation and APA 7th engineering traceability |
| `docs/` | Topology, passwordless policy, federation, merge flow, RP onboarding, and papers |

## Quick start (standalone)

Requires Docker or Podman with the compose plugin.

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

### Register external federation

The portable realm contains no employer ADFS, LDAP/AD source, or other
customer-specific federation. Render deployment values from KV and preflight
every private payload before apply:

- SAML and external OIDC:
  `POST /federation/identity-providers:validate`, followed by the Keyverse
  desired-state `PUT` and reconciliation flow.
- LDAP and Active Directory:
  `POST /federation/user-directories:validate`, followed by deployment-owned
  private Keycloak component apply. The first profile is LDAPS-only,
  read-only, Kerberos-disabled, and `trustEmail=false`.

LDAP preflight performs no DNS lookup, socket connection, bind, search, KV/DB
write, or Keycloak call. Its response redacts `bindDn` and `bindCredential` and
must never be used as the apply payload; apply the original private file only.

See [`docs/federation-onboarding.md`](docs/federation-onboarding.md),
[`deploy/keycloak/README.md`](deploy/keycloak/README.md), and
[`deploy/templates/README.md`](deploy/templates/README.md).

An application starts brokered login through
`POST /federation/identity-providers:start-login` and then adds PKCE locally.
See [`docs/authorization-onboarding.md`](docs/authorization-onboarding.md).

### Onboard a relying party

See [`docs/rp-onboarding.md`](docs/rp-onboarding.md). Software-unit ACL, menu
decisions, SSO combinations, and programmable application tokens are documented
in [`docs/authorization-onboarding.md`](docs/authorization-onboarding.md).

## Account unification & merge

```bash
cd services/account_unification
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Design: [`docs/merge-unification-flow.md`](docs/merge-unification-flow.md).
Matching precedence is **exact (idp, subject) → verified email → explicit link**,
and the engine **never merges on an unverified email**.

## Standalone AND submodule-embeddable

- **Standalone:** the compose file or the Helm chart.
- **Submodule:** add this repo as a git submodule and `include:` its
  `docker-compose.yml`, or depend on `helm/cwl-idp`. Every component exposes a
  `/healthz`-style readiness probe so the parent can gate on it.

## Configuration & secrets

Config and secrets are read from the **KV / DB store**, not from runtime
`os.getenv`. Environment variables are used **only as bootstrap transport** to
reach that store (`CWL_IDP_BOOTSTRAP` → `deploy/bootstrap/bootstrap.yaml`).
Database objects use two-word snake_case names (`idp_config_entries`,
`account_merge_audit`).

## Engine & licensing

- Engine: **Keycloak** (Apache-2.0). This repo: **Apache-2.0** (`LICENSE`).
- **Permissive OSS only** — no GPL/AGPL dependencies. cwl-idp deliberately does
  **not** use ZITADEL (AGPL-3.0) nor the commercial scim-for-keycloak plugin;
  the SCIM shim in this repo is our own Apache-2.0 code.

## References

Standards and papers live under `docs/papers/` and `docs/doctoring/`, including
NIST SP 800-63C federation, RFC 7644 SCIM, OIDC Core, SAML V2.0, and the LDAP
RFC 4511–4515 family.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

## Hourly OpenCode product development

At minute 41 UTC, and only when no pull request exists and the exact `main` SHA
is healthy, Keyverse may run one bounded OpenCode development cycle through a
loopback NVIDIA NIM credential broker. The model works from a disposable
`git archive` without `.git`, GitHub credentials, Actions OIDC, publication
authority, or the upstream NIM credential.

A fresh job independently validates the sealed patch and re-runs the complete
100% production docstring, statement, and branch coverage gates plus package,
realm, Compose, and provider-template checks. Only then may a dedicated
`OPENCODE_PRODUCT_DEVELOPMENT_TOKEN` create one draft PR. Existing review-agent
workflows and credentials are unchanged; the development workflow cannot
approve, merge, tag, or release.

Operations are documented in
[`docs/operations/hourly-product-development.md`](docs/operations/hourly-product-development.md).
Standards traceability and APA 7th references are recorded in
[`docs/doctoring/hourly-opencode-product-development.md`](docs/doctoring/hourly-opencode-product-development.md).
