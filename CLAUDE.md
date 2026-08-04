# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## What this repo is

**keyverse** hosts **cwl-idp**, the ContextualWisdom ecosystem's central Identity
Provider built on **Keycloak** (Apache-2.0). It issues OIDC/OAuth 2.1 to ecosystem
relying parties (`naruon`, `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`,
`contextual-orchestrator`, `newsdom-api`), federates external IdPs in (employer
ADFS via SAML, corporate LDAP/AD, optional personal OIDC), runs an inbound SCIM
v2 provisioning shim, and is **passwordless-first** (FIDO2/passkeys; the password
authenticator is removed from the login flow). cwl-idp is the hub; employer ADFS
is external deployment data and a compatibility target, never the hub.

## Common commands

Make targets work with Docker or Podman (`COMPOSE="podman compose" make up`):

```bash
make up               # bring up Keycloak + Postgres + admin service
make down             # tear down while retaining volumes
make logs             # follow logs
make ready            # poll readiness (deploy/scripts/healthz.sh)
make install          # install the admin service development environment
make test             # run account-unification unit tests
make lint             # run Ruff + interrogate docstring coverage
make validate-realm   # validate deploy/keycloak/realm-cwl.json
make seed-bootstrap   # create a local SQLite KV bootstrap store
```

Compose bring-up needs `.env` (from `.env.example`) and
`deploy/bootstrap/bootstrap.yaml` (from `bootstrap.example.yaml`). Keycloak
console: `http://localhost:8080`; admin service:
`http://localhost:8099/healthz`.

Per-service commands matching CI, from `services/account_unification/`:

```bash
uv sync --locked --extra dev       # install locked dependencies
uv run ruff check app tests tools  # lint
uv run interrogate .               # docstring coverage gate (fail-under 100)
uv run pytest -q                   # all tests
uv run pytest tests/test_merge.py -q
uv run pytest tests/test_merge.py::test_name -q
```

Run the admin service standalone from `services/account_unification/`:

```bash
python tools/seed_config_store.py --db /tmp/idp_config_store.db
export CWL_IDP_BOOTSTRAP=/path/to/bootstrap.yaml
uvicorn app.main:app --port 8099
```

## CI gates (`.github/workflows/ci.yml`)

1. **account-unification-tests** — `uv sync --locked --extra dev`, then
   `ruff check app tests tools`, `interrogate .`, and `pytest -q` on Python 3.12.
2. **realm-config-validates** — validates the portable realm export. The bound
   browser flow must contain WebAuthn passwordless and no password
   authenticator; registration and reset-password remain off; no external IdP or
   user-storage federation may be committed; public RP access-token lifetime is
   bounded; real client secrets are forbidden.
3. **compose-config-validates** — validates `docker-compose.yml` with placeholder
   bootstrap passwords.

CodeQL also runs on push and pull requests. `.clusterfuzzlite/` is a discovery
marker; the fuzz entrypoint is
`services/account_unification/fuzz/fuzz_matching.py` (Atheris).

## Architecture

Three containers run on two networks (`docker-compose.yml`; the Helm chart has
the same shape):

- **idp_database** — Postgres 17, Keycloak's system of record. Internal network
  only.
- **idp_engine** — Keycloak 26, `start --import-realm`; imports the portable,
  passwordless-first `cwl` realm from `deploy/keycloak/realm-cwl.json`. Health is
  exposed on management port 9000. TLS terminates at the WAF edge, so HTTP is
  enabled internally.
- **account_unification_service** — the FastAPI admin service (Python ≥3.11) on
  port 8099. It talks to Keycloak only through the Admin REST API using a
  confidential service-account client. It provides account inspect/link/merge,
  inbound SCIM 2.0, passwordless registration, and external-IdP desired-state
  validation/reconciliation.

Networks: `idp_internal_network` (database, engine, and admin service; never
public) and `idp_edge_network` (Keycloak OIDC endpoints and the admin/SCIM API
behind the WAF edge). Every component exposes a `/healthz`-style probe;
`deploy/scripts/healthz.sh` gates on all of them.

Tests run against an in-memory Keycloak fake; no live IdP is required.

### Deployment layout

- `deploy/keycloak/` — portable realm config-as-code and
  `kcadm-bootstrap.sh`. The realm contains no employer-specific federation.
- `deploy/templates/` — explicit deployment contracts. The employer SAML
  template uses the Keyverse desired-state API; LDAP and RP-client templates
  document their Keycloak Admin REST endpoints. All `{{placeholders}}` are
  resolved from KV before use.
- `deploy/bootstrap/` — the bootstrap pointer locating the KV/DB config store.
- `helm/cwl-idp/` — the same three components; Keycloak and Postgres may be
  disabled in favor of externally managed services. Secrets come from
  pre-created Kubernetes secrets populated from KV.
- The repository is **standalone AND submodule-embeddable**: a parent compose can
  `include:` `docker-compose.yml`, or depend on the Helm chart.

## Key conventions

- **Config and secrets come from the KV/DB store, never runtime `os.getenv`.**
  Environment variables are bootstrap transport only. The admin service reads
  `CWL_IDP_BOOTSTRAP`, which points at the bootstrap file and then the typed KV
  configuration.
- **External federation is desired state.** Validate registrations through
  `POST /federation/identity-providers:validate`, then persist with `PUT` and
  converge through the federation service. Preflight must not write, call
  Keycloak, resolve DNS, or fetch metadata. Unknown and secret-bearing config is
  always redacted from responses.
- **Never link or merge accounts on an unverified email.** Matching precedence
  is exact `(identity_provider, subject)` → verified email → explicit operator
  link. Merges are survivor-wins, tombstone the duplicate, and audit every step
  under one `audit_id`.
- **Passwordless invariant.** Never add a password authenticator to the bound
  browser flow. The realm validator fails if one appears.
- **Permissive OSS only** — no GPL/AGPL dependencies.
- Container images are pinned by tag **and** digest.
- Database objects use two-word snake_case names (`idp_config_entries`,
  `account_merge_audit`).
- Python uses Ruff (target py311), pytest, and 100% interrogate docstring
  coverage. Dependencies are locked with `uv`; update `uv.lock` whenever
  `pyproject.toml` changes.
