# CLAUDE.md

This file provides guidance to AI coding agents working in this repository.
Read `AGENTS.md`, `ARCHITECTURE.md`, and the relevant design and doctoring
records before editing code.

## What this repo is

**keyverse** hosts **cwl-idp**, the ContextualWisdom ecosystem's central Identity
Provider built on **Keycloak** (Apache-2.0). It issues OIDC/OAuth 2.1 to ecosystem
relying parties (`naruon`, `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`,
`contextual-orchestrator`, `newsdom-api`), federates external IdPs in (employer
ADFS via SAML, corporate LDAP/AD, optional personal OIDC), runs an inbound SCIM
v2 provisioning shim, and is **passwordless-first** (FIDO2/passkeys; the password
authenticator is removed from the login flow). cwl-idp is the hub; employer and
corporate identity systems are external deployment data and compatibility
targets, never the hub.

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
uv sync --locked --extra dev
uv run ruff check app tests tools
uv run interrogate .
uv run python -m compileall -q app tests tools
uv run coverage run --branch --source=app -m pytest -q
uv run coverage report --show-missing --fail-under=100
uv build --out-dir dist
uv run pytest tests/test_directory_federation_preflight.py -q
```

Run the admin service standalone from `services/account_unification/`:

```bash
python tools/seed_config_store.py --db /tmp/idp_config_store.db
export CWL_IDP_BOOTSTRAP=/path/to/bootstrap.yaml
uvicorn app.main:app --port 8099
```

## CI gates (`.github/workflows/ci.yml`)

1. **account-unification-tests** — locked dependencies, Ruff, 100% interrogate
   docstring coverage, Python compilation, complete pytest, 100% production
   statement and branch coverage, and a clean `uv build` distribution on Python
   3.12.
2. **realm-config-validates** — validates the portable realm export and parses
   every committed deployment-template JSON artifact. The bound browser flow
   must contain WebAuthn passwordless and no password authenticator;
   registration and reset-password remain off; no external IdP or user-storage
   federation may be committed; public RP access-token lifetime is bounded; real
   client secrets are forbidden.
3. **compose-config-validates** — validates `docker-compose.yml` with placeholder
   bootstrap passwords.

CodeQL, Semgrep, Security Scan, current-head review, and unresolved-thread gates
remain authoritative. `.clusterfuzzlite/` is a discovery marker; the fuzz
entrypoint is `services/account_unification/fuzz/fuzz_matching.py` (Atheris).

## Architecture

See `ARCHITECTURE.md` for the stable component, trust, data, and automation
boundaries.

Three runtime containers run on two networks (`docker-compose.yml`; the Helm
chart has the same shape):

- **idp_database** — Postgres 17, Keycloak's system of record. Internal network
  only.
- **idp_engine** — Keycloak 26, `start --import-realm`; imports the portable,
  passwordless-first `cwl` realm. Health is exposed on management port 9000.
  TLS terminates at the WAF edge, so HTTP is enabled internally.
- **account_unification_service** — FastAPI admin service (Python ≥3.11) on port
  8099. It talks to Keycloak only through the Admin REST API using a confidential
  service-account client. It provides account inspect/link/merge, inbound SCIM,
  passwordless registration, SAML/OIDC desired state, LDAP/AD preflight, and
  secret-free OIDC relying-party desired state.

Networks: `idp_internal_network` (database, engine, and admin service; never
public) and `idp_edge_network` (Keycloak OIDC endpoints and the admin/SCIM API
behind the WAF edge). Every component exposes a `/healthz`-style probe;
`deploy/scripts/healthz.sh` gates on all of them.

Tests run against in-memory fakes or deterministic pure validators; no live IdP
is required by the normal suite.

### Deployment layout

- `deploy/keycloak/` — portable realm config-as-code and
  `kcadm-bootstrap.sh`. The realm contains no employer-specific federation.
- `deploy/templates/` — explicit private deployment contracts. SAML/OIDC use
  Keyverse desired-state endpoints. `oidc-rp-naruon.json` is the reviewed public
  Naruon runtime profile; `oidc-rp-lineageweave.json` is the ADR-0009
  confidential profile that projects an account's same-client role and exact
  `org`/`workspace` attributes. LDAP is preflighted through Keyverse and then
  applied through private Keycloak Admin REST in this release. All
  `{{placeholders}}` are resolved from KV before use.
- `deploy/bootstrap/` — the bootstrap pointer locating the KV/DB config store.
- `helm/cwl-idp/` — the same three components; Keycloak and Postgres may be
  disabled in favor of externally managed services. Secrets come from
  pre-created Kubernetes secrets populated from KV.
- The repository is **standalone AND submodule-embeddable**: a parent compose can
  `include:` `docker-compose.yml`, or depend on `helm/cwl-idp`.

## Key conventions

- **Config and secrets come from the KV/DB store, never runtime `os.getenv`.**
  Environment variables are bootstrap transport only. The admin service reads
  `CWL_IDP_BOOTSTRAP`, which points at the bootstrap file and then the typed KV
  configuration.
- **SAML/OIDC federation is desired state.** Validate registrations through
  `POST /federation/identity-providers:validate`, persist with `PUT`, and
  converge through the federation service. Preflight must not write, call
  Keycloak, resolve DNS, or fetch metadata. Unknown and secret-bearing config is
  always redacted from responses.
- **LDAP/AD input is preflighted before private Keycloak apply.** Use
  `POST /federation/user-directories:validate`. The first profile requires
  LDAPS, `READ_ONLY`, no registration sync, no Kerberos, no trusted email,
  truststore enforcement, bounded latency, RFC 4514 DN syntax, and a closed
  single-valued config shape. Preflight performs no DNS lookup, socket, bind,
  search, storage write, or Keycloak call. Its redacted response is never an
  apply payload.
- **OIDC relying-party metadata is secret-free desired state.** Validate with
  `POST /clients/relying-parties:validate`, persist with `PUT`, and require exact
  post-mutation observation before accepting a receipt. The optional mapper
  profile permits static canonical claims, plus the separately reviewed
  ADR-0009 `lineageweave-web` account-derived profile. Never expand mapper
  classes, claim names, resource audiences, or token destinations by
  configuration alone.
- **Treat mapper normalization narrowly.** Ignore only a valid generated mapper
  `id` and canonicalize known mapper order. Unknown, malformed, duplicate, or
  semantically changed live mapper state is drift. Mapper configuration does not
  replace downstream token signature/issuer/expiry/audience acceptance tests.
- **Never link or merge accounts on an unverified email.** Matching precedence
  is exact `(identity_provider, subject)` → verified email → explicit operator
  link. Merges are survivor-wins, tombstone the duplicate, and audit every step
  under one `audit_id`.
- **Passwordless invariant.** Never add a password authenticator to the bound
  browser flow. The realm validator fails if one appears.
- **Permissive OSS only** — no GPL/AGPL dependencies.
- Container images are pinned by tag **and** digest.
- Database objects use descriptive two-word-or-longer snake_case names
  (`idp_config_entries`, `account_merge_audit`,
  `user_operation_lock_state`).
- Python uses Ruff, pytest, locked `uv` dependencies, 100% docstring coverage,
  and 100% production statement/branch coverage.
- Behavior changes use TDD: observe the intended RED failure before production
  code, then re-run focused and full verification.
- Update `CHANGELOG.md`, affected operator docs, architecture/specification, and
  `docs/doctoring` APA 7th references for every externally observable feature.

## Autonomous development and review

The hourly product-development workflow uses OpenCode through
`NVIDIA_NIM_API_KEY`, not Copilot Agent Tasks or `COPILOT_GITHUB_TOKEN`. Its
model workspace is disposable and credential-free, and it may publish only one
bounded draft PR after independent verification. Existing review agents and
their credential system are separate and must not be modified as a side effect.
No agent may self-approve, bypass branch protection, merge unverified work, tag,
or publish a release.
