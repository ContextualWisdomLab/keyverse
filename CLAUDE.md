# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

**keyverse** hosts **cwl-idp**, the ContextualWisdom ecosystem's central Identity Provider built on **Keycloak** (Apache-2.0). It issues OIDC/OAuth 2.1 to ecosystem relying parties (`naruon`, `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`, `contextual-orchestrator`, `newsdom-api`), federates external IdPs in (employer ADFS via SAML/WS-Fed, corporate LDAP/AD, optional personal OIDC), runs an inbound SCIM v2 provisioning shim, and is **passwordless-first** (FIDO2/passkeys; the password authenticator is removed from the login flow). cwl-idp is the hub; the employer ADFS is an external compatibility target, never the hub.

## Common commands

Make targets (work with docker or podman: `COMPOSE="podman compose" make up`):

```bash
make up               # bring up Keycloak + Postgres + admin service (docker compose up -d)
make down             # tear down (keeps volumes)
make logs             # follow logs
make ready            # poll readiness (deploy/scripts/healthz.sh)
make install          # pip install -e '.[dev]' for the admin service
make test             # run account-unification unit tests (pytest -q)
make lint             # ruff check + interrogate (docstring coverage)
make validate-realm   # python scripts/validate_realm.py deploy/keycloak/realm-cwl.json
make seed-bootstrap   # create a local sqlite KV bootstrap store for dev
```

Compose bring-up needs `.env` (from `.env.example`) and `deploy/bootstrap/bootstrap.yaml` (from `bootstrap.example.yaml`). Keycloak console: `http://localhost:8080`; admin service: `http://localhost:8099/healthz`.

Per-service, matching what CI runs (from `services/account_unification/`):

```bash
uv sync --locked --extra dev       # install locked deps
uv run ruff check app tests tools  # lint
uv run interrogate .               # docstring coverage gate (fail-under 100)
uv run pytest -q                   # all tests
uv run pytest tests/test_merge.py -q                       # one file
uv run pytest tests/test_merge.py::test_name -q            # one test
```

Run the admin service standalone (from `services/account_unification/`):

```bash
python tools/seed_config_store.py --db /tmp/idp_config_store.db
export CWL_IDP_BOOTSTRAP=/path/to/bootstrap.yaml   # points at the KV store
uvicorn app.main:app --port 8099
```

## CI gates (.github/workflows/ci.yml)

1. **account-unification-tests** — `uv sync --locked --extra dev`, then `ruff check app tests tools`, `interrogate .`, `pytest -q` (Python 3.12, working dir `services/account_unification`).
2. **realm-config-validates** — `python scripts/validate_realm.py deploy/keycloak/realm-cwl.json`. Fails if the realm export breaks policy invariants: passwordless browser flow bound with the WebAuthn passwordless authenticator and **no** password authenticator, registration/reset-password off, ADFS SAML IdP + LDAP source present, no real committed client secret (placeholders must be `__set_from_kv__`).
3. **compose-config-validates** — `docker compose -f docker-compose.yml config` with placeholder passwords.

CodeQL (python) also runs on push/PR. `.clusterfuzzlite/` is a discovery marker; the fuzz entrypoint is `services/account_unification/fuzz/fuzz_matching.py` (Atheris).

## Architecture

Three containers on two networks (`docker-compose.yml`; same shape in the Helm chart):

- **idp_database** — Postgres 17, Keycloak's system of record. Internal network only.
- **idp_engine** — Keycloak 26.3.2, `start --import-realm`; imports the passwordless-first `cwl` realm as-code from `deploy/keycloak/realm-cwl.json` on first boot. Health on management port 9000. TLS terminates at the WAF edge, so HTTP is enabled internally.
- **account_unification_service** — the only service under `services/`: a FastAPI admin service (Python ≥3.11) on port 8099. It talks to Keycloak exclusively through the **Admin REST API** (`app/keycloak_client.py`), authenticating with a confidential service-account client (client credentials, `realm-management` view-users/manage-users). It provides account **inspect/link/merge** plus the inbound **SCIM 2.0 shim** (`/scim/v2/Users` → Keycloak Admin API). Module responsibilities are tabled in `services/account_unification/README.md`; the merge algorithm and HTTP surface are in `docs/merge-unification-flow.md`.

Networks: `idp_internal_network` (DB + engine + admin service, never public) and `idp_edge_network` (only Keycloak OIDC endpoints and the admin/SCIM API, behind the WAF edge). Every component exposes a `/healthz`-style probe; `deploy/scripts/healthz.sh` gates on all of them (public-port signal is the realm's OIDC discovery document).

Tests run entirely against an in-memory Keycloak fake (`tests/mock_keycloak.py`) — no live IdP needed.

### Deployment layout

- `deploy/keycloak/` — realm config-as-code (`realm-cwl.json`) + `kcadm-bootstrap.sh`, which patches secrets/URLs from KV after import. Committed: non-secret structure. Patched from KV, never committed: ADFS metadata URL, LDAP bind credential, client secrets.
- `deploy/templates/` — Admin-API request-body templates for registering **additional** RPs/IdPs against a running realm (SAML IdP, LDAP source, OIDC RP client); `{{placeholders}}` resolved from KV.
- `deploy/bootstrap/` — the bootstrap pointer file (`bootstrap.yaml`) locating the KV/DB config store.
- `helm/cwl-idp/` — chart templating the same three components; Keycloak and Postgres are individually toggleable (`enabled: false` to use externally-managed ones). Secrets come from pre-created Kubernetes secrets populated from KV.
- The repo is **standalone AND submodule-embeddable**: a parent compose can `include:` this `docker-compose.yml`, or depend on the Helm chart.

## Key conventions

- **Config/secrets come from the KV/DB store, never runtime `os.getenv`.** Environment variables are bootstrap transport only — the admin service reads exactly one env var, `CWL_IDP_BOOTSTRAP`, pointing at the bootstrap file (`app/bootstrap.py` → `app/kv_store.py` → typed `ServiceConfig` in `app/config.py`, which fails loudly on missing keys). RP client registrations and secrets live in the IdP DB/KV, never in an RP's environment.
- **Never link or merge accounts on an unverified email.** Matching precedence is exact `(identity_provider, subject)` → verified email → explicit operator link; `allow_unverified_email_link` hard-defaults to `false`. Merges are survivor-wins, tombstone the duplicate (disable + `merged_into_user_id` attribute, never delete), and audit every step under one `audit_id`.
- **Passwordless invariant.** Never add a password authenticator to the bound browser flow in `realm-cwl.json`; `scripts/validate_realm.py` fails CI if one appears. Realm secrets in committed JSON must stay `__set_from_kv__`.
- **Permissive OSS only** — no GPL/AGPL dependencies (this is why the SCIM shim is in-repo rather than ZITADEL or the commercial scim-for-keycloak plugin).
- Container images are pinned by tag **and** digest (compose and Helm values).
- Database objects use two-word snake_case names (`idp_config_entries`, `account_merge_audit`).
- Python: ruff (line-length 100, target py311), pytest, and interrogate docstring coverage 100% (docstrings are required on modules/functions). Dependencies are locked with `uv` (`uv.lock`); CI installs with `uv sync --locked`, so update the lockfile when changing `pyproject.toml`.
