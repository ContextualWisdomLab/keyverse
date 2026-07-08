# cwl-idp — ecosystem central IdP

The **ContextualWisdom ecosystem's central Identity Provider**, a new standalone
component built on [**ZITADEL**](https://zitadel.com) (Apache-2.0). It:

- issues **OIDC / OAuth 2.1** to ecosystem relying parties (`naruon`,
  `pg-erd-cloud`, `semantic-data-portal`, `clearfolio`, `contextual-orchestrator`,
  `newsdom-api` via the WAF edge);
- is **passwordless-first**: FIDO2 / passkeys are the default and **passwords are
  disabled** for ecosystem-local accounts;
- runs a **SCIM v2 server** for inbound provisioning;
- **federates external IdPs in** — the employer **ADFS** (`sts.hssmartdev.com`)
  via SAML/WS-Fed, corporate **LDAP/AD**, and optional personal OIDC — with JIT
  provisioning and auto-link-by-**verified**-email; and
- adds an **account-unification** admin service to link one human's many external
  identities and to **merge** two pre-existing accounts into one.

> The employer ADFS is an **external, proprietary** IdP and a **compatibility
> target — not the hub**. cwl-idp is the hub.

RP client registrations and secrets live in the **IdP DB / KV**, never in an RP's
environment.

## Architecture

```
external IdPs  ──►  cwl-idp (ZITADEL)  ──►  OIDC to ecosystem RPs
  ADFS (SAML)       passwordless OIDC/OAuth
  LDAP/AD           FIDO2 passkeys
  OIDC (opt)        SCIM v2 server (inbound)
  HR/IGA (SCIM)     account-unification admin service
```

Full diagram and trust directions: [`docs/topology.md`](docs/topology.md).

## Repository layout

| Path | What |
| --- | --- |
| `docker-compose.yml` | Standalone bring-up: ZITADEL + Postgres + admin service (pinned by digest) |
| `deploy/zitadel/` | ZITADEL config-as-code: passwordless policy, SCIM, init steps |
| `deploy/templates/` | Management-API templates: employer ADFS (SAML), LDAP source, OIDC RP client |
| `deploy/bootstrap/` | Bootstrap pointer to the KV/DB config store |
| `deploy/scripts/healthz.sh` | Cross-component readiness probe |
| `services/account_unification/` | FastAPI admin service (link + merge) with unit tests |
| `helm/cwl-idp/` | Helm chart (ZITADEL subchart + admin service) |
| `docs/` | Topology, passwordless policy, merge flow, RP onboarding, papers |

## Quick start (standalone)

Requires Docker or Podman with the compose plugin.

```bash
cp .env.example .env          # populate values from your KV (bootstrap transport)
cp deploy/bootstrap/bootstrap.example.yaml deploy/bootstrap/bootstrap.yaml

docker compose up -d          # or: podman compose up -d
./deploy/scripts/healthz.sh   # waits for ZITADEL + admin service to be READY
```

- ZITADEL console: `http://localhost:8080`
- Admin service health: `http://localhost:8099/healthz`

The stack applies the **passwordless-first** login policy at first-run init
(`deploy/zitadel/init-steps.yaml`): `AllowUsernamePassword: false` and
`PasswordlessType: PASSWORDLESS_TYPE_ALLOWED`.

### Register the employer ADFS + LDAP

Apply the templates in `deploy/templates/` against the ZITADEL Management API
(they auto-link only on **verified** email). See
[`deploy/templates/README.md`](deploy/templates/README.md).

### Onboard a relying party

See [`docs/rp-onboarding.md`](docs/rp-onboarding.md).

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

- Engine: **ZITADEL** (Apache-2.0). This repo: **Apache-2.0** (`LICENSE`).
- **Permissive OSS only** — no GPL/AGPL dependencies.

## References

Standards and papers in [`docs/papers/`](docs/papers/) (NIST SP 800-63C
federation; RFC 7644 SCIM; OIDC Core; SAML V2.0), with citations.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
