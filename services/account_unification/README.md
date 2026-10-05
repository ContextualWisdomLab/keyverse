# account-unification service

FastAPI admin service for cwl-idp. Provides the capabilities neither Keycloak
nor an external ADFS offers natively:

- **inspect** one user's many external identities (Keycloak federated
  identities),
- **merge** two pre-existing accounts into one survivor — moving federated
  identities, role mappings (realm + client), and group memberships/ownership,
  with a survivor-wins conflict policy, a tombstoned duplicate, and a full audit
  trail, and
- a minimal **SCIM 2.0** inbound provisioning shim (`/scim/v2/Users`) that
  provisions into Keycloak via its Admin REST API,
- a hierarchical **authorization plane** for software-unit ACL, menu
  ABAC/RBAC, SSO combinations, and org-path inheritance,
- an app **start-login** helper for brokered IdP discovery, and
- hashed **programmable application tokens** scoped to one software unit.

See [`../../docs/merge-unification-flow.md`](../../docs/merge-unification-flow.md)
for the algorithm and matching rules.

## Layout

| Module | Responsibility |
| --- | --- |
| `app/bootstrap.py` | Reads the one allowed env var (`CWL_IDP_BOOTSTRAP`) → opens the KV/DB config store |
| `app/kv_store.py` | Config/secret store (`idp_config_entries`); SQLite + in-memory backends |
| `app/config.py` | Typed `ServiceConfig` loaded only from the store (no runtime `os.getenv`) |
| `app/keycloak_client.py` | Keycloak Admin REST API `Protocol` + httpx implementation |
| `app/matching.py` | Match precedence: exact idp subject → verified email → explicit |
| `app/service.py` | Merge engine (survivor-wins) + identity inspection |
| `app/scim.py` | Inbound SCIM 2.0 provisioning shim → Keycloak Admin API |
| `app/audit.py` | Append-only audit (`account_merge_audit`); in-memory + SQLite sinks |
| `app/api.py` / `app/main.py` | HTTP routes + `/healthz` |
| `app/org_authorization.py` | Hierarchical org-path, inheritance, menu, and SSO decisions |
| `app/authorization_plane.py` | Durable grants and PDP HTTP surface |
| `app/start_login.py` | App start-login / IdP discovery helper |
| `app/application_tokens.py` | Hashed programmable application tokens |

## Run the tests

```bash
uv sync --locked --extra dev
uv run pytest -q
```

Tests run entirely against an in-memory Keycloak fake (`tests/mock_keycloak.py`)
— no live IdP needed.

## Run the service (standalone)

```bash
# 1. Seed a local KV store (dev placeholders).
python tools/seed_config_store.py --db /tmp/idp_config_store.db

# 2. Point the bootstrap file at it (see deploy/bootstrap/bootstrap.example.yaml).
export CWL_IDP_BOOTSTRAP=/path/to/bootstrap.yaml

# 3. Serve.
uvicorn app.main:app --port 8099
curl -fsS localhost:8099/healthz
```

## Configuration keys (KV namespace `account_unification`)

| Key | Meaning |
| --- | --- |
| `keycloak_server_url` | Keycloak base URL (e.g. `http://localhost:8080`) |
| `keycloak_realm` | Realm the service manages (e.g. `cwl`) |
| `keycloak_client_id` | Confidential service-account client id |
| `keycloak_client_secret` | Service-account client secret (secret) |
| `merge_conflict_policy` | `survivor_wins` (default) |
| `allow_unverified_email_link` | hard-default `false` — never link/merge on unverified email |
