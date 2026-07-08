# account-unification service

FastAPI admin service for cwl-idp. Provides the two capabilities neither
ZITADEL nor an external ADFS offers natively:

- **inspect** one user's many external identities (`idp_links`), and
- **merge** two pre-existing accounts into one survivor — moving idp_links,
  role grants, and memberships/ownership, with a survivor-wins conflict policy,
  a tombstoned duplicate, and a full audit trail.

See [`../../docs/merge-unification-flow.md`](../../docs/merge-unification-flow.md)
for the algorithm and matching rules.

## Layout

| Module | Responsibility |
| --- | --- |
| `app/bootstrap.py` | Reads the one allowed env var (`CWL_IDP_BOOTSTRAP`) → opens the KV/DB config store |
| `app/kv_store.py` | Config/secret store (`idp_config_entries`); SQLite + in-memory backends |
| `app/config.py` | Typed `ServiceConfig` loaded only from the store (no runtime `os.getenv`) |
| `app/zitadel_client.py` | ZITADEL Management API `Protocol` + httpx implementation |
| `app/matching.py` | Match precedence: exact idp subject → verified email → explicit |
| `app/service.py` | Merge engine (survivor-wins) + identity inspection |
| `app/audit.py` | Append-only audit (`account_merge_audit`); in-memory + SQLite sinks |
| `app/api.py` / `app/main.py` | HTTP routes + `/healthz` |

## Run the tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Tests run entirely against an in-memory ZITADEL fake (`tests/mock_zitadel.py`) —
no live IdP needed.

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
| `zitadel_api_base` | ZITADEL Management API base URL |
| `zitadel_mgmt_token` | Management PAT (secret) |
| `zitadel_org_id` | Org id for `x-zitadel-orgid` |
| `merge_conflict_policy` | `survivor_wins` (default) |
| `allow_unverified_email_link` | hard-default `false` — never link/merge on unverified email |
