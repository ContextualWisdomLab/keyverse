"""Seed a local SQLite KV config store for standalone/dev bring-up.

This writes the ``idp_config_entries`` rows the service reads at runtime, so a
developer can run the service without a full secret manager. In production the
same keys live in the platform KV. Values here are DEV PLACEHOLDERS.

    python tools/seed_config_store.py [--db PATH] [--namespace NS]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import (  # noqa: E402
    KEY_ALLOW_UNVERIFIED_LINK,
    KEY_KEYCLOAK_CLIENT_ID,
    KEY_KEYCLOAK_CLIENT_SECRET,
    KEY_KEYCLOAK_REALM,
    KEY_KEYCLOAK_SERVER_URL,
    KEY_MERGE_CONFLICT_POLICY,
    KEY_OPERATOR_API_TOKEN,
    KEY_REGISTRATION_API_TOKEN,
)
from app.kv_store import SqliteKvStore  # noqa: E402


def main() -> int:
    """Write development Keycloak settings into a local SQLite KV store."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="../../deploy/bootstrap/idp_config_store.db")
    parser.add_argument("--namespace", default="account_unification")
    parser.add_argument("--server-url", default="http://localhost:8080")
    parser.add_argument("--realm", default="cwl")
    parser.add_argument("--client-id", default="account-unification-svc")
    parser.add_argument("--client-secret", default="dev-placeholder-secret")
    parser.add_argument("--operator-token", default="dev-operator-token")
    parser.add_argument("--registration-token", default="dev-registration-token")
    args = parser.parse_args()

    store = SqliteKvStore(args.db)
    store.put(args.namespace, KEY_KEYCLOAK_SERVER_URL, args.server_url)
    store.put(args.namespace, KEY_KEYCLOAK_REALM, args.realm)
    store.put(args.namespace, KEY_KEYCLOAK_CLIENT_ID, args.client_id)
    store.put(args.namespace, KEY_KEYCLOAK_CLIENT_SECRET, args.client_secret)
    store.put(args.namespace, KEY_MERGE_CONFLICT_POLICY, "survivor_wins")
    store.put(args.namespace, KEY_ALLOW_UNVERIFIED_LINK, "false")
    store.put(args.namespace, KEY_OPERATOR_API_TOKEN, args.operator_token)
    store.put(args.namespace, KEY_REGISTRATION_API_TOKEN, args.registration_token)
    print(f"seeded {args.db} namespace={args.namespace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
