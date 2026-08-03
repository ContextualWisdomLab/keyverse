"""Seed a standalone SQLite KV configuration store for local development.

The tool writes the same two-word snake_case entries consumed by the service.
Values are development placeholders; production deployments populate the
platform KV and provide only the bootstrap pointer to the process.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import (  # noqa: E402
    KEY_ALLOW_UNVERIFIED_LINK,
    KEY_AUDIT_DATABASE_PATH,
    KEY_KEYCLOAK_CLIENT_ID,
    KEY_KEYCLOAK_CLIENT_SECRET,
    KEY_KEYCLOAK_REALM,
    KEY_KEYCLOAK_SERVER_URL,
    KEY_MERGE_CONFLICT_POLICY,
    KEY_OPERATOR_API_TOKEN,
    KEY_REGISTRATION_ACTION_LIFESPAN_SECONDS,
    KEY_REGISTRATION_API_TOKEN,
    KEY_REGISTRATION_CLIENT_ID,
    KEY_REGISTRATION_REDIRECT_URI,
)
from app.kv_store import SqliteKvStore  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser for local configuration seeding."""
    parser = argparse.ArgumentParser(
        description="Seed the Keyverse standalone SQLite KV store."
    )
    parser.add_argument(
        "--db",
        default="../../deploy/bootstrap/idp_config_store.db",
    )
    parser.add_argument("--namespace", default="account_unification")
    parser.add_argument("--server-url", default="http://localhost:8080")
    parser.add_argument("--realm", default="cwl")
    parser.add_argument(
        "--client-id", default="account-unification-svc"
    )
    parser.add_argument(
        "--client-secret",
        default="dev-placeholder-secret",
    )
    parser.add_argument("--operator-token", default="dev-operator-token")
    parser.add_argument(
        "--registration-token",
        default="dev-registration-token",
    )
    parser.add_argument(
        "--registration-client-id",
        default="naruon-web",
    )
    parser.add_argument(
        "--registration-redirect-uri",
        default="https://naruon.example/auth/passkey-complete",
    )
    parser.add_argument(
        "--registration-action-lifespan-seconds",
        default="900",
    )
    parser.add_argument(
        "--audit-database-path",
        default="../../deploy/bootstrap/account_unification_audit.sqlite3",
    )
    return parser


def main() -> int:
    """Write development Keycloak settings into a local SQLite KV store."""
    args = _build_parser().parse_args()
    store = SqliteKvStore(args.db)
    try:
        entries = {
            KEY_KEYCLOAK_SERVER_URL: args.server_url,
            KEY_KEYCLOAK_REALM: args.realm,
            KEY_KEYCLOAK_CLIENT_ID: args.client_id,
            KEY_KEYCLOAK_CLIENT_SECRET: args.client_secret,
            KEY_MERGE_CONFLICT_POLICY: "survivor_wins",
            KEY_ALLOW_UNVERIFIED_LINK: "false",
            KEY_OPERATOR_API_TOKEN: args.operator_token,
            KEY_REGISTRATION_API_TOKEN: args.registration_token,
            KEY_REGISTRATION_CLIENT_ID: args.registration_client_id,
            KEY_REGISTRATION_REDIRECT_URI: args.registration_redirect_uri,
            KEY_REGISTRATION_ACTION_LIFESPAN_SECONDS: (
                args.registration_action_lifespan_seconds
            ),
            KEY_AUDIT_DATABASE_PATH: args.audit_database_path,
        }
        for entry_key, entry_value in entries.items():
            store.put(args.namespace, entry_key, entry_value)
    finally:
        store.close()
    print(f"seeded {args.db} namespace={args.namespace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
