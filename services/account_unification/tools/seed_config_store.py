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
    KEY_MERGE_CONFLICT_POLICY,
    KEY_ZITADEL_API_BASE,
    KEY_ZITADEL_MGMT_TOKEN,
    KEY_ZITADEL_ORG_ID,
)
from app.kv_store import SqliteKvStore  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="../../deploy/bootstrap/idp_config_store.db")
    parser.add_argument("--namespace", default="account_unification")
    parser.add_argument("--api-base", default="http://localhost:8080")
    parser.add_argument("--org-id", default="dev-org")
    parser.add_argument("--mgmt-token", default="dev-placeholder-token")
    args = parser.parse_args()

    store = SqliteKvStore(args.db)
    store.put(args.namespace, KEY_ZITADEL_API_BASE, args.api_base)
    store.put(args.namespace, KEY_ZITADEL_ORG_ID, args.org_id)
    store.put(args.namespace, KEY_ZITADEL_MGMT_TOKEN, args.mgmt_token)
    store.put(args.namespace, KEY_MERGE_CONFLICT_POLICY, "survivor_wins")
    store.put(args.namespace, KEY_ALLOW_UNVERIFIED_LINK, "false")
    print(f"seeded {args.db} namespace={args.namespace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
