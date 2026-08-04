#!/usr/bin/env python3
"""Upgrade the stored OIDC coverage fixture to the fail-closed desired-state contract."""
from __future__ import annotations

from pathlib import Path


TARGET = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "account_unification"
    / "tests"
    / "test_full_coverage_federation.py"
)

OLD = '''        "provider_config": {
            "issuer": "https://login.partner.example",
            "clientId": "keyverse",
            "clientSecret": "secret",
        },
'''

NEW = '''        "provider_config": {
            "issuer": "https://login.partner.example/tenant",
            "authorizationUrl": (
                "https://login.partner.example/tenant/oauth2/authorize"
            ),
            "tokenUrl": "https://login.partner.example/tenant/oauth2/token",
            "jwksUrl": "https://login.partner.example/tenant/oidc/jwks",
            "clientId": "keyverse",
            "clientSecret": "secret",
            "clientAuthMethod": "client_secret_basic",
            "validateSignature": "true",
            "useJwksUrl": "true",
            "pkceEnabled": "true",
            "pkceMethod": "S256",
            "defaultScope": "openid profile email",
        },
'''


def main() -> None:
    """Replace the single legacy fixture and fail closed on source drift."""
    content = TARGET.read_text(encoding="utf-8")
    count = content.count(OLD)
    if count != 1:
        raise RuntimeError(f"coverage OIDC fixture anchor count was {count}, expected 1")
    TARGET.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")


if __name__ == "__main__":
    main()
