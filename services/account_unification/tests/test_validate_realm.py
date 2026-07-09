"""Realm validator regression tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_validate_realm():
    script_path = Path(__file__).resolve().parents[3] / "scripts" / "validate_realm.py"
    spec = importlib.util.spec_from_file_location("validate_realm", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_realm_validation_errors_do_not_echo_sensitive_authenticator_terms():
    validator = _load_validate_realm()
    realm = {
        "realm": "cwl",
        "enabled": True,
        "browserFlow": "browser",
        "authenticationFlows": [
            {
                "alias": "browser",
                "authenticationExecutions": [
                    {"authenticator": "auth-password-form"},
                ],
            }
        ],
        "resetPasswordAllowed": True,
        "identityProviders": [
            {"alias": "employer-adfs", "providerId": "saml", "trustEmail": True}
        ],
        "components": {
            "org.keycloak.storage.UserStorageProvider": [{"providerId": "ldap"}]
        },
        "clients": [
            {
                "clientId": "ecosystem-rp-template",
                "attributes": {"pkce.code.challenge.method": "S256"},
            },
            {"clientId": "account-unification-svc", "serviceAccountsEnabled": True},
        ],
    }

    errors = validator.validate(realm)

    assert errors
    assert all("password" not in error.lower() for error in errors)
    assert any("credential-form" in error for error in errors)
