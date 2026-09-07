"""Keycloak realm policy regression tests."""
from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import ModuleType


def _repository_root() -> Path:
    """Return the repository root from the service test package."""
    return Path(__file__).resolve().parents[3]


def _validator_module() -> ModuleType:
    """Load the repository realm validator as a Python module."""
    validator_path = _repository_root() / "scripts" / "validate_realm.py"
    spec = importlib.util.spec_from_file_location(
        "keyverse_validate_realm", validator_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load realm validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _realm() -> dict:
    """Load the committed Keycloak realm representation."""
    realm_path = _repository_root() / "deploy" / "keycloak" / "realm-cwl.json"
    return json.loads(realm_path.read_text(encoding="utf-8"))


def _client(realm: dict, client_id: str) -> dict:
    """Return one client representation by client ID."""
    return next(
        client
        for client in realm["clients"]
        if client.get("clientId") == client_id
    )


def test_committed_realm_passes_passwordless_policy() -> None:
    """The checked-in realm satisfies every fail-closed policy invariant."""
    validator = _validator_module()
    assert validator.validate(_realm()) == []


def test_bound_browser_flow_rejects_password_authenticator() -> None:
    """No nested execution reachable from browserFlow may accept a password."""
    validator = _validator_module()
    realm = deepcopy(_realm())
    credential_flow = next(
        flow
        for flow in realm["authenticationFlows"]
        if flow.get("alias") == "browser-passwordless-credentials"
    )
    credential_flow["authenticationExecutions"].append(
        {
            "authenticator": "auth-password-form",
            "authenticatorFlow": False,
            "requirement": "ALTERNATIVE",
            "priority": 20,
        }
    )

    errors = validator.validate(realm)

    assert any("disallowed credential-form authenticator" in error for error in errors)


def test_public_client_token_lifespan_is_bounded() -> None:
    """A public browser client cannot issue long-lived bearer access tokens."""
    validator = _validator_module()
    realm = deepcopy(_realm())
    _client(realm, "naruon-web")["attributes"]["access.token.lifespan"] = "901"

    errors = validator.validate(realm)

    assert any("access.token.lifespan" in error for error in errors)


def test_naruon_direct_access_grants_stays_disabled() -> None:
    """A later realm edit cannot silently restore the blocked ROPC grant."""
    validator = _validator_module()
    realm = deepcopy(_realm())
    _client(realm, "naruon-web")["directAccessGrantsEnabled"] = True

    errors = validator.validate(realm)

    assert any("Direct Access Grants" in error for error in errors)


def test_reusable_client_template_does_not_name_naruon_host() -> None:
    """The generic RP template stays portable across ecosystem products."""
    template = _client(_realm(), "ecosystem-rp-template")
    serialized = json.dumps(template, sort_keys=True)
    assert "naruon.example" not in serialized
