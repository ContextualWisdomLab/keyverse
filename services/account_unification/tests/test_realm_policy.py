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


def test_portable_realm_contains_only_the_control_plane_service_client() -> None:
    """Runtime application relying parties are absent from portable import."""
    realm = _realm()

    assert {client.get("clientId") for client in realm["clients"]} == {
        "account-unification-svc"
    }
    assert realm["defaultDefaultClientScopes"] == ["basic", "profile", "email"]


def test_validator_rejects_runtime_application_clients() -> None:
    """A realm export cannot bypass Keyverse desired-state reconciliation."""
    validator = _validator_module()
    realm = deepcopy(_realm())
    realm["clients"].extend(
        [
            {"clientId": "ecosystem-rp-template"},
            {"clientId": "naruon-web", "publicClient": True},
            {"clientId": "unmanaged-web", "publicClient": True},
        ]
    )

    errors = validator.validate(realm)

    assert any("runtime application client 'ecosystem-rp-template'" in error for error in errors)
    assert any("runtime application client 'naruon-web'" in error for error in errors)
    assert any(
        "portable realm may contain only the account-unification-svc" in error
        for error in errors
    )
