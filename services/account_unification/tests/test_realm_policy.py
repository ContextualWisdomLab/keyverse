"""Keycloak realm policy regression tests."""
from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import pytest


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
    realm_path = _repository_root() / "deploy" / "keycloak" / "cwl-realm.json"
    return json.loads(realm_path.read_text(encoding="utf-8"))


def _user_profile() -> dict:
    """Load the closed post-import product account-attribute profile."""
    profile_path = (
        _repository_root() / "deploy" / "keycloak" / "lineageweave-user-profile.json"
    )
    return json.loads(profile_path.read_text(encoding="utf-8"))


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
    assert validator.validate_user_profile(_user_profile()) == []


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


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("multivalued", True, "must be scalar"),
        ("permissions", {"view": ["admin"], "edit": ["admin", "user"]}, "admin-managed"),
        ("validations", {"length": {"max": "65"}}, "maximum length of 64"),
    ],
)
@pytest.mark.parametrize("attribute_name", ("org", "workspace"))
def test_product_account_attributes_are_constrained(
    attribute_name: str, field: str, value: object, expected: str
) -> None:
    """Authorization attributes stay scalar, bounded, and administrator-managed."""
    validator = _validator_module()
    profile = deepcopy(_user_profile())
    attribute = next(
        item for item in profile["attributes"] if item["name"] == attribute_name
    )
    attribute[field] = value

    errors = validator.validate_user_profile(profile)

    assert any(expected in error for error in errors)


def test_product_account_attributes_allow_unassigned_registration() -> None:
    """Registration may create an account before operator ABAC assignment."""
    validator = _validator_module()
    profile = _user_profile()
    for attribute in profile["attributes"]:
        if attribute["name"] in {"org", "workspace"}:
            attribute.pop("required", None)

    assert validator.validate_user_profile(profile) == []


@pytest.mark.parametrize("attribute_name", ("org", "workspace"))
@pytest.mark.parametrize(
    "required",
    ({}, {"roles": ["user"]}, {"roles": ["admin", "user"]}),
)
def test_product_account_attributes_cannot_be_required_at_creation(
    attribute_name: str, required: dict[str, object]
) -> None:
    """Product ABAC attributes cannot become user-required at creation time."""
    validator = _validator_module()
    profile = deepcopy(_user_profile())
    attribute = next(
        item for item in profile["attributes"] if item["name"] == attribute_name
    )
    attribute["required"] = required

    errors = validator.validate_user_profile(profile)

    assert any("must remain optional during account creation" in error for error in errors)


def test_product_account_attribute_policy_reports_every_independent_violation() -> None:
    """One malformed attribute shows every repair an operator must make."""
    validator = _validator_module()
    profile = deepcopy(_user_profile())
    attribute = next(item for item in profile["attributes"] if item["name"] == "org")
    attribute["multivalued"] = True
    attribute["permissions"] = {"view": ["admin"], "edit": ["admin", "user"]}
    attribute["required"] = {"roles": ["user"]}
    attribute["validations"] = {"length": {"max": 65}}

    errors = validator.validate_user_profile(profile)

    assert any("must be scalar" in error for error in errors)
    assert any("must be admin-managed" in error for error in errors)
    assert any("must remain optional during account creation" in error for error in errors)
    assert any("maximum length of 64" in error for error in errors)


def test_product_account_attribute_policy_accepts_keycloak_numeric_length_limit() -> None:
    """Keycloak's documented numeric JSON length maximum remains valid."""
    validator = _validator_module()
    profile = deepcopy(_user_profile())
    for attribute in profile["attributes"]:
        if attribute["name"] in {"org", "workspace"}:
            attribute["validations"]["length"]["max"] = 64

    assert validator.validate_user_profile(profile) == []


def test_product_account_attributes_cannot_be_omitted() -> None:
    """Every issued product claim has an explicit Keycloak account source."""
    validator = _validator_module()
    profile = deepcopy(_user_profile())
    profile["attributes"] = []

    errors = validator.validate_user_profile(profile)

    assert any("must define 'org'" in error for error in errors)
    assert any("must define 'workspace'" in error for error in errors)


def test_keycloak_26_profile_uses_the_closed_policy_representation() -> None:
    """The Admin API rejects a string DISABLED; null is Keycloak 26's closed mode."""
    validator = _validator_module()
    profile = deepcopy(_user_profile())

    assert "unmanagedAttributePolicy" not in profile
    assert {"username", "email", "firstName", "lastName"} <= {
        item["name"] for item in profile["attributes"]
    }

    profile["unmanagedAttributePolicy"] = "ENABLED"

    errors = validator.validate_user_profile(profile)

    assert any("must omit unmanagedAttributePolicy" in error for error in errors)


def test_reusable_client_template_does_not_name_naruon_host() -> None:
    """The generic RP template stays portable across ecosystem products."""
    template = _client(_realm(), "ecosystem-rp-template")
    serialized = json.dumps(template, sort_keys=True)
    assert "naruon.example" not in serialized
