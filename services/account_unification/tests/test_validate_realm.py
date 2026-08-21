"""Realm validator regression tests."""
from __future__ import annotations

import importlib.util
import json
import runpy
import sys
from pathlib import Path

import pytest


def _script_path() -> Path:
    return Path(__file__).resolve().parents[3] / "scripts" / "validate_realm.py"


def _repository_root() -> Path:
    """Return the repository root from the account-unification tests."""
    return _script_path().parents[1]


def _load_validate_realm():
    script_path = _script_path()
    spec = importlib.util.spec_from_file_location("validate_realm", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_committed_policy_artifacts(realm_path: Path, profile_path: Path) -> None:
    """Copy the reviewed realm and user profile into isolated CLI inputs."""
    root = _repository_root()
    realm_path.write_text(
        (root / "deploy" / "keycloak" / "cwl-realm.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    profile_path.write_text(
        (root / "deploy" / "keycloak" / "lineageweave-user-profile.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )


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


def test_keycloak_authenticator_ids_are_preserved_without_log_taint_literals():
    validator = _load_validate_realm()
    source = _script_path().read_text(encoding="utf-8")

    assert validator.PASSKEY_AUTHENTICATOR == "webauthn-authenticator-passwordless"
    assert {
        "auth-password-form",
        "auth-username-password-form",
        "password",
    } <= validator.DISALLOWED_CREDENTIAL_AUTHENTICATORS
    assert '"webauthn-authenticator-passwordless"' not in source
    assert '"auth-password-form"' not in source
    assert '"auth-username-password-form"' not in source


def test_validator_helpers_cover_missing_flows_cycles_and_token_inputs() -> None:
    """Nested export flows and malformed lifespan values stay fail-closed."""
    validator = _load_validate_realm()
    realm = {
        "authenticationFlows": [
            {
                "alias": "outer",
                "authenticationExecutions": [
                    {"authenticator": "first-factor"},
                    {"flowAlias": "inner"},
                ],
            },
            {
                "alias": "inner",
                "authenticationExecutions": [
                    {"authenticator": "second-factor"},
                    {"flowAlias": "outer"},
                ],
            },
        ]
    }

    assert validator._executions(realm, "missing") == []
    assert validator._all_authenticators(realm, "outer") == {
        "first-factor",
        "second-factor",
    }
    assert validator._public_token_lifespan({"attributes": {}}) is None
    assert validator._public_token_lifespan(
        {"attributes": {"access.token.lifespan": []}}
    ) == -1
    assert validator._public_token_lifespan(
        {"attributes": {"access.token.lifespan": "10.5"}}
    ) == -1
    assert validator._public_token_lifespan(
        {"attributes": {"access.token.lifespan": " 10 "}}
    ) == 10


def test_realm_validator_reports_independent_security_drift() -> None:
    """A production-like export reports every independently dangerous drift."""
    validator = _load_validate_realm()
    realm = json.loads(
        (_repository_root() / "deploy/keycloak/cwl-realm.json").read_text(
            encoding="utf-8"
        )
    )
    clients = {client["clientId"]: client for client in realm["clients"]}
    template = clients["ecosystem-rp-template"]
    service_client = clients["account-unification-svc"]
    naruon = clients["naruon-web"]
    basic = next(scope for scope in realm["clientScopes"] if scope["name"] == "basic")

    realm["realm"] = "other"
    realm["enabled"] = False
    realm["registrationAllowed"] = True
    realm["verifyEmail"] = True
    realm.pop("smtpServer", None)
    realm["$schema"] = "not-importable"
    template["implicitFlowEnabled"] = True
    template["attributes"]["pkce.code.challenge.method"] = "plain"
    service_client["serviceAccountsEnabled"] = False
    service_client["secret"] = "committed-secret"
    basic["protocolMappers"] = []
    realm["defaultDefaultClientScopes"] = [
        scope for scope in realm["defaultDefaultClientScopes"] if scope != "basic"
    ]
    naruon["publicClient"] = False
    naruon["implicitFlowEnabled"] = True
    naruon["attributes"]["pkce.code.challenge.method"] = "plain"
    naruon["attributes"]["access.token.lifespan"] = "901"
    naruon["protocolMappers"] = [
        mapper
        for mapper in naruon["protocolMappers"]
        if mapper.get("protocolMapper") != "oidc-audience-mapper"
        and mapper.get("config", {}).get("claim.name") != "workspace"
    ]
    naruon["defaultClientScopes"] = [
        scope for scope in naruon["defaultClientScopes"] if scope != "basic"
    ]

    errors = set(validator.validate(realm))

    assert {
        "realm name must be 'cwl'",
        "realm must be enabled",
        "IdP-hosted registration must remain disabled; use the headless registration API",
        "verifyEmail requires a realm smtpServer; configure SMTP or disable verifyEmail",
        "RP template must not enable the implicit flow (OAuth 2.1)",
        "RP template must require PKCE S256",
        "account-unification-svc must enable service accounts",
        "client 'account-unification-svc' commits a non-placeholder secret",
        "'$'-annotation key '$schema' breaks Keycloak 26 realm import",
        "client scope 'basic' must include the oidc-sub-mapper",
        "'basic' must be a realm default client scope",
        "naruon-web must be a public (PKCE) client",
        "naruon-web must not enable the implicit flow",
        "naruon-web must require PKCE S256",
        "naruon-web access.token.lifespan must be an integer at or below 900 seconds",
        "naruon-web must include an audience mapper",
        "naruon-web must carry the hardcoded 'workspace' claim naruon's session contract requires",
        "naruon-web must assign the 'basic' default scope",
    } <= errors


def test_realm_validator_reports_missing_flow_and_required_clients() -> None:
    """A malformed export cannot hide missing execution or relying-party policy."""
    validator = _load_validate_realm()
    source = (_repository_root() / "deploy/keycloak/cwl-realm.json").read_text(
        encoding="utf-8"
    )

    no_browser = json.loads(source)
    no_browser.pop("browserFlow")
    assert "browserFlow must be set" in validator.validate(no_browser)

    empty_browser = json.loads(source)
    empty_browser["browserFlow"] = "empty-browser"
    empty_browser["authenticationFlows"].append(
        {"alias": "empty-browser", "authenticationExecutions": []}
    )
    assert "browserFlow 'empty-browser' has no executions defined" in validator.validate(
        empty_browser
    )

    required_clients_missing = json.loads(source)
    required_clients_missing["clients"] = [
        client
        for client in required_clients_missing["clients"]
        if client["clientId"]
        not in {"ecosystem-rp-template", "account-unification-svc"}
    ]
    errors = set(validator.validate(required_clients_missing))
    assert "OIDC RP client template 'ecosystem-rp-template' is missing" in errors
    assert "service-account client 'account-unification-svc' is missing" in errors


def test_user_profile_validator_reports_all_administrator_attribute_drift() -> None:
    """Closed account claims stay scalar, admin-controlled, and required."""
    validator = _load_validate_realm()
    profile = json.loads(
        (
            _repository_root() / "deploy/keycloak/lineageweave-user-profile.json"
        ).read_text(encoding="utf-8")
    )
    profile["unmanagedAttributePolicy"] = "ENABLED"
    profile["attributes"] = [
        attribute
        for attribute in profile["attributes"]
        if attribute["name"] not in {"email", "workspace"}
    ]
    org = next(attribute for attribute in profile["attributes"] if attribute["name"] == "org")
    org["multivalued"] = True
    org["permissions"] = {"view": ["admin"]}
    org["required"] = {}
    org["validations"] = {}

    errors = set(validator.validate_user_profile(profile))

    assert {
        "user profile must omit unmanagedAttributePolicy so Keycloak 26 disables unmanaged attributes",
        "user profile must retain Keycloak built-in account attributes when the Admin API replaces the complete profile",
        "user profile 'org' must be scalar",
        "user profile 'org' must be admin-managed",
        "user profile 'org' must require administrators",
        "user profile 'org' must have a maximum length of 64",
        "user profile must define 'workspace'",
    } <= errors


def test_main_accepts_an_explicit_profile_outside_the_realm_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Arbitrary realm validation can name its reviewed sibling-independent profile."""
    validator = _load_validate_realm()
    realm_path = tmp_path / "exported-realm.json"
    profile_path = tmp_path / "reviewed-profile.json"
    _write_committed_policy_artifacts(realm_path, profile_path)

    result = validator.main(["validate_realm.py", str(realm_path), str(profile_path)])

    assert result == 0
    assert f"OK: {realm_path}" in capsys.readouterr().out


def test_main_uses_the_default_committed_realm_and_profile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI default paths validate the committed policy artifacts."""
    validator = _load_validate_realm()
    monkeypatch.chdir(_repository_root())

    result = validator.main(["validate_realm.py"])

    assert result == 0
    assert "OK: deploy/keycloak/cwl-realm.json" in capsys.readouterr().out


def test_main_names_an_explicit_invalid_profile_in_its_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A malformed supplied profile cannot be hidden by an implicit sibling lookup."""
    validator = _load_validate_realm()
    realm_path = tmp_path / "exported-realm.json"
    profile_path = tmp_path / "reviewed-profile.json"
    _write_committed_policy_artifacts(realm_path, profile_path)
    profile_path.write_text("{", encoding="utf-8")

    result = validator.main(["validate_realm.py", str(realm_path), str(profile_path)])

    assert result == 1
    stderr = capsys.readouterr().err
    assert str(profile_path) in stderr
    assert "cannot parse" in stderr


def test_main_rejects_ambiguous_extra_path_arguments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The validator never silently ignores a second profile-like argument."""
    validator = _load_validate_realm()
    realm_path = tmp_path / "cwl-realm.json"
    profile_path = tmp_path / "lineageweave-user-profile.json"
    _write_committed_policy_artifacts(realm_path, profile_path)

    result = validator.main(
        ["validate_realm.py", str(realm_path), str(profile_path), "unexpected.json"]
    )

    assert result == 1
    assert "USAGE" in capsys.readouterr().err


def test_main_reports_realm_parse_and_profile_policy_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI users receive a bounded failure for unreadable and invalid artifacts."""
    validator = _load_validate_realm()
    malformed_realm = tmp_path / "malformed-realm.json"
    malformed_realm.write_text("{", encoding="utf-8")

    assert validator.main(["validate_realm.py", str(malformed_realm)]) == 1
    assert f"cannot parse {malformed_realm}" in capsys.readouterr().err

    realm_path = tmp_path / "cwl-realm.json"
    profile_path = tmp_path / "lineageweave-user-profile.json"
    _write_committed_policy_artifacts(realm_path, profile_path)
    profile_path.write_text("{}", encoding="utf-8")

    assert validator.main(["validate_realm.py", str(realm_path)]) == 1
    stderr = capsys.readouterr().err
    assert f"INVALID: {realm_path}" in stderr
    assert "user profile must define 'org'" in stderr


def test_main_reports_realm_policy_errors_when_profile_parse_also_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A missing profile does not hide independently detected realm errors."""
    validator = _load_validate_realm()
    realm_path = tmp_path / "invalid-realm.json"
    profile_path = tmp_path / "missing-profile.json"
    realm_path.write_text(json.dumps({"realm": "wrong"}), encoding="utf-8")

    assert validator.main(["validate_realm.py", str(realm_path), str(profile_path)]) == 1

    stderr = capsys.readouterr().err
    assert "realm name must be 'cwl'" in stderr
    assert f"cannot parse {profile_path}" in stderr


def test_script_entrypoint_honors_the_explicit_profile_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The executable entrypoint preserves the tested main-function behavior."""
    realm_path = tmp_path / "exported-realm.json"
    profile_path = tmp_path / "reviewed-profile.json"
    _write_committed_policy_artifacts(realm_path, profile_path)
    monkeypatch.setattr(sys, "argv", [str(_script_path()), str(realm_path), str(profile_path)])

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(_script_path()), run_name="__main__")

    assert raised.value.code == 0
