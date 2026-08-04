"""OIDC federation preflight security and side-effect tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.federation import (
    FEDERATION_PROVIDER_NAMESPACE,
    FederationService,
    IdentityProviderRegistration,
)
from app.kv_store import InMemoryKvStore
from app.main import create_app


def _oidc_body(provider_id: str = "oidc") -> dict[str, object]:
    """Return one secure, explicitly pinned OIDC desired-state body."""
    return {
        "provider_alias": "partner-oidc",
        "display_name": "Partner OIDC",
        "provider_id": provider_id,
        "enabled": True,
        "trust_email": False,
        "provider_config": {
            "issuer": "https://login.partner.example/tenant",
            "authorizationUrl": (
                "https://login.partner.example/tenant/oauth2/authorize"
            ),
            "tokenUrl": "https://login.partner.example/tenant/oauth2/token",
            "userInfoUrl": (
                "https://api.partner.example/oidc/userinfo?schema=standard"
            ),
            "logoutUrl": "https://login.partner.example/tenant/logout",
            "jwksUrl": "https://login.partner.example/tenant/oidc/jwks",
            "clientId": "keyverse-broker",
            "clientSecret": "partner-client-secret",
            "clientAuthMethod": "client_secret_basic",
            "validateSignature": "true",
            "useJwksUrl": "true",
            "pkceEnabled": "true",
            "pkceMethod": "S256",
            "defaultScope": "openid profile email",
            "syncMode": "IMPORT",
        },
    }


def _post_preflight(body: dict[str, object], api, auth_header, operator_token):
    """Post one OIDC preflight body and return its response and fresh store."""
    store = InMemoryKvStore()
    app = create_app(wire=False)
    app.state.federation_service = FederationService(store, api)
    app.state.operator_api_token = operator_token
    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/identity-providers:validate",
            json=body,
        )
    return response, store


def _assert_no_side_effects(store: InMemoryKvStore, api) -> None:
    """Assert that preflight did not persist or call the Keycloak test double."""
    assert store.get_all(FEDERATION_PROVIDER_NAMESPACE) == {}
    assert api.calls == []


@pytest.mark.parametrize("provider_id", ["oidc", "keycloak-oidc"])
def test_oidc_preflight_accepts_pinned_secure_configuration(
    provider_id: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Both generic OIDC broker types validate without side effects."""
    response, store = _post_preflight(
        _oidc_body(provider_id), api, auth_header, operator_token
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ready_to_apply"] is True
    config = payload["registration"]["provider_config"]
    assert config["issuer"] == "https://login.partner.example/tenant"
    assert config["authorizationUrl"].startswith("https://")
    assert config["tokenUrl"].startswith("https://")
    assert config["jwksUrl"].startswith("https://")
    assert config["clientId"] == "keyverse-broker"
    assert config["clientAuthMethod"] == "client_secret_basic"
    assert config["pkceEnabled"] == "true"
    assert config["pkceMethod"] == "S256"
    assert config["clientSecret"] == "<redacted>"
    assert "partner-client-secret" not in response.text
    _assert_no_side_effects(store, api)


def test_oidc_preflight_allows_optional_endpoints_to_be_absent(
    api, auth_header, operator_token
) -> None:
    """UserInfo and logout endpoints remain optional for ID-token-only providers."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config.pop("userInfoUrl")
    config.pop("logoutUrl")

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 200
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "required_field",
    [
        "issuer",
        "authorizationUrl",
        "tokenUrl",
        "jwksUrl",
        "clientId",
        "clientSecret",
        "clientAuthMethod",
        "validateSignature",
        "useJwksUrl",
        "pkceEnabled",
        "pkceMethod",
        "defaultScope",
    ],
)
def test_oidc_preflight_requires_complete_explicit_configuration(
    required_field: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Every security-critical OIDC field is required before persistence."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config.pop(required_field)

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert required_field in response.json()["detail"]
    assert "partner-client-secret" not in response.text
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize("discovery_key", ["fromUrl", "discoveryEndpoint"])
def test_oidc_preflight_rejects_remote_discovery_import(
    discovery_key: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Desired state cannot delegate endpoint selection or retrieval to runtime."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config[discovery_key] = (
        "https://login.partner.example/.well-known/openid-configuration"
    )

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert discovery_key in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    [
        ("issuer", "http://login.partner.example/tenant"),
        ("issuer", "https://login.partner.example/tenant?issuer=other"),
        ("issuer", "https://login.partner.example/tenant#fragment"),
        (
            "authorizationUrl",
            "http://login.partner.example/tenant/oauth2/authorize",
        ),
        ("tokenUrl", "http://login.partner.example/tenant/oauth2/token"),
        ("jwksUrl", "http://login.partner.example/tenant/oidc/jwks"),
        ("userInfoUrl", "http://api.partner.example/oidc/userinfo"),
        ("logoutUrl", "http://login.partner.example/tenant/logout"),
        ("authorizationUrl", "https://[broken"),
        (
            "jwksUrl",
            "https://login.partner.example/tenant/oidc/jwks%0d%0aInjected",
        ),
    ],
)
def test_oidc_preflight_rejects_unsafe_issuer_and_endpoints(
    field_name: str,
    unsafe_value: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """OIDC issuer and network locations fail closed on unsafe material."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config[field_name] = unsafe_value

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert unsafe_value not in response.text
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("validateSignature", "false"),
        ("validateSignature", "sometimes"),
        ("useJwksUrl", "false"),
        ("useJwksUrl", "yes"),
        ("pkceEnabled", "false"),
        ("pkceEnabled", "yes"),
    ],
)
def test_oidc_preflight_requires_strict_enabled_security_flags(
    field_name: str,
    field_value: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Signature, JWKS, and PKCE controls must be explicit strict booleans."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config[field_name] = field_value

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize("pkce_method", ["plain", "s256", ""])
def test_oidc_preflight_requires_pkce_s256(
    pkce_method: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Authorization-code injection protection uses only the S256 method."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config["pkceMethod"] = pkce_method

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "pkceMethod" in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "client_auth_method",
    ["none", "private_key_jwt", "client_secret_jwt", ""],
)
def test_oidc_preflight_rejects_unimplemented_client_authentication(
    client_auth_method: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Unimplemented authentication methods cannot bypass key-management policy."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config["clientAuthMethod"] = client_auth_method

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "clientAuthMethod" in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    "default_scope",
    [
        "profile email",
        "openid openid profile",
        "openid  profile",
        'openid pro"file',
        "openid profile\\admin",
        "openid 프로필",
        "openid\tprofile",
    ],
)
def test_oidc_preflight_rejects_non_oidc_or_malformed_scope_sets(
    default_scope: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Scope strings follow RFC 6749 and contain exactly one openid token."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config["defaultScope"] = default_scope

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "defaultScope" in response.json()["detail"]
    _assert_no_side_effects(store, api)


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("clientId", ""),
        ("clientId", " keyverse-broker"),
        ("clientId", "keyverse\x00broker"),
        ("clientSecret", ""),
        ("clientSecret", "partner-client-secret "),
        ("clientSecret", "partner\x7fsecret"),
    ],
)
def test_oidc_preflight_rejects_ambiguous_client_credentials(
    field_name: str,
    field_value: str,
    api,
    auth_header,
    operator_token,
) -> None:
    """Broker client credentials are non-empty, bounded, and control-free."""
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config[field_name] = field_value

    response, store = _post_preflight(body, api, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    if field_value:
        assert field_value not in response.text
    _assert_no_side_effects(store, api)


def test_oidc_put_rejects_invalid_configuration_before_mutation(api) -> None:
    """The mutation boundary shares OIDC validation before storage or Keycloak."""
    store = InMemoryKvStore()
    federation = FederationService(store, api)
    body = _oidc_body()
    config = body["provider_config"]
    assert isinstance(config, dict)
    config["pkceEnabled"] = "false"
    registration = IdentityProviderRegistration.model_validate(body)

    with pytest.raises(HTTPException) as error:
        federation.put_registration("partner-oidc", registration)

    assert error.value.status_code == 400
    _assert_no_side_effects(store, api)


def test_oidc_deployment_template_renders_to_a_valid_registration(api) -> None:
    """The committed partner template matches the closed desired-state contract."""
    repository_root = Path(__file__).resolve().parents[3]
    template_path = repository_root / "deploy" / "templates" / "oidc-idp-partner.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))
    replacements = {
        "{{partner_oidc_issuer}}": "https://login.partner.example/tenant",
        "{{partner_oidc_authorization_url}}": (
            "https://login.partner.example/tenant/oauth2/authorize"
        ),
        "{{partner_oidc_token_url}}": (
            "https://login.partner.example/tenant/oauth2/token"
        ),
        "{{partner_oidc_userinfo_url}}": (
            "https://api.partner.example/oidc/userinfo"
        ),
        "{{partner_oidc_jwks_url}}": (
            "https://login.partner.example/tenant/oidc/jwks"
        ),
        "{{partner_oidc_client_id}}": "keyverse-broker",
        "{{partner_oidc_client_secret}}": "partner-client-secret",
    }
    config = template["provider_config"]
    for config_key, config_value in list(config.items()):
        if config_value in replacements:
            config[config_key] = replacements[config_value]

    registration = IdentityProviderRegistration.model_validate(template)
    result = FederationService(InMemoryKvStore(), api).validate_registration(
        registration
    )

    assert template["trust_email"] is False
    assert result.ready_to_apply is True
    assert result.registration.provider_config["clientSecret"] == "<redacted>"
    assert api.calls == []
