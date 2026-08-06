"""OIDC relying-party client preflight security and side-effect tests."""
from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import create_app
from app.relying_party import (
    RelyingPartyRegistration,
    _parse_registration,
    validate_relying_party_registration,
)


def _confidential_web_client() -> dict[str, object]:
    """Return one production-shaped confidential OIDC web client payload."""
    return {
        "clientId": "naruon-web",
        "name": "naruon-web",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": ["https://naruon.example/auth/callback"],
        "webOrigins": ["https://naruon.example"],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "https://naruon.example/auth/logout",
            "access.token.lifespan": "300",
            "backchannel.logout.session.required": "true",
            "require.pushed.authorization.requests": "false",
        },
        "fullScopeAllowed": False,
        "defaultClientScopes": ["basic", "profile", "email"],
    }


def _registration(**changes: object) -> RelyingPartyRegistration:
    """Return one parsed registration with optional top-level replacements."""
    payload = _confidential_web_client()
    payload.update(changes)
    return _parse_registration(payload)


def _assert_policy_error(
    registration: RelyingPartyRegistration,
    expected_field: str,
) -> None:
    """Assert one direct policy rejection is stable and bounded."""
    with pytest.raises(HTTPException) as raised:
        validate_relying_party_registration(registration)
    assert raised.value.status_code == 400
    assert str(raised.value.detail).startswith(expected_field)


def _assert_shape_error(payload: object, expected_detail: str) -> None:
    """Assert one manual JSON-shape rejection without framework reflection."""
    with pytest.raises(HTTPException) as raised:
        _parse_registration(payload)
    assert raised.value.status_code == 422
    assert raised.value.detail == expected_detail


def test_relying_party_preflight_accepts_secure_confidential_web_client(
    api,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """A secure client payload receives a readiness receipt without side effects."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    app.state.keycloak_api = api

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/clients/relying-parties:validate",
            json=_confidential_web_client(),
        )

    assert response.status_code == 200
    assert response.json() == {
        "registration": _confidential_web_client(),
        "ready_to_apply": True,
    }
    assert api.calls == []


def test_relying_party_preflight_requires_operator_authentication(
    operator_token: str,
) -> None:
    """The preflight remains inside the privileged operator boundary."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token

    with TestClient(app) as client:
        response = client.post(
            "/clients/relying-parties:validate",
            json=_confidential_web_client(),
        )

    assert response.status_code == 401


def test_relying_party_preflight_accepts_public_ipv6_client() -> None:
    """A public client can use canonical IPv6 and an explicit TLS port."""
    registration = _registration(
        publicClient=True,
        clientAuthenticatorType="none",
        redirectUris=["https://[2001:db8::1]:8443/auth/callback"],
        webOrigins=["https://[2001:db8::1]:8443"],
        attributes={
            **cast_attributes(_confidential_web_client()),
            "post.logout.redirect.uris": "https://[2001:db8::1]:8443/auth/logout",
        },
    )

    result = validate_relying_party_registration(registration)

    assert result.ready_to_apply is True
    assert result.registration.public_client is True


def cast_attributes(payload: dict[str, object]) -> dict[str, str]:
    """Return a typed copy of the test payload's string attribute mapping."""
    attributes = payload["attributes"]
    assert isinstance(attributes, dict)
    return {str(key): str(value) for key, value in attributes.items()}


@pytest.mark.parametrize(
    ("payload", "detail"),
    [
        ([], "body must be a JSON object"),
        ({1: "secret"}, "body contains a non-string field name"),
        (
            {**_confidential_web_client(), "attacker-secret": "do-not-reflect"},
            "body contains unsupported fields",
        ),
        (
            {key: value for key, value in _confidential_web_client().items() if key != "name"},
            "name is required",
        ),
        (
            {**_confidential_web_client(), "attributes": []},
            "attributes must be a JSON object",
        ),
        (
            {**_confidential_web_client(), "attributes": {1: "value"}},
            "attributes contains a non-string key",
        ),
        (
            {**_confidential_web_client(), "attributes": {"secret": 1}},
            "attributes must contain only string values",
        ),
        (
            {**_confidential_web_client(), "clientId": 7},
            "clientId must be a string",
        ),
        (
            {**_confidential_web_client(), "enabled": 1},
            "enabled must be a boolean",
        ),
        (
            {**_confidential_web_client(), "redirectUris": "https://example.test"},
            "redirectUris must be an array of strings",
        ),
        (
            {**_confidential_web_client(), "webOrigins": ["https://example.test", 7]},
            "webOrigins must be an array of strings",
        ),
    ],
)
def test_manual_parser_rejects_hostile_shapes_without_reflection(
    payload: object,
    detail: str,
) -> None:
    """Malformed JSON shapes fail with stable errors that do not echo values."""
    _assert_shape_error(payload, detail)
    assert "do-not-reflect" not in detail


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"clientId": ""}, "clientId"),
        ({"clientId": " naruon-web"}, "clientId"),
        ({"clientId": "x" * 64}, "clientId"),
        ({"clientId": "naruon\x00web"}, "clientId"),
        ({"clientId": "{{rp_name}}"}, "clientId"),
        ({"clientId": "Naruon"}, "clientId"),
        ({"clientId": "naruon_web"}, "clientId"),
        ({"clientId": "-naruon"}, "clientId"),
        ({"clientId": "naruon-"}, "clientId"),
        ({"name": "other-client"}, "name"),
        ({"enabled": False}, "enabled"),
        ({"protocol": "saml"}, "protocol"),
        ({"clientAuthenticatorType": "none"}, "clientAuthenticatorType"),
        (
            {"publicClient": True, "clientAuthenticatorType": "client-secret"},
            "clientAuthenticatorType",
        ),
        ({"standardFlowEnabled": False}, "standardFlowEnabled"),
        ({"implicitFlowEnabled": True}, "implicitFlowEnabled"),
        ({"directAccessGrantsEnabled": True}, "directAccessGrantsEnabled"),
        ({"serviceAccountsEnabled": True}, "serviceAccountsEnabled"),
        ({"fullScopeAllowed": True}, "fullScopeAllowed"),
    ],
)
def test_client_and_flow_policy_rejects_unsafe_profiles(
    changes: dict[str, object],
    field: str,
) -> None:
    """Client identity, authentication, and OAuth flow policy fail closed."""
    _assert_policy_error(_registration(**changes), field)


@pytest.mark.parametrize(
    "redirect_uris",
    [[], [f"https://naruon.example/callback/{index}" for index in range(17)]],
)
def test_redirect_uri_list_is_bounded(redirect_uris: list[str]) -> None:
    """Redirect registration cannot allocate an empty or unbounded URI list."""
    _assert_policy_error(_registration(redirectUris=redirect_uris), "redirectUris")


def test_redirect_uri_list_rejects_duplicates() -> None:
    """Duplicate redirect URI text is rejected before origin comparison."""
    uri = "https://naruon.example/auth/callback"
    _assert_policy_error(_registration(redirectUris=[uri, uri]), "redirectUris")


@pytest.mark.parametrize(
    "uri",
    [
        "https://*.example/auth/callback",
        "https://naruon.example/auth+callback",
        "https://naruon.example\\auth",
        "https://naruon.example/auth callback",
        "https://naruon.example/auth%ZZ",
        "https://naruon.example/auth%00callback",
        "https://naruon.example/auth/%2e%2e/callback",
        "https://naruon.example/auth%2Fcallback",
        "https://naruon.example/auth%5ccallback",
        "https://[2001:db8::1/auth",
        "https://naruon.example:invalid/auth",
        "http://naruon.example/auth/callback",
        "https:///auth/callback",
        "https://user@naruon.example/auth/callback",
        "https://naruon.example/auth/callback?next=/admin",
        "https://naruon.example/auth/callback#fragment",
        "https://naruon.example:0/auth/callback",
        "https://나루온.example/auth/callback",
        "https://naruon.example./auth/callback",
        "https://-naruon.example/auth/callback",
        "https://fe80::1%25eth0/auth/callback",
        "https://naruon.example/auth/../callback",
    ],
)
def test_redirect_uri_rejects_ambiguous_or_unsafe_network_syntax(uri: str) -> None:
    """Unsafe redirect syntax is rejected before a registration reaches Keycloak."""
    _assert_policy_error(_registration(redirectUris=[uri]), "redirectUris")


def test_web_origin_rejects_paths() -> None:
    """A CORS origin cannot contain a path even when it is otherwise HTTPS."""
    _assert_policy_error(
        _registration(webOrigins=["https://naruon.example/app"]),
        "webOrigins",
    )


@pytest.mark.parametrize(
    "web_origins",
    [[], [f"https://app{index}.example" for index in range(17)]],
)
def test_web_origin_list_is_bounded(web_origins: list[str]) -> None:
    """The CORS origin set is required and bounded."""
    _assert_policy_error(_registration(webOrigins=web_origins), "webOrigins")


def test_web_origin_list_rejects_duplicates() -> None:
    """Duplicate origin text is rejected before set normalization."""
    origin = "https://naruon.example"
    _assert_policy_error(_registration(webOrigins=[origin, origin]), "webOrigins")


def test_web_origins_must_exactly_cover_redirect_origins() -> None:
    """CORS origins cannot be broader or narrower than the redirect origins."""
    _assert_policy_error(
        _registration(webOrigins=["https://other.example"]),
        "webOrigins",
    )


def test_default_tls_port_is_normalized_for_origin_comparison() -> None:
    """Implicit and explicit TLS port 443 identify the same web origin."""
    registration = _registration(
        redirectUris=["https://naruon.example:443/auth/callback"],
        webOrigins=["https://naruon.example"],
    )

    result = validate_relying_party_registration(registration)

    assert result.ready_to_apply is True


@pytest.mark.parametrize(
    ("mutator", "field"),
    [
        (
            lambda attributes: {**attributes, "unsupported-secret": "do-not-reflect"},
            "attributes",
        ),
        (
            lambda attributes: {
                key: value
                for key, value in attributes.items()
                if key != "pkce.code.challenge.method"
            },
            "pkce.code.challenge.method",
        ),
        (
            lambda attributes: {**attributes, "pkce.code.challenge.method": "plain"},
            "pkce.code.challenge.method",
        ),
        (
            lambda attributes: {
                **attributes,
                "post.logout.redirect.uris": "http://naruon.example/logout",
            },
            "post.logout.redirect.uris",
        ),
        (
            lambda attributes: {**attributes, "access.token.lifespan": "٣٠٠"},
            "access.token.lifespan",
        ),
        (
            lambda attributes: {**attributes, "access.token.lifespan": "seconds"},
            "access.token.lifespan",
        ),
        (
            lambda attributes: {**attributes, "access.token.lifespan": "59"},
            "access.token.lifespan",
        ),
        (
            lambda attributes: {**attributes, "access.token.lifespan": "901"},
            "access.token.lifespan",
        ),
        (
            lambda attributes: {
                **attributes,
                "backchannel.logout.session.required": "false",
            },
            "backchannel.logout.session.required",
        ),
        (
            lambda attributes: {
                **attributes,
                "require.pushed.authorization.requests": "true",
            },
            "require.pushed.authorization.requests",
        ),
        (
            lambda attributes: {**attributes, "access.token.lifespan": ""},
            "access.token.lifespan",
        ),
        (
            lambda attributes: {
                **attributes,
                "access.token.lifespan": " 300",
            },
            "access.token.lifespan",
        ),
        (
            lambda attributes: {
                **attributes,
                "access.token.lifespan": "3\x000",
            },
            "access.token.lifespan",
        ),
        (
            lambda attributes: {
                **attributes,
                "access.token.lifespan": "{{token_lifespan}}",
            },
            "access.token.lifespan",
        ),
        (
            lambda attributes: {
                **attributes,
                "post.logout.redirect.uris": "https://logout.example/auth/logout",
            },
            "post.logout.redirect.uris",
        ),
    ],
)
def test_security_attributes_are_closed_bounded_and_consistent(
    mutator,
    field: str,
) -> None:
    """Every Keycloak security attribute is required and policy constrained."""
    attributes = cast_attributes(_confidential_web_client())
    mutated = mutator(attributes)
    _assert_policy_error(_registration(attributes=mutated), field)


def test_attribute_value_length_is_bounded() -> None:
    """An oversized security attribute is rejected before integer parsing."""
    attributes = cast_attributes(_confidential_web_client())
    attributes["access.token.lifespan"] = "1" * 2_049
    _assert_policy_error(_registration(attributes=attributes), "access.token.lifespan")


@pytest.mark.parametrize(
    "scopes",
    [
        [],
        [f"scope-{index}" for index in range(9)],
        ["basic", "profile", "profile", "email"],
        ["basic", "profile", "email", "roles"],
        ["basic", "profile"],
        ["basic", " profile", "email"],
        ["basic", "pro\x00file", "email"],
        ["basic", "{{scope}}", "email"],
        ["basic", "x" * 65, "email"],
    ],
)
def test_portable_scope_profile_is_exact(scopes: list[str]) -> None:
    """Only the exact portable basic/profile/email scope set is accepted."""
    _assert_policy_error(
        _registration(defaultClientScopes=scopes),
        "defaultClientScopes",
    )


def test_scope_order_does_not_change_the_exact_profile() -> None:
    """The portable set is semantic and does not require one JSON ordering."""
    registration = _registration(
        defaultClientScopes=["email", "basic", "profile"]
    )

    result = validate_relying_party_registration(registration)

    assert result.registration.default_client_scopes == ["email", "basic", "profile"]


def test_error_body_does_not_reflect_unknown_field_or_value(
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Hostile unknown fields never appear in the HTTP error response."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    payload = deepcopy(_confidential_web_client())
    payload["client_secret_do_not_reflect"] = "super-sensitive-value"

    with TestClient(app, headers=auth_header) as client:
        response = client.post("/clients/relying-parties:validate", json=payload)

    assert response.status_code == 422
    serialized = response.text
    assert "client_secret_do_not_reflect" not in serialized
    assert "super-sensitive-value" not in serialized
