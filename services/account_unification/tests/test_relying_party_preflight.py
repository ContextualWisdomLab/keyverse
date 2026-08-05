"""OIDC relying-party client preflight security and side-effect tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


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
