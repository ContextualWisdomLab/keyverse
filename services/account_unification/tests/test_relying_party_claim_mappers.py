"""Closed OIDC relying-party audience and session-claim mapper tests."""
from __future__ import annotations

from copy import deepcopy

from fastapi.testclient import TestClient

from app.main import create_app

from .test_relying_party_preflight import _confidential_web_client


def _naruon_registration_with_mappers() -> dict[str, object]:
    """Return a production-shaped Naruon client with its closed claim profile."""
    payload = deepcopy(_confidential_web_client())
    payload.update(
        {
            "publicClient": True,
            "clientAuthenticatorType": "none",
            "protocolMappers": [
                {
                    "name": "keyverse-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.client.audience": "naruon-web",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                },
                {
                    "name": "keyverse-claim-role",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "consentRequired": False,
                    "config": {
                        "claim.name": "role",
                        "claim.value": "member",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                },
                {
                    "name": "keyverse-claim-org",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "consentRequired": False,
                    "config": {
                        "claim.name": "org",
                        "claim.value": "org-cwl",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                },
                {
                    "name": "keyverse-claim-workspace",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "consentRequired": False,
                    "config": {
                        "claim.name": "workspace",
                        "claim.value": "workspace-org-cwl",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                },
            ],
        }
    )
    return payload


def test_naruon_claim_mapper_profile_is_accepted(
    api,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """A reviewed Naruon mapper profile receives a side-effect-free receipt."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    app.state.keycloak_api = api
    payload = _naruon_registration_with_mappers()

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/clients/relying-parties:validate",
            json=payload,
        )

    assert response.status_code == 200
    assert response.json() == {
        "registration": payload,
        "ready_to_apply": True,
    }
    assert api.calls == []
