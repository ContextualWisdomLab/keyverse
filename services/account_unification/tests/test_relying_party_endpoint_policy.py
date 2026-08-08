"""HTTP boundary regressions for relying-party policy enforcement."""
from __future__ import annotations

from copy import deepcopy

from fastapi.testclient import TestClient

from app.main import create_app

from .test_relying_party_preflight import _confidential_web_client


def test_http_preflight_rejects_policy_invalid_protocol_mapper(
    api,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """The HTTP endpoint enforces mapper policy instead of shape parsing alone."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    app.state.keycloak_api = api
    payload = deepcopy(_confidential_web_client())
    payload["protocolMappers"] = [
        {
            "name": "private-attacker-value",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-script-based-protocol-mapper",
            "consentRequired": False,
            "config": {
                "script": "private-attacker-value",
            },
        }
    ]

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/clients/relying-parties:validate",
            json=payload,
        )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "protocolMappers.protocolMapper is not supported",
    }
    assert "private-attacker-value" not in response.text
    assert api.calls == []
