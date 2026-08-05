"""Secret-redaction tests for malformed LDAP preflight request shapes."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


def _valid_component() -> dict[str, object]:
    """Return the smallest complete component accepted by directory preflight."""
    return {
        "name": "corp-ldap",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "enabled": ["true"],
            "priority": ["1"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "vendor": ["ad"],
            "connectionUrl": ["ldaps://ad.corp.example:636"],
            "usersDn": ["OU=Users,DC=corp,DC=example"],
            "bindDn": ["CN=svc-keycloak,DC=corp,DC=example"],
            "bindCredential": ["valid-private-value"],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "searchScope": ["2"],
            "trustEmail": ["false"],
            "useTruststoreSpi": ["always"],
            "connectionPooling": ["true"],
            "connectionTimeout": ["10000"],
            "readTimeout": ["10000"],
            "allowKerberosAuthentication": ["false"],
        },
    }


def _post(payload: object, auth_header: dict[str, str], operator_token: str):
    """Submit arbitrary JSON to the authenticated preflight surface."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    with TestClient(app, headers=auth_header) as client:
        return client.post(
            "/federation/user-directories:validate",
            json=payload,
        )


@pytest.mark.parametrize(
    ("payload_factory", "private_value"),
    [
        (
            lambda: {
                **_valid_component(),
                "config": {
                    **_valid_component()["config"],  # type: ignore[arg-type]
                    "bindCredential": "shape-private-value",
                },
            },
            "shape-private-value",
        ),
        (
            lambda: {
                **_valid_component(),
                "unexpectedPrivateField": "extra-private-value",
            },
            "extra-private-value",
        ),
        (lambda: ["body-private-value"], "body-private-value"),
    ],
)
def test_malformed_directory_request_never_echoes_private_input(
    payload_factory,
    private_value: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Shape errors use bounded field diagnostics rather than reflected input."""
    response = _post(payload_factory(), auth_header, operator_token)

    assert response.status_code == 422
    assert private_value not in response.text
