"""LDAP and Active Directory side-effect-free preflight tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def _active_directory_component() -> dict[str, object]:
    """Return one realistic read-only Active Directory component payload."""
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
            "connectionUrl": [
                "ldaps://ad-01.corp.example:636 "
                "ldaps://ad-02.corp.example:636"
            ],
            "usersDn": ["OU=Users,DC=corp,DC=example"],
            "bindDn": [
                "CN=svc-keycloak,OU=ServiceAccounts,DC=corp,DC=example"
            ],
            "bindCredential": ["rendered-private-value"],
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


def test_directory_preflight_accepts_read_only_ldaps_profile(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """A rendered enterprise directory payload receives a readiness receipt."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/user-directories:validate",
            json=_active_directory_component(),
        )

    assert response.status_code == 200
    assert response.json()["ready_to_apply"] is True
