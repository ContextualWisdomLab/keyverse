"""LDAP and Active Directory side-effect-free preflight tests."""
from __future__ import annotations

import json
import socket
from copy import deepcopy
from pathlib import Path

import pytest
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


def _test_app(operator_token: str):
    """Return an unwired app with only the operator credential configured."""
    app = create_app(wire=False)
    app.state.operator_api_token = operator_token
    return app


def _post_preflight(
    body: dict[str, object],
    auth_header: dict[str, str],
    operator_token: str,
):
    """Post one component through the authenticated directory boundary."""
    app = _test_app(operator_token)
    with TestClient(app, headers=auth_header) as client:
        return client.post(
            "/federation/user-directories:validate",
            json=body,
        )


def test_directory_preflight_accepts_read_only_ldaps_profile(
    auth_header: dict[str, str], operator_token: str, api
) -> None:
    """A rendered enterprise directory payload receives a redacted receipt."""
    app = _test_app(operator_token)
    app.state.keycloak_api = api

    with TestClient(app, headers=auth_header) as client:
        response = client.post(
            "/federation/user-directories:validate",
            json=_active_directory_component(),
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ready_to_apply"] is True
    registration = payload["registration"]
    assert registration["providerId"] == "ldap"
    assert registration["providerType"] == (
        "org.keycloak.storage.UserStorageProvider"
    )
    config = registration["config"]
    assert config["bindCredential"] == ["<redacted>"]
    assert config["bindDn"] == ["<redacted>"]
    assert config["connectionUrl"] == [
        "ldaps://ad-01.corp.example:636 "
        "ldaps://ad-02.corp.example:636"
    ]
    assert "rendered-private-value" not in response.text
    assert "svc-keycloak" not in response.text
    assert api.calls == []


def test_directory_preflight_requires_operator_authentication(
    operator_token: str,
) -> None:
    """The privileged directory validation surface is never anonymous."""
    app = _test_app(operator_token)
    with TestClient(app) as client:
        missing = client.post(
            "/federation/user-directories:validate",
            json=_active_directory_component(),
        )
        wrong = client.post(
            "/federation/user-directories:validate",
            json=_active_directory_component(),
            headers={"Authorization": "Bearer wrong-token"},
        )

    assert missing.status_code == 401
    assert wrong.status_code == 403


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("name", "Corp LDAP"),
        ("name", "-corp-ldap"),
        ("name", "corp-ldap-"),
        ("name", "c" * 64),
        ("providerId", "kerberos"),
        ("providerType", "org.keycloak.storage.OtherProvider"),
    ],
)
def test_directory_preflight_rejects_invalid_component_identity(
    field_name: str,
    field_value: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Only the bounded LDAP user-storage component identity is accepted."""
    body = _active_directory_component()
    body[field_name] = field_value

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert field_value not in response.text


def test_directory_preflight_rejects_top_level_and_config_schema_drift(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """Unexpected representation fields and non-list config values fail closed."""
    extra_body = _active_directory_component()
    extra_body["parentId"] = "realm-id"
    scalar_body = _active_directory_component()
    scalar_body["config"]["enabled"] = "true"  # type: ignore[index]

    extra = _post_preflight(extra_body, auth_header, operator_token)
    scalar = _post_preflight(scalar_body, auth_header, operator_token)

    assert extra.status_code == 422
    assert scalar.status_code == 422


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("enabled", []),
        ("enabled", ["true", "false"]),
        ("unknownOption", ["value"]),
    ],
)
def test_directory_preflight_requires_one_known_value_per_config_key(
    field_name: str,
    field_value: list[str],
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Ambiguous multivalued and unknown Keycloak settings are rejected."""
    body = _active_directory_component()
    body["config"][field_name] = field_value  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]


def test_directory_preflight_requires_every_closed_profile_key(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """Removing any required Keycloak setting fails with a field-only error."""
    required_keys = tuple(_active_directory_component()["config"])
    for field_name in required_keys:
        body = _active_directory_component()
        body["config"].pop(field_name)  # type: ignore[union-attr]

        response = _post_preflight(body, auth_header, operator_token)

        assert response.status_code == 400
        assert field_name in response.json()["detail"]


def test_directory_preflight_rejects_unrendered_values_without_echoing_them(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """Deployment placeholders fail before they can reach Keycloak or logs."""
    body = _active_directory_component()
    body["config"]["bindCredential"] = [  # type: ignore[index]
        "{{ldap_bind_password}}"
    ]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "bindCredential" in response.json()["detail"]
    assert "ldap_bind_password" not in response.text


@pytest.mark.parametrize(
    "connection_urls",
    [
        "ldap://ad.corp.example:389",
        "ldaps://operator:secret@ad.corp.example:636",
        "ldaps://ad.corp.example:636?base=users",
        "ldaps://ad.corp.example:636#fragment",
        "ldaps://ad.corp.example:636/OU=Users",
        "ldaps://ad.corp.example:636\\OU=Users",
        "ldaps://ad.corp.example:636%0aInjected",
        "ldaps://ad.corp.example:70000",
        "ldaps://[broken:636",
        " ldaps://ad.corp.example:636",
        "ldaps://ad.corp.example:636 ",
        "ldaps://ad-01.example:636  ldaps://ad-02.example:636",
        "ldaps://ad.example:636 ldaps://ad.example:636",
    ],
)
def test_directory_preflight_rejects_unsafe_or_ambiguous_connection_urls(
    connection_urls: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Only unique, unambiguous LDAPS authorities enter the control plane."""
    body = _active_directory_component()
    body["config"]["connectionUrl"] = [connection_urls]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "connectionUrl" in response.json()["detail"]
    assert connection_urls not in response.text


@pytest.mark.parametrize(
    "connection_urls",
    [
        "ldaps://ad.corp.example",
        "ldaps://ad.corp.example:636/",
        "ldaps://[2001:db8::1]:636",
        "ldaps://ad-01.example:636 ldaps://ad-02.example:636",
    ],
)
def test_directory_preflight_accepts_supported_ldaps_authorities(
    connection_urls: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Hostname, IPv6, root path, and replica-list forms remain interoperable."""
    body = _active_directory_component()
    body["config"]["connectionUrl"] = [connection_urls]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 200
    assert response.json()["registration"]["config"]["connectionUrl"] == [
        connection_urls
    ]


@pytest.mark.parametrize(
    "field_name",
    ["usersDn", "bindDn"],
)
@pytest.mark.parametrize(
    "distinguished_name",
    [
        "CN=Smith\\, John+UID=123,OU=Users,DC=corp,DC=example",
        "CN=Leading\\ Space,OU=Users,DC=corp,DC=example",
        "CN=Trailing\\ ,OU=Users,DC=corp,DC=example",
        "1.2.840.113556.1.4.656=#04024869,DC=corp,DC=example",
    ],
)
def test_directory_preflight_accepts_rfc4514_dn_forms(
    field_name: str,
    distinguished_name: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Escaped, multivalued, numeric-OID, and hexadecimal DN forms pass."""
    body = _active_directory_component()
    body["config"][field_name] = [distinguished_name]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 200


@pytest.mark.parametrize(
    "distinguished_name",
    [
        "",
        "CN=User,,DC=corp,DC=example",
        "CN=User+,OU=Users,DC=corp,DC=example",
        "CN=Smith, John,OU=Users,DC=corp,DC=example",
        "CN=User\\",
        "CN=User\\0G,DC=corp,DC=example",
        "CN=#private,DC=corp,DC=example",
        "CN= User,DC=corp,DC=example",
        "CN=User ,DC=corp,DC=example",
        "CN=User\x00,DC=corp,DC=example",
        "CNUser,DC=corp,DC=example",
    ],
)
def test_directory_preflight_rejects_unsafe_distinguished_names(
    distinguished_name: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Ambiguous RFC 4514 text fails without exposing internal directory data."""
    body = _active_directory_component()
    body["config"]["bindDn"] = [distinguished_name]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "bindDn" in response.json()["detail"]
    if distinguished_name:
        assert distinguished_name not in response.text


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("usernameLDAPAttribute", "employee_id"),
        ("rdnLDAPAttribute", "2bad"),
        ("uuidLDAPAttribute", "objectGUID;binary"),
        ("userObjectClasses", "person, organizationalPerson, person"),
        ("userObjectClasses", "person,,user"),
        ("userObjectClasses", "person,organizationalPerson,user"),
    ],
)
def test_directory_preflight_rejects_invalid_schema_identifiers(
    field_name: str,
    field_value: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """LDAP descriptors and object-class lists use one closed lexical form."""
    body = _active_directory_component()
    body["config"][field_name] = [field_value]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]


def test_directory_preflight_accepts_numeric_oid_attribute(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """Numeric LDAP object identifiers remain valid attribute identifiers."""
    body = _active_directory_component()
    body["config"]["uuidLDAPAttribute"] = [  # type: ignore[index]
        "1.2.840.113556.1.4.656"
    ]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("enabled", "false"),
        ("enabled", "TRUE"),
        ("importEnabled", "false"),
        ("syncRegistrations", "true"),
        ("connectionPooling", "false"),
        ("trustEmail", "true"),
        ("allowKerberosAuthentication", "true"),
        ("editMode", "WRITABLE"),
        ("editMode", "UNSYNCED"),
        ("useTruststoreSpi", "ldapsOnly"),
        ("searchScope", "0"),
        ("vendor", "optional"),
    ],
)
def test_directory_preflight_rejects_insecure_policy_values(
    field_name: str,
    field_value: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """The first directory profile is imported, read-only, and fail-closed."""
    body = _active_directory_component()
    body["config"][field_name] = [field_value]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]
    assert field_value not in response.text


@pytest.mark.parametrize("vendor", ["ad", "other", "rhds", "tivoli", "edirectory"])
@pytest.mark.parametrize("search_scope", ["1", "2"])
def test_directory_preflight_accepts_supported_vendor_and_scope(
    vendor: str,
    search_scope: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Keycloak's supported directory vendors and search scopes remain usable."""
    body = _active_directory_component()
    body["config"]["vendor"] = [vendor]  # type: ignore[index]
    body["config"]["searchScope"] = [search_scope]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("priority", "-1"),
        ("priority", "1001"),
        ("priority", "+1"),
        ("connectionTimeout", "99"),
        ("connectionTimeout", "30001"),
        ("connectionTimeout", "1.5"),
        ("readTimeout", "99"),
        ("readTimeout", "30001"),
        ("readTimeout", "ten-seconds"),
    ],
)
def test_directory_preflight_rejects_out_of_range_numeric_settings(
    field_name: str,
    field_value: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Priority and login-path timeouts stay inside bounded integer ranges."""
    body = _active_directory_component()
    body["config"][field_name] = [field_value]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert field_name in response.json()["detail"]


@pytest.mark.parametrize(
    ("priority", "timeout"),
    [("0", "100"), ("1000", "30000")],
)
def test_directory_preflight_accepts_numeric_boundaries(
    priority: str,
    timeout: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Inclusive numeric boundaries remain valid deployment settings."""
    body = _active_directory_component()
    body["config"]["priority"] = [priority]  # type: ignore[index]
    body["config"]["connectionTimeout"] = [timeout]  # type: ignore[index]
    body["config"]["readTimeout"] = [timeout]  # type: ignore[index]

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 200


def test_directory_preflight_never_resolves_or_opens_directory_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Preflight remains local even when presented with syntactically valid hosts."""

    def fail_network(*_args, **_kwargs):
        """Fail if validation attempts any DNS or socket operation."""
        raise AssertionError("directory preflight attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", fail_network)
    monkeypatch.setattr(socket, "create_connection", fail_network)

    response = _post_preflight(
        _active_directory_component(), auth_header, operator_token
    )

    assert response.status_code == 200


def test_deployment_template_matches_the_production_preflight_contract(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """The shipped LDAP template becomes valid after private value rendering."""
    repository_root = Path(__file__).resolve().parents[3]
    template_path = repository_root / "deploy" / "templates" / "ldap-source.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))
    assert not any(key.startswith("$") for key in template)
    assert not any(key.startswith("$") for key in template["config"])
    rendered = deepcopy(template)
    replacements = {
        "{{ldap_server_url}}": (
            "ldaps://ad-01.corp.example:636 ldaps://ad-02.corp.example:636"
        ),
        "{{ldap_users_dn}}": "OU=Users,DC=corp,DC=example",
        "{{ldap_bind_dn}}": (
            "CN=svc-keycloak,OU=ServiceAccounts,DC=corp,DC=example"
        ),
        "{{ldap_bind_password}}": "rendered-private-value",
    }
    for config_values in rendered["config"].values():
        config_values[0] = replacements.get(config_values[0], config_values[0])

    response = _post_preflight(rendered, auth_header, operator_token)

    assert response.status_code == 200
