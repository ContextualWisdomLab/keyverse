"""Edge-path coverage for the closed LDAP directory preflight profile."""
from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import HTTPException

from app.directory_federation import _parse_directory_registration

from .test_directory_federation_preflight import (
    _active_directory_component,
    _post_preflight,
)


def _set_config(body: dict[str, object], field_name: str, value: object) -> None:
    """Replace one config entry in a test component."""
    config = body["config"]
    assert isinstance(config, dict)
    config[field_name] = value


@pytest.mark.parametrize(
    "mutator",
    [
        lambda body: body["config"].update(  # type: ignore[union-attr]
            {f"extraOption{index}": ["value"] for index in range(12)}
        ),
        lambda body: _set_config(body, "", ["value"]),
        lambda body: _set_config(body, "k" * 129, ["value"]),
        lambda body: _set_config(body, "bindCredential", ["x" * 16_385]),
    ],
)
def test_directory_preflight_enforces_config_collection_bounds(
    mutator,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Oversized collections, keys, and values are rejected before apply."""
    body = _active_directory_component()
    mutator(body)

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {
            key: value
            for key, value in _active_directory_component().items()
            if key != "name"
        },
        {**_active_directory_component(), "name": 7},
        {**_active_directory_component(), "config": "private-config-value"},
        {
            **_active_directory_component(),
            "config": {
                **deepcopy(_active_directory_component()["config"]),  # type: ignore[arg-type]
                "bindCredential": [7],
            },
        },
    ],
)
def test_directory_preflight_uses_bounded_shape_errors(
    payload: object,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Missing or non-string request fields produce non-reflective HTTP 422."""
    response = _post_preflight(payload, auth_header, operator_token)

    assert response.status_code == 422
    assert "private-config-value" not in response.text


def test_directory_parser_rejects_non_string_programmatic_config_key() -> None:
    """Direct non-JSON callers cannot bypass string-key validation."""
    body = _active_directory_component()
    config = body["config"]
    assert isinstance(config, dict)
    config[7] = ["value"]

    with pytest.raises(HTTPException) as error:
        _parse_directory_registration(body)

    assert error.value.status_code == 422
    assert "non-string key" in error.value.detail


@pytest.mark.parametrize(
    "distinguished_name",
    [
        "CN=,DC=corp,DC=example",
        "CN=#,DC=corp,DC=example",
        "CN=#0,DC=corp,DC=example",
        "CN=#0G,DC=corp,DC=example",
        "CN=User;Admin,DC=corp,DC=example",
        "CN\\=Alias=User,DC=corp,DC=example",
        f"CN={'x' * 4_096},DC=corp,DC=example",
    ],
)
def test_directory_preflight_rejects_additional_dn_ambiguity(
    distinguished_name: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Empty, malformed hex, reserved, escaped-type, and oversized DNs fail."""
    body = _active_directory_component()
    _set_config(body, "usersDn", [distinguished_name])

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "usersDn" in response.json()["detail"]


def test_directory_preflight_accepts_hexadecimal_dn_escapes(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """RFC 4514 hexadecimal octet escapes remain available for UTF-8 values."""
    body = _active_directory_component()
    _set_config(
        body,
        "usersDn",
        ["CN=J\\C3\\B6rg,OU=Users,DC=corp,DC=example"],
    )

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 200


@pytest.mark.parametrize(
    "connection_urls",
    [
        "ldaps://münich.example:636",
        "ldaps://ad.example:0",
        f"ldaps://{'a' * 2_040}.example:636",
        "ldaps://ad-01.example:636\tldaps://ad-02.example:636",
        "ldaps://ad.example ldaps://AD.EXAMPLE:636",
    ],
)
def test_directory_preflight_rejects_additional_endpoint_ambiguity(
    connection_urls: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Unicode, zero-port, oversized, tabbed, and normalized duplicates fail."""
    body = _active_directory_component()
    _set_config(body, "connectionUrl", [connection_urls])

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "connectionUrl" in response.json()["detail"]


@pytest.mark.parametrize(
    "attribute_value",
    ["", "a" * 129, "cn\n"],
)
def test_directory_preflight_rejects_bounded_attribute_edge_cases(
    attribute_value: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Empty, oversized, and control-bearing LDAP attributes fail closed."""
    body = _active_directory_component()
    _set_config(body, "usernameLDAPAttribute", [attribute_value])

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "usernameLDAPAttribute" in response.json()["detail"]


@pytest.mark.parametrize("credential", ["", "private\nvalue"])
def test_directory_preflight_rejects_empty_or_control_bearing_bind_secret(
    credential: str,
    auth_header: dict[str, str],
    operator_token: str,
) -> None:
    """Bind secrets must be non-empty and safe for bounded internal handling."""
    body = _active_directory_component()
    _set_config(body, "bindCredential", [credential])

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "bindCredential" in response.json()["detail"]
    if credential:
        assert credential not in response.text


def test_directory_preflight_rejects_empty_object_class_list(
    auth_header: dict[str, str], operator_token: str
) -> None:
    """An empty user object-class declaration cannot select directory users."""
    body = _active_directory_component()
    _set_config(body, "userObjectClasses", [""])

    response = _post_preflight(body, auth_header, operator_token)

    assert response.status_code == 400
    assert "userObjectClasses" in response.json()["detail"]
