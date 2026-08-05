"""Side-effect-free LDAP and Active Directory component validation.

The directory preflight accepts the bounded Keycloak component representation
that an operator intends to apply later. It performs deterministic local
validation only: no configuration write, DNS lookup, socket connection, LDAP
bind, search, or Keycloak Admin REST request occurs in this module.
"""
from __future__ import annotations

import re
from typing import Any, NoReturn, cast
from urllib.parse import SplitResult, urlsplit

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictStr

_DIRECTORY_PROVIDER_ID = "ldap"
_DIRECTORY_PROVIDER_TYPE = "org.keycloak.storage.UserStorageProvider"
_REDACTED_VALUE = "<redacted>"
_MAX_COMPONENT_NAME_LENGTH = 63
_MAX_CONFIG_ENTRIES = 32
_MAX_CONFIG_KEY_LENGTH = 128
_MAX_CONFIG_VALUE_LENGTH = 16_384
_MAX_DIRECTORY_URL_LENGTH = 2_048
_MAX_DN_LENGTH = 4_096
_ALLOWED_VENDORS = frozenset({"ad", "other", "rhds", "tivoli", "edirectory"})
_ALLOWED_SEARCH_SCOPES = frozenset({"1", "2"})
_ALLOWED_CONFIG_KEYS = frozenset(
    {
        "allowKerberosAuthentication",
        "bindCredential",
        "bindDn",
        "connectionPooling",
        "connectionTimeout",
        "connectionUrl",
        "editMode",
        "enabled",
        "importEnabled",
        "priority",
        "rdnLDAPAttribute",
        "readTimeout",
        "searchScope",
        "syncRegistrations",
        "trustEmail",
        "useTruststoreSpi",
        "userObjectClasses",
        "usernameLDAPAttribute",
        "usersDn",
        "uuidLDAPAttribute",
        "vendor",
    }
)
_REDACTED_CONFIG_KEYS = frozenset({"bindCredential", "bindDn"})
_UNRESOLVED_TEMPLATE_MARKERS = ("{{", "}}")
_RAW_CONTROL = re.compile(r"[\x00-\x1F\x7F]")
_COMPONENT_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LDAP_DESCRIPTOR = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
_NUMERIC_OID = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
_DECIMAL_INTEGER = re.compile(r"^(?:0|[1-9][0-9]*)$")
_HEX_PAIR = re.compile(r"^[0-9A-Fa-f]{2}$")
_HEX_STRING = re.compile(r"^[0-9A-Fa-f]+$")
_DN_RESERVED = frozenset({",", "+", '"', "\\", "<", ">", ";", "="})
_DN_ESCAPABLE = frozenset({" ", '"', "#", "+", ",", ";", "<", "=", ">", "\\"})


class DirectoryFederationRegistration(BaseModel):
    """Bounded Keycloak LDAP user-storage component representation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: StrictStr
    provider_id: StrictStr = Field(alias="providerId")
    provider_type: StrictStr = Field(alias="providerType")
    config: dict[StrictStr, list[StrictStr]]


class DirectoryFederationView(BaseModel):
    """Operator-safe component representation with private values redacted."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    provider_id: str = Field(alias="providerId")
    provider_type: str = Field(alias="providerType")
    config: dict[str, list[str]]

    @classmethod
    def from_registration(
        cls, registration: DirectoryFederationRegistration
    ) -> "DirectoryFederationView":
        """Return a copy that never discloses bind identity or credentials."""
        redacted = {
            key: (
                [_REDACTED_VALUE]
                if key in _REDACTED_CONFIG_KEYS
                else list(values)
            )
            for key, values in registration.config.items()
        }
        return cls(
            name=registration.name,
            providerId=registration.provider_id,
            providerType=registration.provider_type,
            config=redacted,
        )


class DirectoryFederationValidationResult(BaseModel):
    """Redacted receipt proving a directory component is ready for apply."""

    registration: DirectoryFederationView
    ready_to_apply: bool = True


def _directory_error(field_name: str, requirement: str) -> NoReturn:
    """Raise one bounded validation error without echoing private input."""
    raise HTTPException(
        status_code=400,
        detail=f"{field_name} {requirement}",
    )


def _directory_shape_error(field_name: str, requirement: str) -> NoReturn:
    """Raise one bounded schema error without reflecting malformed input."""
    raise HTTPException(
        status_code=422,
        detail=f"{field_name} {requirement}",
    )


def _parse_directory_registration(payload: Any) -> DirectoryFederationRegistration:
    """Parse arbitrary JSON manually so validation errors cannot echo secrets."""
    if not isinstance(payload, dict):
        _directory_shape_error("body", "must be a JSON object")

    expected_fields = {"name", "providerId", "providerType", "config"}
    payload_fields = set(payload)
    if payload_fields.difference(expected_fields):
        _directory_shape_error("body", "contains unsupported fields")
    missing_fields = sorted(expected_fields.difference(payload_fields))
    if missing_fields:
        _directory_shape_error(missing_fields[0], "is required")

    name = payload["name"]
    provider_id = payload["providerId"]
    provider_type = payload["providerType"]
    config_input = payload["config"]
    for field_name, field_value in (
        ("name", name),
        ("providerId", provider_id),
        ("providerType", provider_type),
    ):
        if not isinstance(field_value, str):
            _directory_shape_error(field_name, "must be a string")
    if not isinstance(config_input, dict):
        _directory_shape_error("config", "must be a JSON object")

    config: dict[str, list[str]] = {}
    for key, items in config_input.items():
        if not isinstance(key, str):
            _directory_shape_error("config", "contains a non-string key")
        if not isinstance(items, list) or any(
            not isinstance(item, str) for item in items
        ):
            _directory_shape_error(
                key,
                "must contain only string values in a JSON array",
            )
        config[key] = list(items)

    return DirectoryFederationRegistration(
        name=cast(str, name),
        providerId=cast(str, provider_id),
        providerType=cast(str, provider_type),
        config=config,
    )


def _single_config_values(
    registration: DirectoryFederationRegistration,
) -> dict[str, str]:
    """Return the closed component configuration as one string per key."""
    if len(registration.config) > _MAX_CONFIG_ENTRIES:
        _directory_error("config", "contains too many entries")

    values: dict[str, str] = {}
    for key, items in registration.config.items():
        if not key or len(key) > _MAX_CONFIG_KEY_LENGTH:
            _directory_error("config", "contains an invalid key")
        if len(items) != 1:
            _directory_error(key, "must contain exactly one string value")
        value = items[0]
        if len(value) > _MAX_CONFIG_VALUE_LENGTH:
            _directory_error(key, "exceeds the bounded value length")
        if any(marker in value for marker in _UNRESOLVED_TEMPLATE_MARKERS):
            _directory_error(key, "contains an unresolved template placeholder")
        values[str(key)] = str(value)

    unknown = sorted(set(values).difference(_ALLOWED_CONFIG_KEYS))
    if unknown:
        _directory_error(unknown[0], "is not supported by the closed profile")
    missing = sorted(_ALLOWED_CONFIG_KEYS.difference(values))
    if missing:
        _directory_error(missing[0], "is required by the closed profile")
    return values


def _require_component_identity(
    registration: DirectoryFederationRegistration,
) -> None:
    """Require one bounded LDAP user-storage component identity."""
    if (
        len(registration.name) > _MAX_COMPONENT_NAME_LENGTH
        or _COMPONENT_NAME.fullmatch(registration.name) is None
    ):
        _directory_error(
            "name",
            "must be a lowercase ASCII alphanumeric-and-hyphen slug",
        )
    if registration.provider_id != _DIRECTORY_PROVIDER_ID:
        _directory_error("providerId", "must be ldap")
    if registration.provider_type != _DIRECTORY_PROVIDER_TYPE:
        _directory_error(
            "providerType",
            "must be org.keycloak.storage.UserStorageProvider",
        )


def _require_exact_boolean(
    config: dict[str, str], field_name: str, required: bool
) -> None:
    """Require a lowercase Keycloak boolean with one exact policy value."""
    value = config[field_name]
    if value not in {"true", "false"}:
        _directory_error(field_name, "must be true or false")
    expected = "true" if required else "false"
    if value != expected:
        _directory_error(field_name, f"must be {expected}")


def _require_bounded_integer(
    config: dict[str, str],
    field_name: str,
    *,
    minimum: int,
    maximum: int,
) -> None:
    """Require an unsigned decimal integer inside an inclusive range."""
    value = config[field_name]
    if _DECIMAL_INTEGER.fullmatch(value) is None:
        _directory_error(field_name, "must be an unsigned decimal integer")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        _directory_error(
            field_name,
            f"must be between {minimum} and {maximum}",
        )


def _validate_ldap_identifier(value: str, field_name: str) -> None:
    """Require one LDAP descriptor or numeric object identifier."""
    if (
        not value
        or len(value) > 128
        or _RAW_CONTROL.search(value) is not None
        or (
            _LDAP_DESCRIPTOR.fullmatch(value) is None
            and _NUMERIC_OID.fullmatch(value) is None
        )
    ):
        _directory_error(
            field_name,
            "must be an ASCII LDAP descriptor or numeric OID",
        )


def _split_unescaped(value: str, separator: str) -> list[str]:
    """Split text on one separator that is not protected by a backslash."""
    parts: list[str] = []
    start = 0
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == separator:
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return parts


def _split_first_unescaped(value: str, separator: str) -> tuple[str, str] | None:
    """Split on the first unescaped separator or return ``None``."""
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == separator:
            return value[:index], value[index + 1 :]
    return None


def _validate_dn_value(value: str, field_name: str) -> None:
    """Validate one RFC 4514 attribute value without normalizing it."""
    if not value:
        _directory_error(field_name, "contains an empty attribute value")
    if value.startswith("#"):
        hex_value = value[1:]
        if (
            not hex_value
            or len(hex_value) % 2 != 0
            or _HEX_STRING.fullmatch(hex_value) is None
        ):
            _directory_error(field_name, "contains an invalid hexadecimal value")
        return
    if value.startswith(" "):
        _directory_error(
            field_name,
            "contains an unescaped leading or trailing special character",
        )
    if value.endswith(" "):
        prefix = value[:-1]
        trailing_backslashes = len(prefix) - len(prefix.rstrip("\\"))
        if trailing_backslashes % 2 == 0:
            _directory_error(
                field_name,
                "contains an unescaped leading or trailing special character",
            )

    index = 0
    while index < len(value):
        character = value[index]
        if character == "\\":
            if index + 1 >= len(value):
                _directory_error(field_name, "contains a dangling escape")
            if index + 2 < len(value) and _HEX_PAIR.fullmatch(
                value[index + 1 : index + 3]
            ):
                index += 3
                continue
            escaped_character = value[index + 1]
            if escaped_character not in _DN_ESCAPABLE:
                _directory_error(field_name, "contains an invalid escape")
            index += 2
            continue
        if character in _DN_RESERVED:
            _directory_error(field_name, "contains an unescaped reserved character")
        index += 1


def _validate_distinguished_name(value: str, field_name: str) -> None:
    """Validate a bounded RFC 4514 distinguished-name lexical profile."""
    if (
        not value
        or len(value) > _MAX_DN_LENGTH
        or _RAW_CONTROL.search(value) is not None
    ):
        _directory_error(field_name, "must be a bounded control-free LDAP DN")
    rdns = _split_unescaped(value, ",")
    if any(not rdn for rdn in rdns):
        _directory_error(field_name, "contains an empty relative distinguished name")
    for rdn in rdns:
        attributes = _split_unescaped(rdn, "+")
        if any(not attribute for attribute in attributes):
            _directory_error(field_name, "contains an empty attribute-value assertion")
        for attribute in attributes:
            split = _split_first_unescaped(attribute, "=")
            if split is None:
                _directory_error(field_name, "contains an assertion without equals")
            attribute_type, attribute_value = cast(tuple[str, str], split)
            _validate_ldap_identifier(attribute_type, field_name)
            _validate_dn_value(attribute_value, field_name)


def _validate_connection_urls(value: str) -> None:
    """Require one or more unique, unambiguous LDAPS authorities."""
    if not value or value != value.strip() or "  " in value:
        _directory_error(
            "connectionUrl",
            "must contain LDAPS URLs separated by one ASCII space",
        )
    endpoints = value.split(" ")
    normalized: set[tuple[str, int]] = set()
    for endpoint in endpoints:
        invalid_text = (
            len(endpoint) > _MAX_DIRECTORY_URL_LENGTH
            or _RAW_CONTROL.search(endpoint) is not None
            or any(character.isspace() for character in endpoint)
            or "\\" in endpoint
            or "%" in endpoint
        )
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError:
            parsed = None
            port = None
        invalid_url = (
            parsed is None
            or parsed.scheme.lower() != "ldaps"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query != ""
            or parsed.fragment != ""
            or parsed.path not in {"", "/"}
            or port == 0
        )
        if invalid_text or invalid_url:
            _directory_error(
                "connectionUrl",
                "must contain unique absolute LDAPS authorities",
            )
        hostname = cast(SplitResult, parsed).hostname
        try:
            cast(str, hostname).encode("ascii")
        except UnicodeEncodeError:
            _directory_error("connectionUrl", "hostnames must use ASCII or punycode")
        endpoint_key = (cast(str, hostname).lower(), port or 636)
        if endpoint_key in normalized:
            _directory_error("connectionUrl", "must not contain duplicate endpoints")
        normalized.add(endpoint_key)


def _validate_object_classes(value: str) -> None:
    """Require a comma-and-space list of unique LDAP object classes."""
    object_classes = value.split(", ")
    malformed = (
        not value
        or any(
            not object_class
            or object_class != object_class.strip()
            or "," in object_class
            for object_class in object_classes
        )
    )
    if malformed:
        _directory_error(
            "userObjectClasses",
            "must be separated by a comma and one ASCII space",
        )
    for object_class in object_classes:
        _validate_ldap_identifier(object_class, "userObjectClasses")
    folded = [object_class.casefold() for object_class in object_classes]
    if len(folded) != len(set(folded)):
        _directory_error("userObjectClasses", "must not contain duplicates")


def validate_directory_registration(
    registration: DirectoryFederationRegistration,
) -> DirectoryFederationValidationResult:
    """Validate one component locally and return its redacted readiness receipt."""
    _require_component_identity(registration)
    config = _single_config_values(registration)

    for field_name, required in (
        ("enabled", True),
        ("importEnabled", True),
        ("syncRegistrations", False),
        ("trustEmail", False),
        ("connectionPooling", True),
        ("allowKerberosAuthentication", False),
    ):
        _require_exact_boolean(config, field_name, required)

    if config["editMode"] != "READ_ONLY":
        _directory_error("editMode", "must be READ_ONLY")
    if config["useTruststoreSpi"] != "always":
        _directory_error("useTruststoreSpi", "must be always")
    if config["vendor"] not in _ALLOWED_VENDORS:
        _directory_error("vendor", "is not a supported Keycloak LDAP vendor")
    if config["searchScope"] not in _ALLOWED_SEARCH_SCOPES:
        _directory_error("searchScope", "must be 1 or 2")

    _validate_connection_urls(config["connectionUrl"])
    _validate_distinguished_name(config["usersDn"], "usersDn")
    _validate_distinguished_name(config["bindDn"], "bindDn")
    if not config["bindCredential"] or _RAW_CONTROL.search(
        config["bindCredential"]
    ) is not None:
        _directory_error(
            "bindCredential",
            "must be a non-empty control-free private value",
        )

    for attribute_field in (
        "usernameLDAPAttribute",
        "rdnLDAPAttribute",
        "uuidLDAPAttribute",
    ):
        _validate_ldap_identifier(config[attribute_field], attribute_field)
    _validate_object_classes(config["userObjectClasses"])

    _require_bounded_integer(
        config,
        "priority",
        minimum=0,
        maximum=1_000,
    )
    for timeout_field in ("connectionTimeout", "readTimeout"):
        _require_bounded_integer(
            config,
            timeout_field,
            minimum=100,
            maximum=30_000,
        )

    return DirectoryFederationValidationResult(
        registration=DirectoryFederationView.from_registration(registration)
    )


directory_federation_router = APIRouter(
    prefix="/federation",
    tags=["directory-federation"],
)


@directory_federation_router.post(
    "/user-directories:validate",
    response_model=DirectoryFederationValidationResult,
)
def validate_user_directory(
    payload: Any = Body(...),
) -> DirectoryFederationValidationResult:
    """Validate LDAP desired input without storage or network side effects."""
    registration = _parse_directory_registration(payload)
    return validate_directory_registration(registration)

_STATEFUL_EXPORTS = frozenset(
    {
        "DIRECTORY_FEDERATION_NAMESPACE",
        "DIRECTORY_FEDERATION_RECEIPT_NAMESPACE",
        "DirectoryConvergenceState",
        "DirectoryFederationService",
        "DirectoryFederationStatus",
    }
)


def __getattr__(name: str):
    """Load stateful directory exports lazily without a circular import."""
    if name not in _STATEFUL_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from . import directory_federation_state

    return getattr(directory_federation_state, name)
