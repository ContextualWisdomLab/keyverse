"""Validate Keycloak OIDC relying-party clients before any remote apply.

The endpoint accepts a deliberately closed subset of Keycloak's
``ClientRepresentation``. Validation is deterministic and local: it performs no
configuration write, DNS lookup, socket connection, secret creation, or
Keycloak Admin REST request.
"""
from __future__ import annotations

import re
from typing import Any, NoReturn, cast
from urllib.parse import SplitResult, urlsplit

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

_MAX_CLIENT_ID_LENGTH = 63
_MAX_URI_LENGTH = 2_048
_MAX_URI_COUNT = 16
_MAX_SCOPE_COUNT = 8
_UNRESOLVED_TEMPLATE_MARKERS = ("{{", "}}")
_RAW_CONTROL = re.compile(r"[\x00-\x1F\x7F]")
_PERCENT_ENCODED_CONTROL = re.compile(r"%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|7[Ff])")
_CLIENT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALLOWED_FIELDS = frozenset(
    {
        "clientId",
        "name",
        "enabled",
        "protocol",
        "publicClient",
        "clientAuthenticatorType",
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "redirectUris",
        "webOrigins",
        "attributes",
        "fullScopeAllowed",
        "defaultClientScopes",
    }
)
_ALLOWED_ATTRIBUTES = frozenset(
    {
        "pkce.code.challenge.method",
        "post.logout.redirect.uris",
        "access.token.lifespan",
        "backchannel.logout.session.required",
        "require.pushed.authorization.requests",
    }
)
_ALLOWED_SCOPES = frozenset({"basic", "profile", "email", "roles"})
_REQUIRED_SCOPES = frozenset({"basic", "profile", "email"})


class RelyingPartyRegistration(BaseModel):
    """Closed Keycloak OIDC client representation accepted by preflight."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    client_id: StrictStr = Field(alias="clientId")
    name: StrictStr
    enabled: StrictBool
    protocol: StrictStr
    public_client: StrictBool = Field(alias="publicClient")
    client_authenticator_type: StrictStr = Field(alias="clientAuthenticatorType")
    standard_flow_enabled: StrictBool = Field(alias="standardFlowEnabled")
    implicit_flow_enabled: StrictBool = Field(alias="implicitFlowEnabled")
    direct_access_grants_enabled: StrictBool = Field(alias="directAccessGrantsEnabled")
    service_accounts_enabled: StrictBool = Field(alias="serviceAccountsEnabled")
    redirect_uris: list[StrictStr] = Field(alias="redirectUris")
    web_origins: list[StrictStr] = Field(alias="webOrigins")
    attributes: dict[StrictStr, StrictStr]
    full_scope_allowed: StrictBool = Field(alias="fullScopeAllowed")
    default_client_scopes: list[StrictStr] = Field(alias="defaultClientScopes")


class RelyingPartyValidationResult(BaseModel):
    """Readiness receipt for one side-effect-free client validation."""

    registration: RelyingPartyRegistration
    ready_to_apply: bool = True


def _client_error(field_name: str, requirement: str) -> NoReturn:
    """Raise one bounded policy error without reflecting submitted values."""
    raise HTTPException(status_code=400, detail=f"{field_name} {requirement}")


def _shape_error(field_name: str, requirement: str) -> NoReturn:
    """Raise one bounded JSON-shape error without reflecting submitted values."""
    raise HTTPException(status_code=422, detail=f"{field_name} {requirement}")


def _require_string(payload: dict[str, Any], field_name: str) -> str:
    """Return one required string field after non-reflective type validation."""
    value = payload[field_name]
    if not isinstance(value, str):
        _shape_error(field_name, "must be a string")
    return value


def _require_boolean(payload: dict[str, Any], field_name: str) -> bool:
    """Return one required strict JSON boolean after type validation."""
    value = payload[field_name]
    if not isinstance(value, bool):
        _shape_error(field_name, "must be a boolean")
    return value


def _require_string_list(payload: dict[str, Any], field_name: str) -> list[str]:
    """Return one required JSON array containing only strings."""
    value = payload[field_name]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _shape_error(field_name, "must be an array of strings")
    return list(cast(list[str], value))


def _parse_registration(payload: Any) -> RelyingPartyRegistration:
    """Manually parse untrusted JSON before constructing the response model."""
    if not isinstance(payload, dict):
        _shape_error("body", "must be a JSON object")
    body = cast(dict[str, Any], payload)
    fields = set(body)
    unsupported = sorted(fields.difference(_ALLOWED_FIELDS))
    if unsupported:
        _shape_error(unsupported[0], "is not supported by the closed profile")
    missing = sorted(_ALLOWED_FIELDS.difference(fields))
    if missing:
        _shape_error(missing[0], "is required")

    attributes_input = body["attributes"]
    if not isinstance(attributes_input, dict):
        _shape_error("attributes", "must be a JSON object")
    attributes: dict[str, str] = {}
    for key, value in cast(dict[Any, Any], attributes_input).items():
        if not isinstance(key, str):
            _shape_error("attributes", "contains a non-string key")
        if not isinstance(value, str):
            _shape_error(key, "must be a string")
        attributes[key] = value

    return RelyingPartyRegistration(
        clientId=_require_string(body, "clientId"),
        name=_require_string(body, "name"),
        enabled=_require_boolean(body, "enabled"),
        protocol=_require_string(body, "protocol"),
        publicClient=_require_boolean(body, "publicClient"),
        clientAuthenticatorType=_require_string(body, "clientAuthenticatorType"),
        standardFlowEnabled=_require_boolean(body, "standardFlowEnabled"),
        implicitFlowEnabled=_require_boolean(body, "implicitFlowEnabled"),
        directAccessGrantsEnabled=_require_boolean(body, "directAccessGrantsEnabled"),
        serviceAccountsEnabled=_require_boolean(body, "serviceAccountsEnabled"),
        redirectUris=_require_string_list(body, "redirectUris"),
        webOrigins=_require_string_list(body, "webOrigins"),
        attributes=attributes,
        fullScopeAllowed=_require_boolean(body, "fullScopeAllowed"),
        defaultClientScopes=_require_string_list(body, "defaultClientScopes"),
    )


def _require_clean_text(value: str, field_name: str, *, maximum: int) -> None:
    """Reject empty, ambiguous, control-bearing, or unresolved text."""
    if not value or value != value.strip() or len(value) > maximum:
        _client_error(field_name, "must be non-empty, trimmed, and bounded")
    if _RAW_CONTROL.search(value) is not None:
        _client_error(field_name, "must not contain control characters")
    if any(marker in value for marker in _UNRESOLVED_TEMPLATE_MARKERS):
        _client_error(field_name, "contains an unresolved template placeholder")


def _parse_https_uri(value: str, field_name: str) -> SplitResult:
    """Parse one exact HTTPS URI and reject ambiguous network syntax."""
    _require_clean_text(value, field_name, maximum=_MAX_URI_LENGTH)
    if (
        "*" in value
        or "\\" in value
        or _PERCENT_ENCODED_CONTROL.search(value) is not None
        or any(character.isspace() for character in value)
    ):
        _client_error(field_name, "must be an exact HTTPS URI without wildcards")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _client_error(field_name, "must be a valid absolute HTTPS URI")
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port == 0
    ):
        _client_error(field_name, "must be a valid absolute HTTPS URI")
    try:
        parsed.hostname.encode("ascii")
    except UnicodeEncodeError:
        _client_error(field_name, "hostname must use ASCII or punycode")
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        _client_error(field_name, "must not contain dot path segments")
    return parsed


def _validate_uri_list(values: list[str], field_name: str, *, origin: bool) -> None:
    """Validate one bounded duplicate-free list of redirect URIs or origins."""
    if not 1 <= len(values) <= _MAX_URI_COUNT:
        _client_error(field_name, "must contain between 1 and 16 values")
    if len(set(values)) != len(values):
        _client_error(field_name, "must not contain duplicate values")
    for value in values:
        parsed = _parse_https_uri(value, field_name)
        if origin and (parsed.path or parsed.query or parsed.fragment):
            _client_error(field_name, "must contain exact HTTPS origins only")


def _validate_attributes(attributes: dict[str, str]) -> None:
    """Validate the exact Keycloak security attribute profile."""
    fields = set(attributes)
    unsupported = sorted(fields.difference(_ALLOWED_ATTRIBUTES))
    if unsupported:
        _client_error(unsupported[0], "is not supported by the closed profile")
    missing = sorted(_ALLOWED_ATTRIBUTES.difference(fields))
    if missing:
        _client_error(missing[0], "is required")
    for key, value in attributes.items():
        _require_clean_text(value, key, maximum=_MAX_URI_LENGTH)

    if attributes["pkce.code.challenge.method"] != "S256":
        _client_error("pkce.code.challenge.method", "must be S256")
    _parse_https_uri(
        attributes["post.logout.redirect.uris"],
        "post.logout.redirect.uris",
    )
    lifespan = attributes["access.token.lifespan"]
    if not lifespan.isascii() or not lifespan.isdecimal():
        _client_error("access.token.lifespan", "must be an unsigned decimal integer")
    if not 60 <= int(lifespan) <= 900:
        _client_error("access.token.lifespan", "must be between 60 and 900 seconds")
    if attributes["backchannel.logout.session.required"] != "true":
        _client_error("backchannel.logout.session.required", "must be true")
    if attributes["require.pushed.authorization.requests"] != "false":
        _client_error("require.pushed.authorization.requests", "must be false")


def _validate_scopes(scopes: list[str]) -> None:
    """Require portable built-in realm scopes without duplicates or expansion."""
    if not 1 <= len(scopes) <= _MAX_SCOPE_COUNT:
        _client_error("defaultClientScopes", "must contain between 1 and 8 values")
    for scope in scopes:
        _require_clean_text(scope, "defaultClientScopes", maximum=64)
    if len(set(scopes)) != len(scopes):
        _client_error("defaultClientScopes", "must not contain duplicates")
    unsupported = sorted(set(scopes).difference(_ALLOWED_SCOPES))
    if unsupported:
        _client_error(unsupported[0], "is not a portable realm scope")
    missing = sorted(_REQUIRED_SCOPES.difference(scopes))
    if missing:
        _client_error(missing[0], "is required by the portable realm profile")


def validate_relying_party_registration(
    registration: RelyingPartyRegistration,
) -> RelyingPartyValidationResult:
    """Validate one client registration without persistence or network access."""
    _require_clean_text(
        registration.client_id,
        "clientId",
        maximum=_MAX_CLIENT_ID_LENGTH,
    )
    if _CLIENT_ID.fullmatch(registration.client_id) is None:
        _client_error("clientId", "must be a lowercase ASCII slug")
    if registration.name != registration.client_id:
        _client_error("name", "must exactly match clientId")
    if not registration.enabled:
        _client_error("enabled", "must be true")
    if registration.protocol != "openid-connect":
        _client_error("protocol", "must be openid-connect")
    expected_authenticator = "none" if registration.public_client else "client-secret"
    if registration.client_authenticator_type != expected_authenticator:
        _client_error(
            "clientAuthenticatorType",
            f"must be {expected_authenticator} for this client type",
        )
    if not registration.standard_flow_enabled:
        _client_error("standardFlowEnabled", "must be true")
    if registration.implicit_flow_enabled:
        _client_error("implicitFlowEnabled", "must be false")
    if registration.direct_access_grants_enabled:
        _client_error("directAccessGrantsEnabled", "must be false")
    if registration.service_accounts_enabled:
        _client_error("serviceAccountsEnabled", "must be false")
    if registration.full_scope_allowed:
        _client_error("fullScopeAllowed", "must be false")

    _validate_uri_list(registration.redirect_uris, "redirectUris", origin=False)
    _validate_uri_list(registration.web_origins, "webOrigins", origin=True)
    _validate_attributes(registration.attributes)
    _validate_scopes(registration.default_client_scopes)
    return RelyingPartyValidationResult(registration=registration)


relying_party_router = APIRouter(prefix="/clients", tags=["relying-parties"])


@relying_party_router.post(
    "/relying-parties:validate",
    response_model=RelyingPartyValidationResult,
    response_model_by_alias=True,
)
def validate_relying_party(
    payload: Any = Body(...),
) -> RelyingPartyValidationResult:
    """Return a readiness receipt for one closed OIDC client representation."""
    return validate_relying_party_registration(_parse_registration(payload))
