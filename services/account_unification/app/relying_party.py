"""Validate Keycloak OIDC relying-party clients before any remote apply.

The endpoint accepts a deliberately closed subset of Keycloak's
``ClientRepresentation``. Validation is deterministic and local: it performs no
configuration write, DNS lookup, socket connection, secret generation, or
Keycloak Admin REST request.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, NoReturn, cast
from urllib.parse import SplitResult, urlsplit

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

_MAX_CLIENT_ID_LENGTH = 63
_MAX_URI_LENGTH = 2_048
_MAX_URI_COUNT = 16
_MAX_MAPPER_COUNT = 4
_MAX_MAPPER_NAME_LENGTH = 64
_MAX_CLAIM_VALUE_LENGTH = 128
_UNRESOLVED_TEMPLATE_MARKERS = ("{{", "}}")
_RAW_CONTROL = re.compile(r"[\x00-\x1F\x7F]")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT_ENCODED_META = re.compile(
    r"%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|2[eEfF]|5[cC]|7[fF])"
)
_CLIENT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_REQUIRED_FIELDS = frozenset(
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
_OPTIONAL_FIELDS = frozenset({"protocolMappers"})
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS
_MAPPER_FIELDS = frozenset(
    {"name", "protocol", "protocolMapper", "consentRequired", "config"}
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
_AUDIENCE_CONFIG_FIELDS = frozenset(
    {
        "included.client.audience",
        "access.token.claim",
        "id.token.claim",
        "introspection.token.claim",
    }
)
_CLAIM_CONFIG_FIELDS = frozenset(
    {
        "claim.name",
        "claim.value",
        "jsonType.label",
        "access.token.claim",
        "id.token.claim",
        "userinfo.token.claim",
        "introspection.token.claim",
    }
)
_REQUIRED_SCOPES = frozenset({"basic", "profile", "email"})
_CLAIM_ORDER = ("role", "org", "workspace")
_CLAIM_RANK = {claim_name: index + 1 for index, claim_name in enumerate(_CLAIM_ORDER)}
_AUDIENCE_MAPPER_NAME = "keyverse-audience"
_AUDIENCE_MAPPER_TYPE = "oidc-audience-mapper"
_CLAIM_MAPPER_TYPE = "oidc-hardcoded-claim-mapper"


class RelyingPartyProtocolMapper(BaseModel):
    """Closed Keycloak protocol-mapper representation accepted by preflight."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: StrictStr
    protocol: StrictStr
    protocol_mapper: StrictStr = Field(alias="protocolMapper")
    consent_required: StrictBool = Field(alias="consentRequired")
    config: dict[StrictStr, StrictStr]


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
    protocol_mappers: list[RelyingPartyProtocolMapper] = Field(
        default_factory=list,
        alias="protocolMappers",
    )


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
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        _shape_error(field_name, "must be an array of strings")
    return list(cast(list[str], value))


def _require_string_mapping(value: Any, field_name: str) -> dict[str, str]:
    """Return a JSON object with only string keys and string values."""
    if not isinstance(value, dict):
        _shape_error(field_name, "must be a JSON object")
    raw_mapping = cast(dict[Any, Any], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        _shape_error(field_name, "contains a non-string key")
    if any(not isinstance(item, str) for item in raw_mapping.values()):
        _shape_error(field_name, "must contain only string values")
    return cast(dict[str, str], dict(raw_mapping))


def _parse_protocol_mappers(value: Any) -> list[RelyingPartyProtocolMapper]:
    """Parse a bounded array of closed protocol-mapper objects."""
    if not isinstance(value, list):
        _shape_error("protocolMappers", "must be an array")
    if len(value) > _MAX_MAPPER_COUNT:
        _shape_error("protocolMappers", "must contain at most 4 entries")
    parsed: list[RelyingPartyProtocolMapper] = []
    for item in value:
        if not isinstance(item, dict):
            _shape_error("protocolMappers", "must contain only JSON objects")
        raw_item = cast(dict[Any, Any], item)
        if any(not isinstance(key, str) for key in raw_item):
            _shape_error("protocolMappers", "contains a non-string field name")
        mapper = cast(dict[str, Any], raw_item)
        fields = set(mapper)
        if fields.difference(_MAPPER_FIELDS):
            _shape_error("protocolMappers", "contains unsupported mapper fields")
        missing = sorted(_MAPPER_FIELDS.difference(fields))
        if missing:
            _shape_error(
                f"protocolMappers.{missing[0]}",
                "is required",
            )
        parsed.append(
            RelyingPartyProtocolMapper(
                name=_require_string(mapper, "name"),
                protocol=_require_string(mapper, "protocol"),
                protocolMapper=_require_string(mapper, "protocolMapper"),
                consentRequired=_require_boolean(mapper, "consentRequired"),
                config=_require_string_mapping(mapper["config"], "protocolMappers.config"),
            )
        )
    return parsed


def _parse_registration(payload: Any) -> RelyingPartyRegistration:
    """Manually parse untrusted JSON before constructing the response model."""
    if not isinstance(payload, dict):
        _shape_error("body", "must be a JSON object")
    raw_body = cast(dict[Any, Any], payload)
    if any(not isinstance(key, str) for key in raw_body):
        _shape_error("body", "contains a non-string field name")
    body = cast(dict[str, Any], raw_body)
    fields = set(body)
    if fields.difference(_ALLOWED_FIELDS):
        _shape_error("body", "contains unsupported fields")
    missing = sorted(_REQUIRED_FIELDS.difference(fields))
    if missing:
        _shape_error(missing[0], "is required")

    registration_fields: dict[str, Any] = {
        "clientId": _require_string(body, "clientId"),
        "name": _require_string(body, "name"),
        "enabled": _require_boolean(body, "enabled"),
        "protocol": _require_string(body, "protocol"),
        "publicClient": _require_boolean(body, "publicClient"),
        "clientAuthenticatorType": _require_string(body, "clientAuthenticatorType"),
        "standardFlowEnabled": _require_boolean(body, "standardFlowEnabled"),
        "implicitFlowEnabled": _require_boolean(body, "implicitFlowEnabled"),
        "directAccessGrantsEnabled": _require_boolean(
            body,
            "directAccessGrantsEnabled",
        ),
        "serviceAccountsEnabled": _require_boolean(body, "serviceAccountsEnabled"),
        "redirectUris": _require_string_list(body, "redirectUris"),
        "webOrigins": _require_string_list(body, "webOrigins"),
        "attributes": _require_string_mapping(body["attributes"], "attributes"),
        "fullScopeAllowed": _require_boolean(body, "fullScopeAllowed"),
        "defaultClientScopes": _require_string_list(body, "defaultClientScopes"),
    }
    if "protocolMappers" in body:
        registration_fields["protocolMappers"] = _parse_protocol_mappers(
            body["protocolMappers"]
        )
    return RelyingPartyRegistration(**registration_fields)


def _require_clean_text(value: str, field_name: str, *, maximum: int) -> None:
    """Reject empty, ambiguous, control-bearing, or unresolved text."""
    if not value or value != value.strip() or len(value) > maximum:
        _client_error(field_name, "must be non-empty, trimmed, and bounded")
    if _RAW_CONTROL.search(value) is not None:
        _client_error(field_name, "must not contain control characters")
    if any(marker in value for marker in _UNRESOLVED_TEMPLATE_MARKERS):
        _client_error(field_name, "contains an unresolved template placeholder")


def _validate_hostname(hostname: str, field_name: str) -> None:
    """Require one canonical ASCII DNS name or IP address."""
    if hostname.endswith(".") or len(hostname) > 253 or "%" in hostname:
        _client_error(field_name, "hostname must be canonical ASCII or punycode")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.split(".")
        if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
            _client_error(field_name, "hostname must be canonical ASCII or punycode")


def _parse_https_uri(value: str, field_name: str) -> SplitResult:
    """Parse one exact HTTPS URI and reject ambiguous network syntax."""
    _require_clean_text(value, field_name, maximum=_MAX_URI_LENGTH)
    if (
        "*" in value
        or "+" in value
        or "\\" in value
        or _INVALID_PERCENT_ESCAPE.search(value) is not None
        or _PERCENT_ENCODED_META.search(value) is not None
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
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        _client_error(field_name, "must be a valid absolute HTTPS URI")
    try:
        parsed.hostname.encode("ascii")
    except UnicodeEncodeError:
        _client_error(field_name, "hostname must use ASCII or punycode")
    _validate_hostname(parsed.hostname, field_name)
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        _client_error(field_name, "must not contain dot path segments")
    return parsed


def _origin_key(parsed: SplitResult) -> tuple[str, int]:
    """Return the RFC-origin host and effective TLS port for comparisons."""
    return cast(str, parsed.hostname).lower(), parsed.port or 443


def _validate_uri_list(
    values: list[str], field_name: str, *, origin: bool
) -> list[SplitResult]:
    """Validate one bounded duplicate-free list of redirect URIs or origins."""
    if not 1 <= len(values) <= _MAX_URI_COUNT:
        _client_error(field_name, "must contain between 1 and 16 values")
    if len(set(values)) != len(values):
        _client_error(field_name, "must not contain duplicate values")
    parsed_values = [_parse_https_uri(value, field_name) for value in values]
    if origin and any(parsed.path for parsed in parsed_values):
        _client_error(field_name, "must contain exact HTTPS origins only")
    return parsed_values


def _validate_attributes(attributes: dict[str, str]) -> SplitResult:
    """Validate the exact Keycloak security attribute profile."""
    fields = set(attributes)
    if fields.difference(_ALLOWED_ATTRIBUTES):
        _client_error("attributes", "contains unsupported fields")
    missing = sorted(_ALLOWED_ATTRIBUTES.difference(fields))
    if missing:
        _client_error(missing[0], "is required")
    for key, value in attributes.items():
        _require_clean_text(value, key, maximum=_MAX_URI_LENGTH)

    if attributes["pkce.code.challenge.method"] != "S256":
        _client_error("pkce.code.challenge.method", "must be S256")
    logout_uri = _parse_https_uri(
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
    return logout_uri


def _validate_scopes(scopes: list[str]) -> None:
    """Require the exact portable built-in realm scope profile."""
    if not 1 <= len(scopes) <= 8:
        _client_error("defaultClientScopes", "must contain between 1 and 8 values")
    for scope in scopes:
        _require_clean_text(scope, "defaultClientScopes", maximum=64)
    if len(set(scopes)) != len(scopes):
        _client_error("defaultClientScopes", "must not contain duplicates")
    if set(scopes) != _REQUIRED_SCOPES:
        _client_error(
            "defaultClientScopes",
            "must contain exactly basic, profile, and email",
        )


def _require_exact_config(
    mapper: RelyingPartyProtocolMapper,
    expected_fields: frozenset[str],
) -> None:
    """Require one mapper configuration to have an exact closed key set."""
    fields = set(mapper.config)
    if fields != expected_fields:
        _client_error("protocolMappers.config", "must use the exact closed field set")
    for key, value in mapper.config.items():
        _require_clean_text(value, f"protocolMappers.config.{key}", maximum=128)


def _validate_audience_mapper(
    mapper: RelyingPartyProtocolMapper,
    client_id: str,
) -> int:
    """Validate the single closed access-token audience mapper."""
    if mapper.name != _AUDIENCE_MAPPER_NAME:
        _client_error("protocolMappers.name", "must be keyverse-audience")
    _require_exact_config(mapper, _AUDIENCE_CONFIG_FIELDS)
    if mapper.config["included.client.audience"] != client_id:
        _client_error(
            "protocolMappers.config.included.client.audience",
            "must exactly match clientId",
        )
    expected_flags = {
        "access.token.claim": "true",
        "id.token.claim": "false",
        "introspection.token.claim": "true",
    }
    if any(mapper.config[key] != value for key, value in expected_flags.items()):
        _client_error(
            "protocolMappers.config",
            "must use the closed audience claim destinations",
        )
    return 0


def _validate_claim_value(value: str) -> None:
    """Require one bounded visible hardcoded product-claim value."""
    _require_clean_text(
        value,
        "protocolMappers.config.claim.value",
        maximum=_MAX_CLAIM_VALUE_LENGTH,
    )
    if "\u2028" in value or "\u2029" in value:
        _client_error(
            "protocolMappers.config.claim.value",
            "must not contain Unicode line separators",
        )


def _validate_hardcoded_claim_mapper(
    mapper: RelyingPartyProtocolMapper,
) -> tuple[int, str]:
    """Validate one allowlisted hardcoded session-routing claim mapper."""
    _require_exact_config(mapper, _CLAIM_CONFIG_FIELDS)
    claim_name = mapper.config["claim.name"]
    if claim_name not in _CLAIM_RANK:
        _client_error(
            "protocolMappers.config.claim.name",
            "must be role, org, or workspace",
        )
    if mapper.name != f"keyverse-claim-{claim_name}":
        _client_error(
            "protocolMappers.name",
            "must be canonical for the claim name",
        )
    _validate_claim_value(mapper.config["claim.value"])
    expected_values = {
        "jsonType.label": "String",
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "false",
        "introspection.token.claim": "true",
    }
    if any(mapper.config[key] != value for key, value in expected_values.items()):
        _client_error(
            "protocolMappers.config",
            "must use the closed session-claim destinations",
        )
    return _CLAIM_RANK[claim_name], claim_name


def _validate_protocol_mappers(registration: RelyingPartyRegistration) -> None:
    """Validate the optional closed audience and session-claim mapper profile."""
    mappers = registration.protocol_mappers
    if not mappers:
        return
    if len(mappers) > _MAX_MAPPER_COUNT:
        _client_error("protocolMappers", "must contain at most 4 entries")

    ranks: list[int] = []
    audience_count = 0
    claim_names: set[str] = set()
    for mapper in mappers:
        _require_clean_text(
            mapper.name,
            "protocolMappers.name",
            maximum=_MAX_MAPPER_NAME_LENGTH,
        )
        if mapper.protocol != "openid-connect":
            _client_error("protocolMappers.protocol", "must be openid-connect")
        if mapper.consent_required:
            _client_error("protocolMappers.consentRequired", "must be false")
        if mapper.protocol_mapper == _AUDIENCE_MAPPER_TYPE:
            audience_count += 1
            ranks.append(_validate_audience_mapper(mapper, registration.client_id))
        elif mapper.protocol_mapper == _CLAIM_MAPPER_TYPE:
            rank, claim_name = _validate_hardcoded_claim_mapper(mapper)
            if claim_name in claim_names:
                _client_error("protocolMappers", "must not duplicate claim names")
            claim_names.add(claim_name)
            ranks.append(rank)
        else:
            _client_error("protocolMappers.protocolMapper", "is not supported")

    if audience_count != 1:
        _client_error("protocolMappers", "must contain exactly one audience mapper")
    if ranks != sorted(ranks) or len(set(ranks)) != len(ranks):
        _client_error("protocolMappers", "must use canonical mapper order")


def validate_relying_party_registration(
    registration: RelyingPartyRegistration,
) -> RelyingPartyValidationResult:
    """Validate one dynamically-registered OIDC relying party (RP) against this
    org's fixed client-security profile before Keyverse creates or updates the
    corresponding Keycloak client. This function is pure and side-effect-free
    -- it neither persists anything nor makes a network call; a caller may
    apply the change only after this returns without raising.

    Every check below enforces one property of that fixed profile, and none
    of them are configurable per-caller -- a client that needs a different
    property does not qualify for dynamic registration through this path:

    - `clientId` must be a clean, lowercase ASCII slug, and `name` must
      exactly match it -- dynamically-registered clients get no separate
      free-text display identity.
    - The client must be `enabled` and speak the `openid-connect` protocol.
    - A public client (SPA/native, no client secret) must set
      `clientAuthenticatorType` to `none`; a confidential client must set it
      to `client-secret` -- the two client types cannot be conflated.
    - Only the OAuth2 Authorization Code flow (`standardFlowEnabled`) may be
      used. The OAuth2 Implicit flow (`implicitFlowEnabled`) is rejected as
      deprecated. The Resource Owner Password Credentials grant, Keycloak's
      "Direct Access Grants" (`directAccessGrantsEnabled`), is rejected
      because RFC 9700 §2.4 (BCP 240, Jan 2025) and RFC 10017 §7.3 (OAuth 2.0
      for Browser-Based Applications, BCP, Aug 2026) both state it MUST NOT
      be used by browser-based OAuth/OIDC clients -- see
      docs/adr/0014-naruon-owned-password-form.md's Correction section for
      the one hand-authored (not dynamically-registered) exception this
      function deliberately does not need to know about, since it never
      sees `naruon-web`'s registration.
    - `serviceAccountsEnabled` (the client-credentials machine-to-machine
      grant) and `fullScopeAllowed` (implicit access to every realm role and
      scope) are both rejected, because a dynamically-registered RP is
      expected to act only on behalf of an interactive human user with an
      explicitly-granted scope -- never as a standing machine identity with
      unrestricted realm access.
    - `redirectUris` and `webOrigins` must resolve to exactly the same set of
      origins (an RP cannot receive callbacks at an origin it never declared
      as trusted for CORS), and the client's post-logout redirect URI must
      itself be one of those registered web origins.

    Raises `HTTPException(400)` via `_client_error` on the first violation
    found, with a message naming only the violated field and requirement --
    never the submitted value, so a rejected registration attempt cannot be
    used to probe or leak configuration. Returns a `RelyingPartyValidationResult`
    wrapping the validated registration, with `ready_to_apply=True`, once every
    check above has passed.
    """
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

    redirect_uris = _validate_uri_list(
        registration.redirect_uris,
        "redirectUris",
        origin=False,
    )
    web_origins = _validate_uri_list(
        registration.web_origins,
        "webOrigins",
        origin=True,
    )
    logout_uri = _validate_attributes(registration.attributes)
    _validate_scopes(registration.default_client_scopes)
    _validate_protocol_mappers(registration)

    redirect_origin_keys = {_origin_key(uri) for uri in redirect_uris}
    web_origin_keys = {_origin_key(uri) for uri in web_origins}
    if redirect_origin_keys != web_origin_keys:
        _client_error("webOrigins", "must exactly match redirect URI origins")
    if _origin_key(logout_uri) not in web_origin_keys:
        _client_error(
            "post.logout.redirect.uris",
            "must use a registered web origin",
        )
    return RelyingPartyValidationResult(
        registration=registration,
        ready_to_apply=True,
    )


relying_party_router = APIRouter(prefix="/clients", tags=["relying-parties"])


@relying_party_router.post(
    "/relying-parties:validate",
    response_model=RelyingPartyValidationResult,
    response_model_by_alias=True,
    response_model_exclude_unset=True,
)
def validate_relying_party(
    payload: Any = Body(...),
) -> RelyingPartyValidationResult:
    """Return a readiness receipt for one closed OIDC client representation."""
    return validate_relying_party_registration(_parse_registration(payload))
