"""Closed OIDC relying-party audience and session-claim mapper tests."""
from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import create_app
from app.relying_party import (
    RelyingPartyRegistration,
    _parse_registration,
    validate_relying_party_registration,
)

from .test_relying_party_preflight import _confidential_web_client


def _audience_mapper() -> dict[str, object]:
    """Return the canonical access-token audience mapper."""
    return {
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
    }


def _claim_mapper(claim_name: str, claim_value: str) -> dict[str, object]:
    """Return one canonical hardcoded product session-claim mapper."""
    return {
        "name": f"keyverse-claim-{claim_name}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "consentRequired": False,
        "config": {
            "claim.name": claim_name,
            "claim.value": claim_value,
            "jsonType.label": "String",
            "access.token.claim": "true",
            "id.token.claim": "true",
            "userinfo.token.claim": "false",
            "introspection.token.claim": "true",
        },
    }


def _naruon_registration_with_mappers() -> dict[str, object]:
    """Return a production-shaped Naruon client with its closed claim profile."""
    payload = deepcopy(_confidential_web_client())
    payload.update(
        {
            "publicClient": True,
            "clientAuthenticatorType": "none",
            "protocolMappers": [
                _audience_mapper(),
                _claim_mapper("role", "member"),
                _claim_mapper("org", "org-cwl"),
                _claim_mapper("workspace", "workspace-org-cwl"),
            ],
        }
    )
    return payload


def _payload_with_mappers(*mappers: dict[str, object]) -> dict[str, object]:
    """Return a public RP payload carrying the provided mapper list."""
    payload = deepcopy(_confidential_web_client())
    payload.update(
        {
            "publicClient": True,
            "clientAuthenticatorType": "none",
            "protocolMappers": list(mappers),
        }
    )
    return payload


def _assert_shape_error(payload: object, expected_detail: str) -> None:
    """Assert a nested mapper shape error without reflecting submitted data."""
    with pytest.raises(HTTPException) as raised:
        _parse_registration(payload)
    assert raised.value.status_code == 422
    assert raised.value.detail == expected_detail
    assert "private-attacker-value" not in str(raised.value.detail)


def _assert_policy_error(payload: dict[str, object], expected_field: str) -> None:
    """Assert one parsed mapper profile fails a bounded policy field."""
    registration = _parse_registration(payload)
    with pytest.raises(HTTPException) as raised:
        validate_relying_party_registration(registration)
    assert raised.value.status_code == 400
    assert str(raised.value.detail).startswith(expected_field)
    assert "private-attacker-value" not in str(raised.value.detail)


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


def test_audience_only_mapper_profile_is_accepted() -> None:
    """The closed profile permits an audience without optional session claims."""
    registration = _parse_registration(_payload_with_mappers(_audience_mapper()))

    result = validate_relying_party_registration(registration)

    assert result.ready_to_apply is True
    assert len(result.registration.protocol_mappers) == 1


@pytest.mark.parametrize(
    ("mapper_value", "detail"),
    [
        ({}, "protocolMappers must be an array"),
        (["private-attacker-value"], "protocolMappers must contain only JSON objects"),
        ([{1: "private-attacker-value"}], "protocolMappers contains a non-string field name"),
        (
            [{**_audience_mapper(), "secret": "private-attacker-value"}],
            "protocolMappers contains unsupported mapper fields",
        ),
        (
            [
                {
                    key: value
                    for key, value in _audience_mapper().items()
                    if key != "config"
                }
            ],
            "protocolMappers.config is required",
        ),
        (
            [{**_audience_mapper(), "name": 7}],
            "name must be a string",
        ),
        (
            [{**_audience_mapper(), "protocol": 7}],
            "protocol must be a string",
        ),
        (
            [{**_audience_mapper(), "protocolMapper": 7}],
            "protocolMapper must be a string",
        ),
        (
            [{**_audience_mapper(), "consentRequired": "false"}],
            "consentRequired must be a boolean",
        ),
        (
            [{**_audience_mapper(), "config": []}],
            "protocolMappers.config must be a JSON object",
        ),
        (
            [{**_audience_mapper(), "config": {1: "private-attacker-value"}}],
            "protocolMappers.config contains a non-string key",
        ),
        (
            [{**_audience_mapper(), "config": {"secret": 7}}],
            "protocolMappers.config must contain only string values",
        ),
        (
            [_audience_mapper()] * 5,
            "protocolMappers must contain at most 4 entries",
        ),
    ],
)
def test_mapper_shape_is_non_reflective(mapper_value: object, detail: str) -> None:
    """Hostile nested mapper shapes fail with stable field-only diagnostics."""
    payload = _confidential_web_client()
    payload["protocolMappers"] = mapper_value
    _assert_shape_error(payload, detail)


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (lambda mapper: mapper.update(name=""), "protocolMappers.name"),
        (lambda mapper: mapper.update(protocol="saml"), "protocolMappers.protocol"),
        (
            lambda mapper: mapper.update(consentRequired=True),
            "protocolMappers.consentRequired",
        ),
        (
            lambda mapper: mapper.update(protocolMapper="oidc-script-based-protocol-mapper"),
            "protocolMappers.protocolMapper",
        ),
    ],
)
def test_shared_mapper_policy_rejects_unsafe_values(mutate, field: str) -> None:
    """Every mapper shares the same closed protocol and consent boundary."""
    mapper = _audience_mapper()
    mutate(mapper)
    _assert_policy_error(_payload_with_mappers(mapper), field)


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (lambda mapper: mapper.update(name="audience"), "protocolMappers.name"),
        (
            lambda mapper: mapper["config"].pop("id.token.claim"),
            "protocolMappers.config",
        ),
        (
            lambda mapper: mapper["config"].update(extra="private-attacker-value"),
            "protocolMappers.config",
        ),
        (
            lambda mapper: mapper["config"].update(
                {"included.client.audience": "other-web"}
            ),
            "protocolMappers.config.included.client.audience",
        ),
        (
            lambda mapper: mapper["config"].update({"access.token.claim": "false"}),
            "protocolMappers.config",
        ),
        (
            lambda mapper: mapper["config"].update(
                {"included.client.audience": ""}
            ),
            "protocolMappers.config.included.client.audience",
        ),
    ],
)
def test_audience_mapper_policy_rejects_unsafe_values(mutate, field: str) -> None:
    """Audience mapping is pinned to the client and exact token destinations."""
    mapper = _audience_mapper()
    mutate(mapper)
    _assert_policy_error(_payload_with_mappers(mapper), field)


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (
            lambda mapper: mapper["config"].pop("userinfo.token.claim"),
            "protocolMappers.config",
        ),
        (
            lambda mapper: mapper["config"].update(extra="private-attacker-value"),
            "protocolMappers.config",
        ),
        (
            lambda mapper: mapper["config"].update({"claim.name": "department"}),
            "protocolMappers.config.claim.name",
        ),
        (
            lambda mapper: mapper.update(name="arbitrary-role"),
            "protocolMappers.name",
        ),
        (
            lambda mapper: mapper["config"].update({"claim.value": ""}),
            "protocolMappers.config.claim.value",
        ),
        (
            lambda mapper: mapper["config"].update(
                {"claim.value": " private-attacker-value"}
            ),
            "protocolMappers.config.claim.value",
        ),
        (
            lambda mapper: mapper["config"].update(
                {"claim.value": "{{private-attacker-value}}"}
            ),
            "protocolMappers.config.claim.value",
        ),
        (
            lambda mapper: mapper["config"].update({"claim.value": "a\x00b"}),
            "protocolMappers.config.claim.value",
        ),
        (
            lambda mapper: mapper["config"].update({"claim.value": "a\u2028b"}),
            "protocolMappers.config.claim.value",
        ),
        (
            lambda mapper: mapper["config"].update({"claim.value": "x" * 129}),
            "protocolMappers.config.claim.value",
        ),
        (
            lambda mapper: mapper["config"].update({"jsonType.label": "JSON"}),
            "protocolMappers.config",
        ),
        (
            lambda mapper: mapper["config"].update({"id.token.claim": "false"}),
            "protocolMappers.config",
        ),
    ],
)
def test_hardcoded_claim_policy_rejects_unsafe_values(mutate, field: str) -> None:
    """Session claims are allowlisted, bounded, visible, and destination-pinned."""
    mapper = _claim_mapper("role", "member")
    mutate(mapper)
    _assert_policy_error(_payload_with_mappers(_audience_mapper(), mapper), field)


def test_mapper_profile_requires_one_audience() -> None:
    """Hardcoded claims cannot exist without the pinned resource audience."""
    _assert_policy_error(
        _payload_with_mappers(_claim_mapper("role", "member")),
        "protocolMappers",
    )


def test_mapper_profile_rejects_duplicate_audience() -> None:
    """Two audience mappers are ambiguous even when otherwise identical."""
    _assert_policy_error(
        _payload_with_mappers(_audience_mapper(), _audience_mapper()),
        "protocolMappers",
    )


def test_mapper_profile_rejects_duplicate_claim_name() -> None:
    """A claim name may be produced by at most one hardcoded mapper."""
    _assert_policy_error(
        _payload_with_mappers(
            _audience_mapper(),
            _claim_mapper("role", "member"),
            _claim_mapper("role", "admin"),
        ),
        "protocolMappers",
    )


def test_mapper_profile_rejects_noncanonical_order() -> None:
    """Reviewed artifacts use audience, role, org, workspace order."""
    _assert_policy_error(
        _payload_with_mappers(
            _audience_mapper(),
            _claim_mapper("org", "org-cwl"),
            _claim_mapper("role", "member"),
        ),
        "protocolMappers",
    )


def test_direct_model_still_rejects_more_than_four_mappers() -> None:
    """Stored or internal models cannot bypass the HTTP parser's list bound."""
    payload = _payload_with_mappers(
        _audience_mapper(),
        _claim_mapper("role", "member"),
        _claim_mapper("org", "org-cwl"),
        _claim_mapper("workspace", "workspace-org-cwl"),
    )
    payload["protocolMappers"] = [*_naruon_registration_with_mappers()["protocolMappers"], _claim_mapper("role", "other")]
    registration = RelyingPartyRegistration.model_validate(payload)

    with pytest.raises(HTTPException) as raised:
        validate_relying_party_registration(registration)

    assert raised.value.status_code == 400
    assert str(raised.value.detail).startswith("protocolMappers")
