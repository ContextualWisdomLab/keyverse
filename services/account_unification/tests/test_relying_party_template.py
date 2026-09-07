"""Deployment-template contract tests for OIDC relying-party onboarding."""
from __future__ import annotations

import json
from pathlib import Path

from app.relying_party import _parse_registration, validate_relying_party_registration


_TEMPLATE_ROOT = Path(__file__).resolve().parents[3] / "deploy" / "templates"
_TEMPLATE_PATH = _TEMPLATE_ROOT / "oidc-rp-client.json"
_NARUON_TEMPLATE_PATH = _TEMPLATE_ROOT / "oidc-rp-naruon.json"
_LINEAGEWEAVE_TEMPLATE_PATH = _TEMPLATE_ROOT / "oidc-rp-lineageweave.json"


def _render_template() -> dict[str, object]:
    """Render the committed confidential Naruon example without a shell tool."""
    rendered = _TEMPLATE_PATH.read_text(encoding="utf-8")
    replacements = {
        "{{rp_name}}": "naruon-web",
        "{{rp_redirect_uri}}": "https://naruon.example/auth/callback",
        "{{rp_web_origin}}": "https://naruon.example",
        "{{rp_post_logout_uri}}": "https://naruon.example/auth/logout",
    }
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    payload = json.loads(rendered)
    assert isinstance(payload, dict)
    return payload


def _render_naruon_template() -> dict[str, object]:
    """Render the committed public Naruon claim profile without a shell tool."""
    rendered = _NARUON_TEMPLATE_PATH.read_text(encoding="utf-8")
    replacements = {
        "{{naruon_redirect_uri}}": "https://naruon.example/auth/callback",
        "{{naruon_web_origin}}": "https://naruon.example",
        "{{naruon_post_logout_uri}}": "https://naruon.example/auth/logout",
        "{{naruon_role}}": "member",
        "{{naruon_org}}": "org-cwl",
        "{{naruon_workspace}}": "workspace-org-cwl",
    }
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    payload = json.loads(rendered)
    assert isinstance(payload, dict)
    return payload


def _render_lineageweave_template() -> dict[str, object]:
    """Render the committed account-derived client profile without a shell tool."""
    rendered = _LINEAGEWEAVE_TEMPLATE_PATH.read_text(encoding="utf-8")
    replacements = {
        "{{lineageweave_redirect_uri}}": "https://lineageweave.example/auth/callback",
        "{{lineageweave_web_origin}}": "https://lineageweave.example",
        "{{lineageweave_post_logout_uri}}": "https://lineageweave.example/logout",
    }
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    payload = json.loads(rendered)
    assert isinstance(payload, dict)
    return payload


def test_oidc_rp_template_is_closed_secret_free_and_preflight_ready() -> None:
    """The rendered template passes the same production preflight as operators."""
    payload = _render_template()

    result = validate_relying_party_registration(_parse_registration(payload))

    assert result.ready_to_apply is True
    assert not any(str(key).startswith("$") for key in payload)
    assert "secret" not in {str(key).lower() for key in payload}
    assert "clientSecret" not in payload
    assert payload["webOrigins"] == ["https://naruon.example"]
    assert payload["defaultClientScopes"] == ["basic", "profile", "email"]


def test_naruon_runtime_template_has_the_closed_mapper_profile() -> None:
    """The shipped Naruon artifact is secret-free and accepted by production."""
    payload = _render_naruon_template()

    result = validate_relying_party_registration(_parse_registration(payload))

    assert result.ready_to_apply is True
    assert payload["clientId"] == "naruon-web"
    assert payload["publicClient"] is True
    assert payload["clientAuthenticatorType"] == "none"
    assert "secret" not in {str(key).lower() for key in payload}
    assert "clientSecret" not in payload
    mappers = payload["protocolMappers"]
    assert isinstance(mappers, list)
    assert [mapper["name"] for mapper in mappers] == [
        "keyverse-audience",
        "keyverse-claim-role",
        "keyverse-claim-org",
        "keyverse-claim-workspace",
    ]
    audience = mappers[0]
    assert audience["config"]["included.client.audience"] == "naruon-web"


def test_lineageweave_runtime_template_uses_account_derived_claims() -> None:
    """The shipped LineageWeave profile is confidential and secret-free."""
    payload = _render_lineageweave_template()

    result = validate_relying_party_registration(_parse_registration(payload))

    assert result.ready_to_apply is True
    assert payload["clientId"] == "lineageweave-web"
    assert payload["publicClient"] is False
    assert payload["clientAuthenticatorType"] == "client-secret"
    assert "secret" not in {str(key).lower() for key in payload}
    assert "clientSecret" not in payload
    mappers = payload["protocolMappers"]
    assert isinstance(mappers, list)
    assert [mapper["name"] for mapper in mappers] == [
        "keyverse-audience",
        "keyverse-account-role",
        "keyverse-account-org",
        "keyverse-account-workspace",
    ]
    assert all("claim.value" not in mapper["config"] for mapper in mappers[1:])
