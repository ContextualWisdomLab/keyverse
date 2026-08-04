#!/usr/bin/env python3
"""Replace the superseded generic OIDC preflight regression with fail-closed policy."""
from __future__ import annotations

from pathlib import Path


TARGET = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "account_unification"
    / "tests"
    / "test_federation_preflight.py"
)

OLD = '''def test_non_saml_preflight_remains_provider_neutral(
    api, auth_header, operator_token
) -> None:
    """OIDC registrations retain generic validation in this focused slice."""
    store = InMemoryKvStore()
    body = deepcopy(_adfs_body())
    body.update(
        {
            "provider_alias": "partner-oidc",
            "display_name": "Partner OIDC",
            "provider_id": "oidc",
            "trust_email": False,
            "provider_config": {
                "issuer": "https://login.partner.example",
                "clientId": "keyverse",
                "clientSecret": "oidc-secret",
            },
        }
    )

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 200
    assert response.json()["registration"]["provider_alias"] == "partner-oidc"
    assert response.json()["registration"]["provider_config"]["issuer"] == (
        "https://login.partner.example"
    )
    assert response.json()["registration"]["provider_config"]["clientSecret"] == (
        "<redacted>"
    )
    _assert_no_side_effects(store, api)
'''

NEW = '''def test_oidc_preflight_does_not_fall_back_to_generic_validation(
    api, auth_header, operator_token
) -> None:
    """Incomplete OIDC desired state fails instead of using generic validation."""
    store = InMemoryKvStore()
    body = deepcopy(_adfs_body())
    body.update(
        {
            "provider_alias": "partner-oidc",
            "display_name": "Partner OIDC",
            "provider_id": "oidc",
            "trust_email": False,
            "provider_config": {
                "issuer": "https://login.partner.example",
                "clientId": "keyverse",
                "clientSecret": "oidc-secret",
            },
        }
    )

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert "authorizationUrl" in response.json()["detail"]
    assert "oidc-secret" not in response.text
    _assert_no_side_effects(store, api)
'''


def main() -> None:
    """Apply one exact expectation replacement and fail on source drift."""
    content = TARGET.read_text(encoding="utf-8")
    count = content.count(OLD)
    if count != 1:
        raise RuntimeError(f"legacy OIDC test anchor count was {count}, expected 1")
    TARGET.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")


if __name__ == "__main__":
    main()
