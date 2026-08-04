#!/usr/bin/env python3
"""Apply the reviewed OIDC federation preflight implementation to the PR branch."""
from __future__ import annotations

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: str, old: str, new: str, *, label: str) -> None:
    """Replace one exact anchor and fail closed if the source tree drifted."""
    target = REPOSITORY_ROOT / path
    content = target.read_text(encoding="utf-8")
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    target.write_text(content.replace(old, new, 1), encoding="utf-8")


def write_new(path: str, content: str) -> None:
    """Create one new source-controlled file without overwriting existing data."""
    target = REPOSITORY_ROOT / path
    if target.exists():
        raise RuntimeError(f"refusing to overwrite existing file: {path}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def apply_federation_validation() -> None:
    """Add pure fail-closed OIDC validation beside the existing SAML policy."""
    path = "services/account_unification/app/federation.py"
    replace_once(
        path,
        '_HTTP_SCHEMES = frozenset({"http", "https"})\n'
        '_HTTPS_SCHEME = "https"\n'
        '_PERCENT_ENCODED_CONTROL = re.compile(\n',
        '_HTTP_SCHEMES = frozenset({"http", "https"})\n'
        '_HTTPS_SCHEME = "https"\n'
        '_OIDC_PROVIDER_IDS = frozenset({"oidc", "keycloak-oidc"})\n'
        '_OIDC_CLIENT_AUTH_METHODS = frozenset(\n'
        '    {"client_secret_basic", "client_secret_post"}\n'
        ')\n'
        '_OIDC_PKCE_METHOD = "S256"\n'
        '_OIDC_FORBIDDEN_DISCOVERY_KEYS = ("fromUrl", "discoveryEndpoint")\n'
        '_OAUTH_SCOPE_TOKEN = re.compile(r"^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$")\n'
        '_PERCENT_ENCODED_CONTROL = re.compile(\n',
        label="OIDC constants",
    )
    replace_once(
        path,
        '        "authorizationUrl",\n'
        '        "backchannelSupported",\n',
        '        "authorizationUrl",\n'
        '        "backchannelSupported",\n'
        '        "clientAuthMethod",\n'
        '        "clientId",\n',
        label="safe OIDC client fields",
    )
    replace_once(
        path,
        '        "issuer",\n'
        '        "logoutUrl",\n'
        '        "metadataDescriptorUrl",\n',
        '        "issuer",\n'
        '        "jwksUrl",\n'
        '        "logoutUrl",\n'
        '        "metadataDescriptorUrl",\n'
        '        "pkceEnabled",\n'
        '        "pkceMethod",\n',
        label="safe OIDC endpoint and PKCE fields",
    )
    replace_once(
        path,
        '    if registration.provider_id == "saml":\n'
        '        _validate_saml_registration(registration.provider_config)\n',
        '    if registration.provider_id == "saml":\n'
        '        _validate_saml_registration(registration.provider_config)\n'
        '    elif registration.provider_id in _OIDC_PROVIDER_IDS:\n'
        '        _validate_oidc_registration(registration.provider_config)\n',
        label="OIDC validation dispatch",
    )
    replace_once(
        path,
        'def _validate_https_url(\n'
        '    provider_config: dict[str, str], field_name: str\n'
        ') -> None:\n'
        '    """Validate one HTTPS network location without dereferencing it."""\n',
        'def _validate_https_url(\n'
        '    provider_config: dict[str, str], field_name: str\n'
        ') -> SplitResult:\n'
        '    """Validate and return one HTTPS location without dereferencing it."""\n',
        label="HTTPS helper return type",
    )
    replace_once(
        path,
        '        _provider_config_error(\n'
        '            field_name,\n'
        '            "must be an absolute HTTPS URL without a fragment",\n'
        '        )\n\n\n'
        'def _validate_signing_certificates(\n',
        '        _provider_config_error(\n'
        '            field_name,\n'
        '            "must be an absolute HTTPS URL without a fragment",\n'
        '        )\n'
        '    return parsed\n\n\n'
        'def _validate_required_provider_text(\n'
        '    provider_config: dict[str, str],\n'
        '    field_name: str,\n'
        '    *,\n'
        '    maximum_length: int = _MAX_PROVIDER_CONFIG_VALUE_LENGTH,\n'
        ') -> str:\n'
        '    """Return one bounded non-empty value without ambiguous controls."""\n'
        '    raw_value = provider_config.get(field_name)\n'
        '    invalid = (\n'
        '        raw_value is None\n'
        '        or not raw_value\n'
        '        or len(raw_value) > maximum_length\n'
        '        or raw_value != raw_value.strip()\n'
        '        or any(\n'
        '            ord(character) < 0x20 or ord(character) == 0x7F\n'
        '            for character in raw_value\n'
        '        )\n'
        '    )\n'
        '    if invalid:\n'
        '        _provider_config_error(\n'
        '            field_name,\n'
        '            "must be a bounded non-empty control-free value",\n'
        '        )\n'
        '    return cast(str, raw_value)\n\n\n'
        'def _validate_oidc_issuer(provider_config: dict[str, str]) -> None:\n'
        '    """Require one pinned HTTPS issuer without query or fragment."""\n'
        '    parsed = _validate_https_url(provider_config, "issuer")\n'
        '    if parsed.query or parsed.fragment:\n'
        '        _provider_config_error(\n'
        '            "issuer",\n'
        '            "must be an HTTPS URL without a query or fragment",\n'
        '        )\n\n\n'
        'def _validate_oidc_scopes(provider_config: dict[str, str]) -> None:\n'
        '    """Require an RFC 6749 scope set containing one openid token."""\n'
        '    raw_scope = _validate_required_provider_text(\n'
        '        provider_config, "defaultScope"\n'
        '    )\n'
        '    tokens = raw_scope.split(" ")\n'
        '    valid = (\n'
        '        all(tokens)\n'
        '        and all(_OAUTH_SCOPE_TOKEN.fullmatch(token) for token in tokens)\n'
        '        and len(tokens) == len(set(tokens))\n'
        '        and tokens.count("openid") == 1\n'
        '    )\n'
        '    if not valid:\n'
        '        _provider_config_error(\n'
        '            "defaultScope",\n'
        '            "must be unique RFC 6749 scope tokens including openid",\n'
        '        )\n\n\n'
        'def _validate_oidc_registration(provider_config: dict[str, str]) -> None:\n'
        '    """Enforce pinned endpoints, token validation, PKCE, and scopes."""\n'
        '    for discovery_key in _OIDC_FORBIDDEN_DISCOVERY_KEYS:\n'
        '        if discovery_key in provider_config:\n'
        '            _provider_config_error(\n'
        '                discovery_key,\n'
        '                "is not supported; render explicit pinned endpoints",\n'
        '            )\n'
        '    _validate_oidc_issuer(provider_config)\n'
        '    for endpoint_field in ("authorizationUrl", "tokenUrl", "jwksUrl"):\n'
        '        _validate_https_url(provider_config, endpoint_field)\n'
        '    for optional_endpoint in ("userInfoUrl", "logoutUrl"):\n'
        '        if optional_endpoint in provider_config:\n'
        '            _validate_https_url(provider_config, optional_endpoint)\n'
        '    _validate_required_provider_text(provider_config, "clientId")\n'
        '    _validate_required_provider_text(provider_config, "clientSecret")\n'
        '    client_auth_method = _validate_required_provider_text(\n'
        '        provider_config, "clientAuthMethod"\n'
        '    )\n'
        '    if client_auth_method not in _OIDC_CLIENT_AUTH_METHODS:\n'
        '        _provider_config_error(\n'
        '            "clientAuthMethod",\n'
        '            "must be client_secret_basic or client_secret_post",\n'
        '        )\n'
        '    for security_flag in (\n'
        '        "validateSignature",\n'
        '        "useJwksUrl",\n'
        '        "pkceEnabled",\n'
        '    ):\n'
        '        if not _validate_provider_boolean(provider_config, security_flag):\n'
        '            _provider_config_error(\n'
        '                security_flag,\n'
        '                "must be true for OIDC identity providers",\n'
        '            )\n'
        '    pkce_method = _validate_required_provider_text(\n'
        '        provider_config, "pkceMethod"\n'
        '    )\n'
        '    if pkce_method != _OIDC_PKCE_METHOD:\n'
        '        _provider_config_error("pkceMethod", "must be S256")\n'
        '    _validate_oidc_scopes(provider_config)\n\n\n'
        'def _validate_signing_certificates(\n',
        label="OIDC pure validators",
    )


def fix_test_contract() -> None:
    """Correct the test's empty-secret redaction assertion before GREEN."""
    path = "services/account_unification/tests/test_oidc_federation_preflight.py"
    replace_once(
        path,
        '    assert field_name in response.json()["detail"]\n'
        '    assert field_value not in response.text\n'
        '    _assert_no_side_effects(store, api)\n\n\n'
        'def test_oidc_put_rejects_invalid_configuration_before_mutation',
        '    assert field_name in response.json()["detail"]\n'
        '    if field_value:\n'
        '        assert field_value not in response.text\n'
        '    _assert_no_side_effects(store, api)\n\n\n'
        'def test_oidc_put_rejects_invalid_configuration_before_mutation',
        label="empty credential redaction assertion",
    )


def add_deployment_template() -> None:
    """Add a rendered-at-deploy-time OIDC IdP desired-state template."""
    write_new(
        "deploy/templates/oidc-idp-partner.json",
        '''{
  "provider_alias": "partner-oidc",
  "display_name": "Partner OIDC",
  "provider_id": "oidc",
  "enabled": true,
  "trust_email": false,
  "provider_config": {
    "issuer": "{{partner_oidc_issuer}}",
    "authorizationUrl": "{{partner_oidc_authorization_url}}",
    "tokenUrl": "{{partner_oidc_token_url}}",
    "userInfoUrl": "{{partner_oidc_userinfo_url}}",
    "jwksUrl": "{{partner_oidc_jwks_url}}",
    "clientId": "{{partner_oidc_client_id}}",
    "clientSecret": "{{partner_oidc_client_secret}}",
    "clientAuthMethod": "client_secret_basic",
    "validateSignature": "true",
    "useJwksUrl": "true",
    "pkceEnabled": "true",
    "pkceMethod": "S256",
    "defaultScope": "openid profile email",
    "syncMode": "IMPORT"
  }
}
''',
    )


def update_documentation() -> None:
    """Document the OIDC deployment contract and release-facing behavior."""
    replace_once(
        "deploy/templates/README.md",
        '| `saml-idp-employer-adfs.json` | Keyverse desired-state API | external IdP → Keyverse | `PUT /federation/identity-providers/employer-adfs` |\n'
        '| `ldap-source.json` | Keycloak Admin REST | external directory → Keycloak | `POST /admin/realms/{realm}/components` |\n'
        '| `oidc-rp-client.json` | Keycloak Admin REST | Keyverse → RP | `POST /admin/realms/{realm}/clients` |\n',
        '| `saml-idp-employer-adfs.json` | Keyverse desired-state API | external IdP → Keyverse | `PUT /federation/identity-providers/employer-adfs` |\n'
        '| `oidc-idp-partner.json` | Keyverse desired-state API | external OIDC IdP → Keyverse | `PUT /federation/identity-providers/partner-oidc` |\n'
        '| `ldap-source.json` | Keycloak Admin REST | external directory → Keycloak | `POST /admin/realms/{realm}/components` |\n'
        '| `oidc-rp-client.json` | Keycloak Admin REST | Keyverse → RP | `POST /admin/realms/{realm}/clients` |\n',
        label="OIDC template inventory",
    )
    replace_once(
        "deploy/templates/README.md",
        'See [`../../docs/federation-onboarding.md`](../../docs/federation-onboarding.md)\n'
        'for the complete operational and recovery flow.\n\n'
        '## Auto-linking policy\n',
        'See [`../../docs/federation-onboarding.md`](../../docs/federation-onboarding.md)\n'
        'for the complete operational and recovery flow.\n\n'
        '## Partner OIDC apply pattern\n\n'
        'Render `oidc-idp-partner.json` and use the same private-file, exact-200\n'
        'preflight, `ready_to_apply=true`, and `PUT` sequence above with\n'
        '`ALIAS="partner-oidc"`. The template pins issuer, authorization, token,\n'
        'JWKS, and optional UserInfo endpoints explicitly; runtime discovery import\n'
        'is not accepted. Every network endpoint is HTTPS, token signatures and JWKS\n'
        'retrieval are enabled, PKCE is fixed to `S256`, and `openid` is mandatory.\n'
        'Keep `trust_email=false` until the upstream verification and claim-mapping\n'
        'contract has been independently reviewed. `oidc-rp-client.json` is a\n'
        'different artifact: it registers Keyverse as an RP and is applied directly\n'
        'to Keycloak Admin REST rather than the Keyverse federation API.\n\n'
        '## Auto-linking policy\n',
        label="OIDC template instructions",
    )
    replace_once(
        "docs/federation-onboarding.md",
        'For SAML providers, Keyverse requires:\n',
        'For OpenID Connect providers, Keyverse requires explicit HTTPS issuer,\n'
        'authorization, token, and JWKS endpoints; signature validation; JWKS-based\n'
        'key retrieval; confidential-client authentication; PKCE `S256`; and a\n'
        'standards-valid scope set containing `openid`. Keyverse does not fetch OIDC\n'
        'discovery metadata during preflight. Render reviewed metadata into explicit\n'
        'desired state, restrict Keycloak egress to the approved HTTPS hosts, and\n'
        'reject redirect downgrade at the outbound proxy. Optional UserInfo and\n'
        'logout endpoints are validated when supplied. Keep `trust_email=false` by\n'
        'default and enable it only after the upstream email-verification and claim-\n'
        'mapping contract has been independently reviewed.\n\n'
        'For SAML providers, Keyverse requires:\n',
        label="OIDC onboarding policy",
    )
    replace_once(
        "docs/federation-onboarding.md",
        '- Keycloak. (2026). *Server Administration Guide: SAML v2.0 identity providers*.\n'
        '  https://www.keycloak.org/docs/latest/server_admin/#saml-v2-0-identity-providers\n',
        '- Keycloak. (2026). *Server Administration Guide: SAML v2.0 identity providers*.\n'
        '  https://www.keycloak.org/docs/latest/server_admin/#saml-v2-0-identity-providers\n'
        '- OpenID Foundation. (2023). *OpenID Connect Discovery 1.0 incorporating\n'
        '  errata set 2*. https://openid.net/specs/openid-connect-discovery-1_0.html\n'
        '- Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best\n'
        '  current practice for OAuth 2.0 security* (RFC 9700, BCP 240). Internet\n'
        '  Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9700\n'
        '- Sakimura, N., Bradley, J., & Agarwal, N. (2015). *Proof key for code\n'
        '  exchange by OAuth public clients* (RFC 7636). Internet Engineering Task\n'
        '  Force. https://www.rfc-editor.org/rfc/rfc7636\n',
        label="OIDC onboarding references",
    )
    replace_once(
        "CHANGELOG.md",
        '### Added\n\n'
        '- Side-effect-free federation preflight validation with redacted operator\n',
        '### Added\n\n'
        '- Fail-closed OIDC and Keycloak-OIDC federation preflight with pinned HTTPS\n'
        '  endpoints, JWKS signature validation, PKCE `S256`, confidential-client\n'
        '  authentication, and RFC 6749 scope validation before desired-state writes.\n'
        '- A deployment-ready external OIDC provider template for standalone, CWL,\n'
        '  and Naruon integrations with `trust_email=false` by default.\n'
        '- Side-effect-free federation preflight validation with redacted operator\n',
        label="OIDC changelog additions",
    )
    replace_once(
        "CHANGELOG.md",
        '### Fixed\n\n'
        '- Upgraded `cryptography` to 50.0.0 to remediate CVE-2026-69247 while\n',
        '### Fixed\n\n'
        '- Prevented external OIDC broker configuration from persisting cleartext or\n'
        '  unpinned endpoints, disabled token-signature/JWKS checks, missing PKCE,\n'
        '  unsupported client authentication, remote discovery imports, or OAuth-only\n'
        '  scope sets that omit `openid`.\n'
        '- Upgraded `cryptography` to 50.0.0 to remediate CVE-2026-69247 while\n',
        label="OIDC changelog fix",
    )
    replace_once(
        "docs/superpowers/plans/2026-08-04-keyverse-oidc-federation-preflight.md",
        '- [ ] Add explicit OIDC provider IDs, allowed client-auth methods, PKCE method,\n'
        '  forbidden discovery keys, and RFC 6749 scope-token constants.\n'
        '- [ ] Add bounded required-text validation without secret echoing.\n'
        '- [ ] Return parsed HTTPS URLs from the shared helper and enforce issuer query\n'
        '  and fragment restrictions.\n'
        '- [ ] Require explicit authorization, token, and JWKS endpoints; validate\n'
        '  optional UserInfo and logout endpoints when present.\n'
        '- [ ] Require signature validation, JWKS URL use, PKCE S256, confidential-client\n'
        '  credentials, and exactly one `openid` scope.\n'
        '- [ ] Reject runtime discovery import keys.\n'
        '- [ ] Expose only explicitly safe OIDC operational fields in redacted views.\n'
        '- [ ] Run focused tests, Ruff, interrogate, and full production coverage.\n',
        '- [x] Add explicit OIDC provider IDs, allowed client-auth methods, PKCE method,\n'
        '  forbidden discovery keys, and RFC 6749 scope-token constants.\n'
        '- [x] Add bounded required-text validation without secret echoing.\n'
        '- [x] Return parsed HTTPS URLs from the shared helper and enforce issuer query\n'
        '  and fragment restrictions.\n'
        '- [x] Require explicit authorization, token, and JWKS endpoints; validate\n'
        '  optional UserInfo and logout endpoints when present.\n'
        '- [x] Require signature validation, JWKS URL use, PKCE S256, confidential-client\n'
        '  credentials, and exactly one `openid` scope.\n'
        '- [x] Reject runtime discovery import keys.\n'
        '- [x] Expose only explicitly safe OIDC operational fields in redacted views.\n'
        '- [ ] Run focused tests, Ruff, interrogate, and full production coverage.\n',
        label="implementation plan progress",
    )
    replace_once(
        "docs/superpowers/plans/2026-08-04-keyverse-oidc-federation-preflight.md",
        '- [ ] Add a provider-neutral OIDC desired-state template with `trust_email=false`\n'
        '  by default.\n'
        '- [ ] Document verified out-of-band metadata rendering, preflight, apply,\n'
        '  egress restrictions, redirect downgrade protection, PKCE, and secret handling.\n'
        '- [ ] Distinguish OIDC IdP desired state from the existing OIDC RP-client raw\n'
        '  Keycloak template.\n'
        '- [ ] Record the buyer-visible security contract under `[Unreleased]`.\n'
        '- [ ] Validate JSON, Markdown shell snippets, and deployment contracts.\n',
        '- [x] Add a provider-neutral OIDC desired-state template with `trust_email=false`\n'
        '  by default.\n'
        '- [x] Document verified out-of-band metadata rendering, preflight, apply,\n'
        '  egress restrictions, redirect downgrade protection, PKCE, and secret handling.\n'
        '- [x] Distinguish OIDC IdP desired state from the existing OIDC RP-client raw\n'
        '  Keycloak template.\n'
        '- [x] Record the buyer-visible security contract under `[Unreleased]`.\n'
        '- [ ] Validate JSON, Markdown shell snippets, and deployment contracts.\n',
        label="deployment plan progress",
    )


def main() -> None:
    """Apply the OIDC production, test, deployment, and documentation changes."""
    apply_federation_validation()
    fix_test_contract()
    add_deployment_template()
    update_documentation()


if __name__ == "__main__":
    main()
