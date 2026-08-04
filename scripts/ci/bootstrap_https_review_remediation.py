#!/usr/bin/env python3
"""Apply the reviewed HTTPS-only federation remediation to the exact PR head."""
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: str, old: str, new: str, *, label: str) -> None:
    """Replace one exact source anchor and fail closed when the head drifted."""
    target = REPO_ROOT / path
    content = target.read_text(encoding="utf-8")
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    target.write_text(content.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    """Apply code, test, documentation, and changelog review remediations."""
    replace_once(
        "services/account_unification/app/federation.py",
        '_HTTP_SCHEMES = frozenset({"http", "https"})\n'
        '_PERCENT_ENCODED_CONTROL = re.compile(\n',
        '_HTTP_SCHEMES = frozenset({"http", "https"})\n'
        '_HTTPS_SCHEME = "https"\n'
        '_PERCENT_ENCODED_CONTROL = re.compile(\n',
        label="HTTPS scheme constant",
    )
    replace_once(
        "services/account_unification/app/federation.py",
        'def _validate_http_url(\n'
        '    provider_config: dict[str, str], field_name: str\n'
        ') -> None:\n'
        '    """Validate one HTTP(S) network location without fetching it."""\n',
        'def _validate_https_url(\n'
        '    provider_config: dict[str, str], field_name: str\n'
        ') -> None:\n'
        '    """Validate one HTTPS network location without dereferencing it."""\n',
        label="HTTPS URL helper",
    )
    replace_once(
        "services/account_unification/app/federation.py",
        '        parsed.scheme.lower() not in _HTTP_SCHEMES\n'
        '        or parsed.hostname is None\n'
        '        or bool(parsed.fragment)\n'
        '    ):\n'
        '        _provider_config_error(\n'
        '            field_name,\n'
        '            "must be an absolute HTTP(S) URL without a fragment",\n'
        '        )\n',
        '        parsed.scheme.lower() != _HTTPS_SCHEME\n'
        '        or parsed.hostname is None\n'
        '        or bool(parsed.fragment)\n'
        '    ):\n'
        '        _provider_config_error(\n'
        '            field_name,\n'
        '            "must be an absolute HTTPS URL without a fragment",\n'
        '        )\n',
        label="HTTPS URL policy",
    )
    replace_once(
        "services/account_unification/app/federation.py",
        '    _validate_http_url(provider_config, "singleSignOnServiceUrl")\n',
        '    _validate_https_url(provider_config, "singleSignOnServiceUrl")\n',
        label="HTTPS SSO call",
    )
    replace_once(
        "services/account_unification/app/federation.py",
        '    if use_metadata:\n'
        '        _validate_http_url(provider_config, "metadataDescriptorUrl")\n'
        '        return\n'
        '    _validate_signing_certificates(provider_config, "signingCertificate")\n',
        '    if use_metadata:\n'
        '        _validate_https_url(provider_config, "metadataDescriptorUrl")\n'
        '        if provider_config.get("signingCertificate", "").strip():\n'
        '            _validate_signing_certificates(\n'
        '                provider_config, "signingCertificate"\n'
        '            )\n'
        '        return\n'
        '    _validate_signing_certificates(provider_config, "signingCertificate")\n',
        label="metadata and optional manual trust validation",
    )

    replace_once(
        "services/account_unification/tests/test_federation_preflight.py",
        '        ("singleSignOnServiceUrl", "ftp://sts.example/adfs/ls/"),\n'
        '        ("singleSignOnServiceUrl", " https://sts.example/adfs/ls/"),\n',
        '        ("singleSignOnServiceUrl", "ftp://sts.example/adfs/ls/"),\n'
        '        ("singleSignOnServiceUrl", "http://sts.example/adfs/ls/"),\n'
        '        ("singleSignOnServiceUrl", " https://sts.example/adfs/ls/"),\n'
        '        (\n'
        '            "metadataDescriptorUrl",\n'
        '            "http://sts.example/FederationMetadata.xml",\n'
        '        ),\n',
        label="insecure HTTP regressions",
    )
    replace_once(
        "services/account_unification/tests/test_federation_preflight.py",
        '    assert config["signingCertificate"] == "<redacted>"\n'
        '    assert signing_certificates not in response.text\n'
        '    _assert_no_side_effects(store, api)\n',
        '    assert config["signingCertificate"] == "<redacted>"\n'
        '    for certificate_body in signing_certificates.split(","):\n'
        '        certificate_body = certificate_body.strip()\n'
        '        if certificate_body:\n'
        '            assert certificate_body not in response.text\n'
        '    _assert_no_side_effects(store, api)\n',
        label="per-certificate redaction assertion",
    )
    metadata_test_anchor = '''def test_saml_preflight_requires_manual_certificate_when_metadata_is_disabled(
    api, auth_header, operator_token
) -> None:
'''
    metadata_test_insertion = '''def test_saml_preflight_validates_optional_manual_certificate_in_metadata_mode(
    api, auth_header, operator_token
) -> None:
    """Metadata mode still rejects malformed optional manual trust material."""
    store = InMemoryKvStore()
    body = _adfs_body()
    body["provider_config"]["signingCertificate"] = "MIIC-test-certificate"

    response = _post_preflight(body, store, api, auth_header, operator_token)

    assert response.status_code == 400
    assert response.json()["detail"].startswith("signingCertificate ")
    assert "MIIC-test-certificate" not in response.text
    _assert_no_side_effects(store, api)


''' + metadata_test_anchor
    replace_once(
        "services/account_unification/tests/test_federation_preflight.py",
        metadata_test_anchor,
        metadata_test_insertion,
        label="metadata-mode optional certificate regression",
    )

    replace_once(
        "services/account_unification/tests/test_full_coverage_core.py",
        '    locks = object()\n'
        '    unification = object()\n'
        '    federation = object()\n'
        '    descriptor = SimpleNamespace(namespace="runtime")\n',
        '    locks = object()\n'
        '    unification = object()\n'
        '    federation = object()\n'
        '    wired_locks: object | None = None\n\n'
        '    def build_unification(\n'
        '        _api: object,\n'
        '        _audit: object,\n'
        '        _config: object,\n'
        '        user_operation_locks: object,\n'
        '    ) -> object:\n'
        '        """Capture the lock manager assigned to the merge service."""\n'
        '        nonlocal wired_locks\n'
        '        wired_locks = user_operation_locks\n'
        '        return unification\n\n'
        '    descriptor = SimpleNamespace(namespace="runtime")\n',
        label="shared lock capture helper",
    )
    replace_once(
        "services/account_unification/tests/test_full_coverage_core.py",
        '    monkeypatch.setattr(\n'
        '        main,\n'
        '        "UnificationService",\n'
        '        lambda *args: unification,\n'
        '    )\n',
        '    monkeypatch.setattr(\n'
        '        main,\n'
        '        "UnificationService",\n'
        '        build_unification,\n'
        '    )\n',
        label="shared lock constructor capture",
    )
    replace_once(
        "services/account_unification/tests/test_full_coverage_core.py",
        '    assert app.state.user_operation_locks is locks\n'
        '    assert app.state.federation_service is federation\n',
        '    assert app.state.user_operation_locks is locks\n'
        '    assert wired_locks is locks\n'
        '    assert app.state.federation_service is federation\n',
        label="shared lock identity assertion",
    )

    replace_once(
        "docs/federation-onboarding.md",
        'SAML entity identifiers are bounded absolute URIs and may use an interoperable\n'
        '`urn:` form. Network endpoints remain restricted to HTTP(S) and reject\n'
        'credentials, fragments, whitespace, backslashes, and raw or percent-encoded\n'
        'control characters. Preflight validates syntax and policy only; a deployment\n'
        'controller should separately restrict Keycloak egress to the approved metadata\n'
        'and SSO hosts.\n',
        'SAML entity identifiers are bounded absolute URIs and may use an interoperable\n'
        '`urn:` form. Network endpoints are restricted to HTTPS and reject credentials,\n'
        'fragments, whitespace, backslashes, and raw or percent-encoded control\n'
        'characters. Preflight deliberately does not dereference metadata or follow\n'
        'redirects, so it cannot observe a redirect target. Restrict Keycloak egress or\n'
        'its outbound proxy to approved HTTPS metadata and SSO hosts, and reject every\n'
        'HTTPS-to-HTTP redirect before the response reaches Keycloak.\n',
        label="HTTPS onboarding and redirect boundary",
    )
    replace_once(
        "docs/federation-onboarding.md",
        'When metadata refresh is enabled, pin the identity-provider entity identifier\n'
        'and restrict network egress to the approved metadata host. When metadata refresh\n'
        'is disabled, each `signingCertificate` entry must be a Base64 DER X.509\n',
        'When metadata refresh is enabled, pin the identity-provider entity identifier,\n'
        'restrict network egress to the approved HTTPS metadata host, and reject\n'
        'redirect downgrade. A supplied optional `signingCertificate` is still parsed\n'
        'and rejected if malformed, but metadata remains the selected certificate source.\n'
        'When metadata refresh is disabled, each `signingCertificate` entry must be a\n'
        'Base64 DER X.509\n',
        label="metadata trust-source clarification",
    )

    replace_once(
        "deploy/templates/README.md",
        'Preflight performs no KV write, no Keycloak Admin REST request, and no metadata\n'
        'fetch. Unresolved placeholders, unpinned SAML issuers, disabled signature\n'
        'validation, unsafe endpoints, or a missing certificate source return HTTP 400.\n',
        'Preflight performs no KV write, no Keycloak Admin REST request, and no metadata\n'
        'fetch. Unresolved placeholders, unpinned SAML issuers, disabled signature\n'
        'validation, non-HTTPS network endpoints, unsafe URI text, or a missing\n'
        'certificate source return HTTP 400. Because preflight never dereferences remote\n'
        'metadata, the Keycloak egress layer must also reject redirect downgrade.\n',
        label="template HTTPS policy",
    )

    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        '- network-reachable SSO and metadata locations as absolute HTTP(S) URLs without\n'
        '  userinfo, fragments, whitespace, backslashes, raw controls, encoded controls,\n'
        '  or invalid ports;\n',
        '- network-reachable SSO and metadata locations as absolute HTTPS URLs without\n'
        '  userinfo, fragments, whitespace, backslashes, raw controls, encoded controls,\n'
        '  or invalid ports;\n',
        label="design HTTPS scope",
    )
    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        '3. `singleSignOnServiceUrl` is required and must be an absolute HTTP(S) URL.\n',
        '3. `singleSignOnServiceUrl` is required and must be an absolute HTTPS URL.\n',
        label="design SSO rule",
    )
    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        '6. When metadata use is enabled, `metadataDescriptorUrl` is required and must\n'
        '   be an absolute HTTP(S) URL.\n'
        '7. When metadata use is disabled, `signingCertificate` is required. It must\n',
        '6. When metadata use is enabled, `metadataDescriptorUrl` is required and must\n'
        '   be an absolute HTTPS URL. An optional supplied `signingCertificate` is\n'
        '   validated when present but is not required because metadata is the selected\n'
        '   trust source.\n'
        '7. When metadata use is disabled, `signingCertificate` is required. It must\n',
        label="design metadata trust rule",
    )
    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        'URI validation rejects surrounding or internal whitespace, every C0 control\n'
        'character, DEL, backslashes, credentials in hierarchical authority components,\n'
        'and invalid or out-of-range ports. Network URL validation also rejects URI\n'
        'fragments. Query strings remain allowed because some enterprise metadata\n'
        'services use bounded query parameters.\n',
        'URI validation rejects surrounding or internal whitespace, every C0 control\n'
        'character, DEL, backslashes, credentials in hierarchical authority components,\n'
        'and invalid or out-of-range ports. Network URL validation also rejects URI\n'
        'fragments and every scheme other than HTTPS. Query strings remain allowed\n'
        'because some enterprise metadata services use bounded query parameters. The\n'
        'side-effect-free preflight never follows redirects; deployments must enforce an\n'
        'approved-host, HTTPS-only redirect policy at Keycloak egress or its outbound\n'
        'proxy.\n',
        label="design redirect responsibility",
    )
    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        '- The endpoint performs no external fetch, preventing a new SSRF surface.\n',
        '- The endpoint performs no external fetch, preventing a new SSRF surface and\n'
        '  deliberately leaving redirect-target enforcement to the Keycloak egress\n'
        '  boundary.\n',
        label="design no-fetch boundary",
    )
    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        '- every SAML required-field, URI, URL, trust-mode, and boolean branch fails with\n'
        '  HTTP 400 when invalid;\n',
        '- every SAML required-field, URI, URL, trust-mode, and boolean branch fails with\n'
        '  HTTP 400 when invalid, including direct HTTP SSO and metadata endpoints;\n',
        label="design HTTPS tests",
    )
    replace_once(
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        '- valid single and comma-separated rollover certificates are accepted when\n'
        '  metadata retrieval is disabled;\n',
        '- valid single and comma-separated rollover certificates are accepted when\n'
        '  metadata retrieval is disabled, and every certificate body is individually\n'
        '  absent from the redacted response;\n'
        '- malformed optional manual trust material also fails when metadata mode is\n'
        '  selected;\n',
        label="design certificate tests",
    )

    replace_once(
        "docs/superpowers/plans/2026-08-04-keyverse-federation-preflight.md",
        '- [x] Add bounded HTTP(S)-only validation for SSO and metadata locations.\n',
        '- [x] Add bounded HTTPS-only validation for SSO and metadata locations while\n'
        '  preserving HTTP(S) and `urn:` entity identifiers.\n',
        label="plan HTTPS implementation",
    )
    replace_once(
        "docs/superpowers/plans/2026-08-04-keyverse-federation-preflight.md",
        '- [x] Document convergence, outage recovery, certificate rotation, egress\n'
        '  restriction, redaction, and deletion semantics.\n',
        '- [x] Document convergence, outage recovery, certificate rotation, HTTPS-only\n'
        '  egress and redirect-downgrade restriction, redaction, and deletion semantics.\n',
        label="plan HTTPS documentation",
    )

    replace_once(
        "CHANGELOG.md",
        '- Rejected raw C0 controls, DEL, invalid ports, malformed Base64, non-X.509\n'
        '  DER, PEM-wrapped manual certificates, and empty rollover certificate entries\n'
        '  before federation desired state can be persisted.\n',
        '- Rejected raw C0 controls, DEL, invalid ports, insecure HTTP SSO or metadata\n'
        '  endpoints, malformed Base64, non-X.509 DER, PEM-wrapped manual certificates,\n'
        '  and empty rollover certificate entries before federation desired state can\n'
        '  be persisted.\n',
        label="changelog HTTPS hardening",
    )

    for relative_path in (
        "services/account_unification/app/federation.py",
        "services/account_unification/tests/test_federation_preflight.py",
        "services/account_unification/tests/test_full_coverage_core.py",
        "docs/federation-onboarding.md",
        "deploy/templates/README.md",
        "docs/superpowers/specs/2026-08-04-keyverse-federation-preflight-design.md",
        "docs/superpowers/plans/2026-08-04-keyverse-federation-preflight.md",
        "CHANGELOG.md",
    ):
        path = REPO_ROOT / relative_path
        path.write_text(path.read_text(encoding="utf-8").rstrip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
