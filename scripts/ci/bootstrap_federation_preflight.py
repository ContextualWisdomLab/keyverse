#!/usr/bin/env python3
"""Materialize the reviewed federation preflight implementation and docs."""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/bootstrap-federation-preflight.yml"
SCRIPT_PATH = Path(__file__).resolve()


def _read(relative_path: str) -> str:
    """Read one UTF-8 repository file."""
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _write(relative_path: str, content: str) -> None:
    """Write one UTF-8 repository file with a trailing newline."""
    normalized = content.rstrip() + "\n"
    path = REPO_ROOT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized, encoding="utf-8")


def _replace_once(content: str, old: str, new: str, *, label: str) -> str:
    """Replace one exact reviewed anchor and fail closed on drift."""
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return content.replace(old, new, 1)


def _replace_section(
    content: str,
    start_marker: str,
    end_marker: str,
    replacement: str,
    *,
    label: str,
) -> str:
    """Replace one bounded source section and retain its end marker."""
    start_count = content.count(start_marker)
    end_count = content.count(end_marker)
    if start_count != 1 or end_count != 1:
        raise RuntimeError(
            f"{label}: expected one start/end marker, found "
            f"{start_count}/{end_count}"
        )
    start_index = content.index(start_marker)
    end_index = content.index(end_marker, start_index)
    return content[:start_index] + replacement.rstrip() + "\n\n" + content[end_index:]


def _update_federation_module() -> None:
    """Add side-effect-free preflight and shared SAML validation."""
    path = "services/account_unification/app/federation.py"
    content = _read(path)
    content = _replace_once(
        content,
        "import logging\nimport threading\n",
        "import logging\nimport threading\nfrom urllib.parse import SplitResult, urlsplit\n",
        label="federation imports",
    )
    content = _replace_once(
        content,
        "_ALIAS_EDGE_ALPHABET = frozenset(\"abcdefghijklmnopqrstuvwxyz0123456789\")\n",
        "_ALIAS_EDGE_ALPHABET = frozenset(\"abcdefghijklmnopqrstuvwxyz0123456789\")\n"
        "_HTTP_SCHEMES = frozenset({\"http\", \"https\"})\n"
        "_SAML_ENTITY_ID_MAX_LENGTH = 1_024\n"
        "_UNRESOLVED_TEMPLATE_MARKERS = (\"{{\", \"}}\")\n",
        label="federation validation constants",
    )
    content = _replace_once(
        content,
        '        "hideOnLoginPage",\n        "issuer",\n',
        '        "hideOnLoginPage",\n        "idpEntityId",\n        "issuer",\n',
        label="safe IdP issuer exposure",
    )
    content = _replace_once(
        content,
        "        )\n\n\nclass IdentityProviderStatus(BaseModel):\n",
        "        )\n\n\nclass IdentityProviderValidationResult(BaseModel):\n"
        "    \"\"\"Redacted result proving a registration is ready for persistence.\"\"\"\n\n"
        "    registration: IdentityProviderView\n"
        "    ready_to_apply: bool = True\n\n\n"
        "class IdentityProviderStatus(BaseModel):\n",
        label="preflight response model",
    )
    content = _replace_once(
        content,
        "        self._state_lock = threading.RLock()\n"
        "        self._convergence_lock = threading.RLock()\n\n"
        "    def list_registrations(self) -> list[IdentityProviderStatus]:\n",
        "        self._state_lock = threading.RLock()\n"
        "        self._convergence_lock = threading.RLock()\n\n"
        "    def validate_registration(\n"
        "        self, registration: IdentityProviderRegistration\n"
        "    ) -> IdentityProviderValidationResult:\n"
        "        \"\"\"Validate desired state without storage or Keycloak side effects.\"\"\"\n"
        "        _validate_registration(registration)\n"
        "        return IdentityProviderValidationResult(\n"
        "            registration=IdentityProviderView.from_registration(registration)\n"
        "        )\n\n"
        "    def list_registrations(self) -> list[IdentityProviderStatus]:\n",
        label="preflight service method",
    )
    validation_section = '''def _validate_registration(
    registration: IdentityProviderRegistration,
) -> None:
    """Validate one provider registration and bounded config map."""
    _validate_provider_alias(registration.provider_alias)
    if registration.provider_id not in _SUPPORTED_PROVIDER_IDS:
        raise HTTPException(
            status_code=400,
            detail="provider_id must be one of: saml, oidc, keycloak-oidc",
        )
    if len(registration.provider_config) > _MAX_PROVIDER_CONFIG_ENTRIES:
        raise HTTPException(
            status_code=400,
            detail="provider_config contains too many entries",
        )
    for config_key, config_value in registration.provider_config.items():
        if (
            not config_key
            or len(config_key) > _MAX_PROVIDER_CONFIG_KEY_LENGTH
            or len(config_value) > _MAX_PROVIDER_CONFIG_VALUE_LENGTH
        ):
            raise HTTPException(
                status_code=400,
                detail="provider_config key or value exceeds allowed bounds",
            )
        if any(
            marker in config_value
            for marker in _UNRESOLVED_TEMPLATE_MARKERS
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "provider_config contains unresolved template placeholders"
                ),
            )
    if registration.provider_id == "saml":
        _validate_saml_registration(registration.provider_config)


def _provider_config_error(field_name: str, requirement: str) -> None:
    """Raise one bounded non-secret provider configuration error."""
    raise HTTPException(
        status_code=400,
        detail=f"{field_name} {requirement}",
    )


def _validate_provider_boolean(
    provider_config: dict[str, str], field_name: str
) -> bool:
    """Parse one required Keycloak configuration boolean strictly."""
    raw_value = provider_config.get(field_name)
    if raw_value is None:
        _provider_config_error(field_name, "is required and must be true or false")
    normalized = raw_value.strip().lower()
    if normalized not in {"true", "false"}:
        _provider_config_error(field_name, "must be true or false")
    return normalized == "true"


def _validate_absolute_uri(
    provider_config: dict[str, str],
    field_name: str,
    *,
    maximum_length: int,
) -> SplitResult:
    """Validate one bounded absolute URI without dereferencing it."""
    value = provider_config.get(field_name, "")
    invalid_text = (
        not value
        or len(value) > maximum_length
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    )
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    invalid_uri = (
        parsed is None
        or not parsed.scheme
        or parsed.username is not None
        or parsed.password is not None
        or (
            parsed.scheme.lower() in _HTTP_SCHEMES
            and parsed.hostname is None
        )
    )
    if invalid_text or invalid_uri:
        _provider_config_error(field_name, "must be a bounded absolute URI")
    return parsed


def _validate_http_url(
    provider_config: dict[str, str], field_name: str
) -> None:
    """Validate one HTTP(S) network location without fetching it."""
    parsed = _validate_absolute_uri(
        provider_config,
        field_name,
        maximum_length=_MAX_PROVIDER_CONFIG_VALUE_LENGTH,
    )
    if (
        parsed.scheme.lower() not in _HTTP_SCHEMES
        or parsed.hostname is None
        or bool(parsed.fragment)
    ):
        _provider_config_error(
            field_name,
            "must be an absolute HTTP(S) URL without a fragment",
        )


def _validate_saml_registration(provider_config: dict[str, str]) -> None:
    """Enforce issuer, endpoint, signature, and certificate-source policy."""
    _validate_absolute_uri(
        provider_config,
        "entityId",
        maximum_length=_SAML_ENTITY_ID_MAX_LENGTH,
    )
    _validate_absolute_uri(
        provider_config,
        "idpEntityId",
        maximum_length=_SAML_ENTITY_ID_MAX_LENGTH,
    )
    _validate_http_url(provider_config, "singleSignOnServiceUrl")
    if not _validate_provider_boolean(provider_config, "validateSignature"):
        _provider_config_error(
            "validateSignature",
            "must be true for SAML identity providers",
        )
    use_metadata = _validate_provider_boolean(
        provider_config, "useMetadataDescriptorUrl"
    )
    if use_metadata:
        _validate_http_url(provider_config, "metadataDescriptorUrl")
        return
    if not provider_config.get("signingCertificate", "").strip():
        _provider_config_error(
            "signingCertificate",
            "is required when metadata certificate refresh is disabled",
        )
'''
    content = _replace_section(
        content,
        "def _validate_registration(\n",
        "def _redacted_provider_config(\n",
        validation_section,
        label="federation validation section",
    )
    content = _replace_once(
        content,
        "@federation_router.get(\n"
        "    \"/identity-providers\", response_model=list[IdentityProviderStatus]\n"
        ")\n",
        "@federation_router.post(\n"
        "    \"/identity-providers:validate\",\n"
        "    response_model=IdentityProviderValidationResult,\n"
        ")\n"
        "def validate_identity_provider(\n"
        "    registration: IdentityProviderRegistration,\n"
        "    service: FederationService = Depends(get_federation_service),\n"
        ") -> IdentityProviderValidationResult:\n"
        "    \"\"\"Validate provider desired state without writing or converging it.\"\"\"\n"
        "    return service.validate_registration(registration)\n\n\n"
        "@federation_router.get(\n"
        "    \"/identity-providers\", response_model=list[IdentityProviderStatus]\n"
        ")\n",
        label="preflight route",
    )
    _write(path, content)


def _update_existing_federation_fixture() -> None:
    """Keep existing federation regressions valid under the stricter policy."""
    path = "services/account_unification/tests/test_federation.py"
    content = _read(path)
    content = _replace_once(
        content,
        '            "entityId": "https://idp.example/realms/cwl",\n'
        '            "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",\n'
        '            "clientSecret": "federation-secret",\n',
        '            "entityId": "https://idp.example/realms/cwl",\n'
        '            "idpEntityId": "http://sts.example/adfs/services/trust",\n'
        '            "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",\n'
        '            "metadataDescriptorUrl": (\n'
        '                "https://sts.example/FederationMetadata/2007-06/"\n'
        '                "FederationMetadata.xml"\n'
        '            ),\n'
        '            "useMetadataDescriptorUrl": "true",\n'
        '            "clientSecret": "federation-secret",\n',
        label="existing ADFS fixture",
    )
    _write(path, content)


def _write_adfs_template() -> None:
    """Convert the employer ADFS template to the Keyverse API contract."""
    _write(
        "deploy/templates/saml-idp-employer-adfs.json",
        '''{
  "provider_alias": "employer-adfs",
  "display_name": "Employer ADFS (hssmartdev)",
  "provider_id": "saml",
  "enabled": true,
  "trust_email": true,
  "provider_config": {
    "entityId": "https://idp.example/realms/cwl",
    "idpEntityId": "http://sts.hssmartdev.com/adfs/services/trust",
    "metadataDescriptorUrl": "{{employer_adfs_metadata_url}}",
    "useMetadataDescriptorUrl": "true",
    "singleSignOnServiceUrl": "{{employer_adfs_sso_url}}",
    "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "principalType": "SUBJECT",
    "postBindingResponse": "true",
    "postBindingAuthnRequest": "true",
    "wantAuthnRequestsSigned": "true",
    "wantAssertionsSigned": "true",
    "validateSignature": "true",
    "syncMode": "FORCE"
  }
}''',
    )


def _write_template_readme() -> None:
    """Document which control plane owns each deployment template."""
    _write(
        "deploy/templates/README.md",
        '''# Federation and client registration templates

These files are deployment inputs. They contain no reusable credentials and all
`{{placeholders}}` must be resolved from the platform KV before use.

| Template | Owner | Direction | Apply endpoint |
| --- | --- | --- | --- |
| `saml-idp-employer-adfs.json` | Keyverse desired-state API | external IdP → Keyverse | `PUT /federation/identity-providers/employer-adfs` |
| `ldap-source.json` | Keycloak Admin REST | external directory → Keycloak | `POST /admin/realms/{realm}/components` |
| `oidc-rp-client.json` | Keycloak Admin REST | Keyverse → RP | `POST /admin/realms/{realm}/clients` |

The portable realm contains no employer-specific federation. External providers
are customer or deployment data stored in the Keyverse KV/DB desired-state
registry and reconciled into Keycloak.

## Employer ADFS apply pattern

Render the ADFS template into a private temporary file, validate it without side
effects, and apply it only after preflight returns HTTP 200:

```bash
BASE="https://keyverse-admin.example"
TOKEN="$(kv get secret/keyverse/operator-api-token)"
render deploy/templates/saml-idp-employer-adfs.json >"$TMPDIR/employer-adfs.json"
chmod 0600 "$TMPDIR/employer-adfs.json"

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @"$TMPDIR/employer-adfs.json" \
  "$BASE/federation/identity-providers:validate"

curl --fail-with-body --silent --show-error -X PUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @"$TMPDIR/employer-adfs.json" \
  "$BASE/federation/identity-providers/employer-adfs"
```

Preflight performs no KV write, no Keycloak Admin REST request, and no metadata
fetch. Unresolved placeholders, unpinned SAML issuers, disabled signature
validation, unsafe endpoints, or a missing certificate source return HTTP 400.
Operator responses redact unknown and credential-bearing configuration values.

See [`../../docs/federation-onboarding.md`](../../docs/federation-onboarding.md)
for the complete operational and recovery flow.

## Auto-linking policy

`trust_email: true` makes an email assertion eligible for account linking only
when the upstream provider's assertion is trusted as verified. The
account-unification service retains the stricter invariant: it never links or
merges accounts when the only common signal is an unverified email. See
[`../../docs/merge-unification-flow.md`](../../docs/merge-unification-flow.md).
''',
    )


def _write_onboarding_guide() -> None:
    """Write the operator-facing federation onboarding and recovery guide."""
    _write(
        "docs/federation-onboarding.md",
        '''# External federation onboarding

Keyverse treats external identity providers as deployment desired state rather
than portable realm code. This keeps the standalone component reusable across
organizations and allows a parent CWL or Naruon deployment to manage federation
through one stable API.

## Trust boundary

The operator API is privileged. Store its bearer token in the platform secret
manager and expose it only to the deployment controller. The preflight endpoint
accepts the same closed request schema as `PUT`, but it deliberately performs no
storage write, Keycloak call, DNS lookup, or metadata download.

For SAML providers Keyverse requires:

- explicit service-provider and identity-provider entity identifiers;
- an HTTP(S) SSO endpoint;
- signature validation enabled;
- an explicit certificate-source mode;
- either an HTTP(S) metadata descriptor URL or a manually supplied signing
  certificate;
- fully rendered values without `{{...}}` markers.

SAML entity identifiers are absolute URIs and may use an interoperable `urn:`
form. Network endpoints remain restricted to HTTP(S).

## Render, validate, apply

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
ALIAS="employer-adfs"
TOKEN="$(kv get secret/keyverse/operator-api-token)"
PAYLOAD="$(mktemp)"
trap 'rm -f "$PAYLOAD"' EXIT
chmod 0600 "$PAYLOAD"
render deploy/templates/saml-idp-employer-adfs.json >"$PAYLOAD"

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers:validate"

curl --fail-with-body --silent --show-error -X PUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers/${ALIAS}"
```

A successful `PUT` persists desired state even when Keycloak is temporarily
unavailable and returns `applied_to_keycloak: false`. This makes the outage
visible without losing the intended configuration.

## Convergence and recovery

List redacted desired state and live convergence status:

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${TOKEN}" \
  "$BASE/federation/identity-providers"
```

After a Keycloak restart, realm rebuild, or temporary outage, reapply all stored
providers:

```bash
curl --fail-with-body --silent --show-error -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  "$BASE/federation/identity-providers:apply"
```

Delete removes the provider from Keycloak first and then removes desired state.
If Keycloak deletion fails, the desired-state record remains so the operator can
retry without silently orphaning an applied provider.

## Secret handling

Unknown provider configuration values are accepted for convergence but are
redacted from every operator response. Payload files must be private and
short-lived. Do not pass client secrets or signing material in process arguments,
workflow logs, issue comments, or source-controlled templates.

## Standards basis

- OASIS Security Services Technical Committee. (2019). *SAML V2.0 Metadata
  Interoperability Profile Version 1.0*.
  https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.html
- Keycloak. (2026). *Server Administration Guide: SAML v2.0 identity providers*.
  https://www.keycloak.org/docs/latest/server_admin/#saml-v2-0-identity-providers
''',
    )


def _update_root_readme() -> None:
    """Remove stale claims that employer federation is committed realm code."""
    path = "README.md"
    content = _read(path)
    content = _replace_once(
        content,
        "| `deploy/keycloak/` | Keycloak config-as-code: realm export (passwordless flow, OIDC RP template, ADFS SAML IdP, LDAP source, service-account client) + kcadm bootstrap |\n",
        "| `deploy/keycloak/` | Portable Keycloak realm config-as-code, passwordless flows, shared scopes, concrete Naruon RP, and service-account bootstrap |\n",
        label="root layout description",
    )
    content = _replace_once(
        content,
        "### Register the employer ADFS + LDAP\n\n"
        "The realm ships the employer ADFS SAML IdP and the LDAP/AD source as-code; run\n"
        "`deploy/keycloak/kcadm-bootstrap.sh` to patch their secrets/URLs from KV. To\n"
        "register additional RPs/IdPs against a running realm, apply the templates in\n"
        "`deploy/templates/`. See [`deploy/keycloak/README.md`](deploy/keycloak/README.md)\n"
        "and [`deploy/templates/README.md`](deploy/templates/README.md).\n",
        "### Register external federation\n\n"
        "The portable realm contains no employer ADFS, LDAP/AD source, or other\n"
        "customer-specific federation. Render deployment values from KV, validate SAML\n"
        "desired state through the side-effect-free preflight endpoint, and converge it\n"
        "through `/federation/identity-providers`. See\n"
        "[`docs/federation-onboarding.md`](docs/federation-onboarding.md),\n"
        "[`deploy/keycloak/README.md`](deploy/keycloak/README.md), and\n"
        "[`deploy/templates/README.md`](deploy/templates/README.md).\n",
        label="root federation onboarding section",
    )
    _write(path, content)


def _update_changelog() -> None:
    """Record the unreleased preflight and template corrections."""
    path = "CHANGELOG.md"
    content = _read(path)
    content = _replace_once(
        content,
        "### Added\n\n",
        "### Added\n\n"
        "- Side-effect-free federation preflight validation with redacted operator\n"
        "  results, explicit SAML issuer pinning, mandatory signature validation, and\n"
        "  metadata-backed or manual certificate trust.\n"
        "- An operational external-federation onboarding and recovery guide for\n"
        "  standalone, CWL platform, and Naruon-integrated deployments.\n",
        label="changelog additions",
    )
    content = _replace_once(
        content,
        "### Fixed\n\n",
        "### Fixed\n\n"
        "- Converted the employer ADFS template from an incompatible raw Keycloak\n"
        "  representation to the closed Keyverse desired-state API contract.\n"
        "- Corrected root and template documentation that still claimed employer\n"
        "  federation was embedded in the portable realm.\n",
        label="changelog fixes",
    )
    _write(path, content)


def main() -> None:
    """Apply every reviewed change and remove the one-shot materializer."""
    _update_federation_module()
    _update_existing_federation_fixture()
    _write_adfs_template()
    _write_template_readme()
    _write_onboarding_guide()
    _update_root_readme()
    _update_changelog()
    WORKFLOW_PATH.unlink()
    SCRIPT_PATH.unlink()


if __name__ == "__main__":
    main()
