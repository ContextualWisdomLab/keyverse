# Federation Preflight Validation Design

## Problem

Keyverse stores external identity-provider desired state and converges it into
Keycloak, but the current operator workflow accepts only generic size and alias
checks. A rendered ADFS/SAML payload can therefore contain unresolved template
markers, missing SSO endpoints, relative URLs, disabled signature validation, or
no trusted certificate source. `PUT` persists that invalid desired state before
Keycloak reports convergence failure, and the committed ADFS template still
uses the raw Keycloak Admin REST shape instead of the Keyverse desired-state
API shape.

For an enterprise identity control plane, configuration errors must fail before
persistence and before a network call. Operators also need a safe dry-run
endpoint that never writes desired state, never calls Keycloak, and never echoes
credentials.

## Scope

This slice adds a provider-neutral preflight endpoint and secure SAML-specific
validation for the employer ADFS compatibility path.

In scope:

- `POST /federation/identity-providers:validate` using the same
  `IdentityProviderRegistration` contract as `PUT`;
- redacted success responses with an explicit `ready_to_apply` signal;
- no desired-state mutation and no Keycloak Admin REST call during preflight;
- unresolved `{{...}}` marker rejection for all provider configuration values;
- SAML validation for service-provider entity ID, SSO URL, signature validation,
  and a certificate source;
- either a metadata descriptor URL or manually supplied signing certificate;
- absolute HTTP(S) URLs without userinfo, fragments, or control characters;
- conversion of the employer ADFS template to the Keyverse runtime API shape;
- operator documentation, root README correction, and changelog update.

Out of scope:

- fetching or parsing remote SAML metadata inside the account-unification
  service;
- OIDC discovery endpoint probing;
- LDAP desired-state management;
- an administrative web UI;
- secret rotation or drift fingerprinting.

## API Contract

### Request

`POST /federation/identity-providers:validate`

The request body is `IdentityProviderRegistration`:

```json
{
  "provider_alias": "employer-adfs",
  "display_name": "Employer ADFS",
  "provider_id": "saml",
  "enabled": true,
  "trust_email": true,
  "provider_config": {
    "entityId": "https://idp.example/realms/cwl",
    "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",
    "validateSignature": "true",
    "useMetadataDescriptorUrl": "true",
    "metadataDescriptorUrl": "https://sts.example/FederationMetadata/2007-06/FederationMetadata.xml"
  }
}
```

### Success

HTTP 200:

```json
{
  "registration": {
    "provider_alias": "employer-adfs",
    "display_name": "Employer ADFS",
    "provider_id": "saml",
    "enabled": true,
    "trust_email": true,
    "provider_config": {
      "entityId": "https://idp.example/realms/cwl",
      "singleSignOnServiceUrl": "https://sts.example/adfs/ls/",
      "validateSignature": "true",
      "clientSecret": "<redacted>"
    }
  },
  "ready_to_apply": true
}
```

The response uses the existing safe allowlist and redacts every unknown or
credential-like configuration value.

### Failure

Invalid input returns HTTP 400 with one bounded, non-secret explanation. No
provider configuration value is copied into the error detail.

## Validation Rules

All providers retain the existing alias, provider ID, entry-count, key-length,
and value-length bounds. Any provider configuration value containing `{{` or
`}}` is rejected as an unresolved template.

For `provider_id == "saml"`:

1. `entityId` is required and must be an absolute HTTP(S) URL.
2. `singleSignOnServiceUrl` is required and must be an absolute HTTP(S) URL.
3. `validateSignature` must be the exact boolean string `true` after trimming
   and ASCII case normalization.
4. `useMetadataDescriptorUrl`, when present, must be `true` or `false`.
5. When metadata use is enabled, `metadataDescriptorUrl` is required and must
   be an absolute HTTP(S) URL.
6. When metadata use is disabled, a non-empty `signingCertificate` is required.

URL validation rejects credentials in authority components, URI fragments, and
ASCII control characters. Query strings remain allowed because some enterprise
metadata services use bounded query parameters.

## Architecture and Data Flow

The pure validation helpers remain inside `app/federation.py`, next to the
existing desired-state model and validation boundary. This avoids a circular
model dependency and keeps all HTTP 400 semantics consistent.

Preflight flow:

1. FastAPI authenticates the operator bearer token.
2. Pydantic validates the closed request schema.
3. `FederationService.validate_registration` runs generic and SAML policy
   validation.
4. The service returns `IdentityProviderValidationResult`, built from the
   redacted `IdentityProviderView`.
5. No store or Keycloak method is invoked.

Apply flow remains unchanged except that the same stronger validation runs
before the desired-state write.

## Security and Privacy

- Preflight is operator-authenticated through the existing router dependency.
- The endpoint performs no external fetch, preventing a new SSRF surface.
- Unresolved placeholders fail before persistence.
- Secret-bearing configuration is accepted for validation but never returned.
- Error text names only configuration fields and policy requirements, never
  supplied values.
- SAML signature validation cannot be disabled through the supported runtime
  contract.

## Testing

The test-first sequence proves:

- the new route is absent before implementation;
- a valid ADFS registration returns a redacted 200 response;
- preflight leaves both the KV store and Keycloak mock untouched;
- unresolved placeholders fail closed without side effects;
- every SAML required-field and URL branch fails with HTTP 400;
- manual signing certificates are accepted when metadata retrieval is disabled;
- malformed boolean strings are rejected;
- the existing `PUT`, list, get, apply, outage, lock, and redaction regressions
  remain green;
- production docstring and statement/branch coverage remain 100%.

## Compatibility and Release

The existing `PUT`, `GET`, `DELETE`, and `:apply` routes are not renamed. The
new endpoint is additive. The employer ADFS template changes from a raw
Keycloak representation to the already-public Keyverse registration contract;
operator documentation explicitly distinguishes it from the remaining raw LDAP
and RP-client templates.

This is an unreleased feature. It updates `CHANGELOG.md` but does not bump the
package or Helm version until the broader 0.2.0 release criteria are satisfied.
