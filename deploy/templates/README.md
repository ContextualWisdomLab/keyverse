# Federation and client registration templates

These files are deployment inputs. They contain no reusable credentials, and
all `{{placeholders}}` must be resolved from the platform KV before use.

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
effects, and apply it only after preflight returns HTTP 200. Keep the bearer
token out of the `curl` argument vector by placing the header in a private curl
configuration file:

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
ALIAS="employer-adfs"
TOKEN="$(kv get secret/keyverse/operator-api-token)"
PAYLOAD="$(mktemp)"
AUTH_CONFIG="$(mktemp)"
trap 'rm -f "$PAYLOAD" "$AUTH_CONFIG"' EXIT
chmod 0600 "$PAYLOAD" "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN

render deploy/templates/saml-idp-employer-adfs.json >"$PAYLOAD"

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers:validate"

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --request PUT \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers/$ALIAS"
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
