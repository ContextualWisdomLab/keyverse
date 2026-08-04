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
PAYLOAD="$(mktemp)"
PREFLIGHT_RESPONSE="$(mktemp)"
AUTH_CONFIG=""
cleanup() {
  rm -f "$PAYLOAD" "$PREFLIGHT_RESPONSE"
  if [ -n "${AUTH_CONFIG:-}" ]; then
    rm -f "$AUTH_CONFIG"
  fi
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$PREFLIGHT_RESPONSE"

XTRACE_WAS_ON=0
case $- in
  *x*)
    XTRACE_WAS_ON=1
    set +x
    ;;
esac
TOKEN="$(kv get secret/keyverse/operator-api-token)"
AUTH_CONFIG="$(mktemp)"
chmod 0600 "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

render deploy/templates/saml-idp-employer-adfs.json >"$PAYLOAD"

PREFLIGHT_STATUS="$(
  curl --config "$AUTH_CONFIG" \
    --silent \
    --show-error \
    --max-redirs 0 \
    --output "$PREFLIGHT_RESPONSE" \
    --write-out '%{http_code}' \
    --header "Content-Type: application/json" \
    --data-binary @"$PAYLOAD" \
    "$BASE/federation/identity-providers:validate"
)"
if [ "$PREFLIGHT_STATUS" != "200" ]; then
  printf 'preflight returned HTTP %s\n' "$PREFLIGHT_STATUS" >&2
  cat "$PREFLIGHT_RESPONSE" >&2
  exit 1
fi
if ! python3 - "$PREFLIGHT_RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
raise SystemExit(0 if response.get("ready_to_apply") is True else 1)
PY
then
  echo 'preflight response did not confirm ready_to_apply=true' >&2
  exit 1
fi

curl --config "$AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request PUT \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$BASE/federation/identity-providers/$ALIAS"
```

Preflight performs no KV write, no Keycloak Admin REST request, and no metadata
fetch. Unresolved placeholders, unpinned SAML issuers, disabled signature
validation, non-HTTPS network endpoints, unsafe URI text, or a missing
certificate source return HTTP 400. Because preflight never dereferences remote
metadata, the Keycloak egress layer must also reject redirect downgrade.
Operator responses redact unknown and credential-bearing configuration values.

See [`../../docs/federation-onboarding.md`](../../docs/federation-onboarding.md)
for the complete operational and recovery flow.

## Auto-linking policy

`trust_email: true` makes an email assertion eligible for account linking only
when the upstream provider's assertion is trusted as verified. The
account-unification service retains the stricter invariant: it never links or
merges accounts when the only common signal is an unverified email. See
[`../../docs/merge-unification-flow.md`](../../docs/merge-unification-flow.md).
