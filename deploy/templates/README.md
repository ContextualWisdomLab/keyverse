# Federation and client registration templates

These files are deployment inputs. They contain no reusable credentials, and
all `{{placeholders}}` must be resolved from the platform KV before use.

| Template | Owner | Direction | Preflight | Apply endpoint |
| --- | --- | --- | --- | --- |
| `saml-idp-employer-adfs.json` | Keyverse desired-state API | external IdP → Keyverse | `POST /federation/identity-providers:validate` | `PUT /federation/identity-providers/employer-adfs` |
| `oidc-idp-partner.json` | Keyverse desired-state API | external OIDC IdP → Keyverse | `POST /federation/identity-providers:validate` | `PUT /federation/identity-providers/partner-oidc` |
| `ldap-source.json` | Keycloak component contract | external directory → Keycloak | `POST /federation/user-directories:validate` | `POST /admin/realms/{realm}/components` |
| `oidc-rp-client.json` | Keycloak Admin REST | Keyverse → RP | deployment review | `POST /admin/realms/{realm}/clients` |

The portable realm contains no employer-specific federation. External SAML and
OIDC providers are customer or deployment data stored in the Keyverse KV/DB
desired-state registry and reconciled into Keycloak. LDAP is still applied as a
Keycloak user-storage component in this release, but its rendered payload must
first pass the authenticated Keyverse directory preflight described below.

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

## Partner OIDC apply pattern

Render `oidc-idp-partner.json` and use the same private-file, exact-200
preflight, `ready_to_apply=true`, and `PUT` sequence above with
`ALIAS="partner-oidc"`. The template pins issuer, authorization, token,
JWKS, and optional UserInfo endpoints explicitly; runtime discovery import
is not accepted. Every network endpoint is HTTPS, token signatures and JWKS
retrieval are enabled, PKCE is fixed to `S256`, and `openid` is mandatory.
Keep `trust_email=false` until the upstream verification and claim-mapping
contract has been independently reviewed. `oidc-rp-client.json` is a
different artifact: it registers Keyverse as an RP and is applied directly
to Keycloak Admin REST rather than the Keyverse federation API.

## LDAP and Active Directory preflight pattern

`ldap-source.json` is a private Keycloak component payload, not a Keyverse
identity-provider registration. Render it from KV, submit the rendered private
file to `POST /federation/user-directories:validate`, require exact HTTP 200 and
`ready_to_apply=true`, and then send the **original private file** to Keycloak.
Never apply the preflight response because `bindDn` and `bindCredential` are
redacted in that response.

```bash
set -euo pipefail
KEYVERSE_ADMIN="https://keyverse-admin.example"
KEYCLOAK_ADMIN="https://keycloak-admin.internal"
REALM="cwl"
PAYLOAD="$(mktemp)"
PREFLIGHT_RESPONSE="$(mktemp)"
KEYVERSE_AUTH_CONFIG=""
KEYCLOAK_AUTH_CONFIG=""
cleanup() {
  rm -f "$PAYLOAD" "$PREFLIGHT_RESPONSE"
  [ -z "${KEYVERSE_AUTH_CONFIG:-}" ] || rm -f "$KEYVERSE_AUTH_CONFIG"
  [ -z "${KEYCLOAK_AUTH_CONFIG:-}" ] || rm -f "$KEYCLOAK_AUTH_CONFIG"
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$PREFLIGHT_RESPONSE"

XTRACE_WAS_ON=0
case $- in
  *x*) XTRACE_WAS_ON=1; set +x ;;
esac
KEYVERSE_TOKEN="$(kv get secret/keyverse/operator-api-token)"
KEYCLOAK_TOKEN="$(keycloak-admin-token)"
KEYVERSE_AUTH_CONFIG="$(mktemp)"
KEYCLOAK_AUTH_CONFIG="$(mktemp)"
chmod 0600 "$KEYVERSE_AUTH_CONFIG" "$KEYCLOAK_AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$KEYVERSE_TOKEN" \
  >"$KEYVERSE_AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$KEYCLOAK_TOKEN" \
  >"$KEYCLOAK_AUTH_CONFIG"
unset KEYVERSE_TOKEN KEYCLOAK_TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

render deploy/templates/ldap-source.json >"$PAYLOAD"

PREFLIGHT_STATUS="$(
  curl --config "$KEYVERSE_AUTH_CONFIG" \
    --silent \
    --show-error \
    --max-redirs 0 \
    --output "$PREFLIGHT_RESPONSE" \
    --write-out '%{http_code}' \
    --header "Content-Type: application/json" \
    --data-binary @"$PAYLOAD" \
    "$KEYVERSE_ADMIN/federation/user-directories:validate"
)"
if [ "$PREFLIGHT_STATUS" != "200" ]; then
  printf 'LDAP preflight returned HTTP %s\n' "$PREFLIGHT_STATUS" >&2
  cat "$PREFLIGHT_RESPONSE" >&2
  exit 1
fi
python3 - "$PREFLIGHT_RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
raise SystemExit(0 if response.get("ready_to_apply") is True else 1)
PY

curl --config "$KEYCLOAK_AUTH_CONFIG" \
  --fail-with-body \
  --silent \
  --show-error \
  --max-redirs 0 \
  --request POST \
  --header "Content-Type: application/json" \
  --data-binary @"$PAYLOAD" \
  "$KEYCLOAK_ADMIN/admin/realms/$REALM/components"
```

The first LDAP profile is intentionally conservative:

- all directory locations use `ldaps://`;
- `editMode=READ_ONLY`;
- `syncRegistrations=false`;
- `trustEmail=false`;
- `allowKerberosAuthentication=false`;
- `useTruststoreSpi=always`;
- connection and read timeouts are bounded;
- distinguished names and LDAP schema identifiers are parsed locally;
- no custom LDAP search filter is accepted.

Preflight performs no DNS lookup, socket connection, bind, search, KV write, or
Keycloak call. It cannot prove server reachability, TLS certificate validity,
DNS behavior, directory schema, credential validity, or replication topology.
The deployment controller and egress layer retain those responsibilities.

## Auto-linking policy

`trust_email: true` makes an SAML/OIDC email assertion eligible for account
linking only when the upstream provider's assertion is trusted as verified.
The account-unification service retains the stricter invariant: it never links
or merges accounts when the only common signal is an unverified email. LDAP
preflight fixes `trustEmail=false`; a future verified-directory-email profile
requires a separately reviewed attribute and lifecycle contract. See
[`../../docs/merge-unification-flow.md`](../../docs/merge-unification-flow.md).
