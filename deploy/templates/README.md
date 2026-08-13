# Federation and client registration templates

These files are deployment inputs. They contain no reusable credentials, and
all `{{placeholders}}` must be resolved from the platform KV before use.

| Template | Owner | Direction | Preflight | Apply endpoint |
| --- | --- | --- | --- | --- |
| `saml-idp-employer-adfs.json` | Keyverse desired-state API | external IdP → Keyverse | `POST /federation/identity-providers:validate` | `PUT /federation/identity-providers/employer-adfs` |
| `oidc-idp-partner.json` | Keyverse desired-state API | external OIDC IdP → Keyverse | `POST /federation/identity-providers:validate` | `PUT /federation/identity-providers/partner-oidc` |
| `ldap-source.json` | Keycloak component contract | external directory → Keycloak | `POST /federation/user-directories:validate` | `POST /admin/realms/{realm}/components` |
| `oidc-rp-client.json` | Keyverse RP desired-state API | Keyverse → RP | `POST /clients/relying-parties:validate` | `PUT /clients/relying-parties/{client_id}` |
| `oidc-rp-naruon.json` | Keyverse RP desired-state API | Keyverse → Naruon | `POST /clients/relying-parties:validate` | `PUT /clients/relying-parties/naruon-web` |
| `oidc-rp-lineageweave.json` | Keyverse RP desired-state API | Keyverse → LineageWeave | `POST /clients/relying-parties:validate` | `PUT /clients/relying-parties/lineageweave-web` |

The portable realm contains no employer-specific federation. External SAML and
OIDC providers are customer or deployment data stored in the Keyverse KV/DB
desired-state registry and reconciled into Keycloak. OIDC relying-party clients
are likewise reconciled through Keyverse desired state rather than applied
straight from a public deployment path. LDAP is still applied as a Keycloak
user-storage component in this release, but its rendered payload must first pass
the authenticated Keyverse directory preflight described below.

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
contract has been independently reviewed. The OIDC RP templates are different
artifacts: they register ecosystem applications as relying parties of Keyverse.
Their rendered payloads pass `POST /clients/relying-parties:validate` and are
then reconciled through the Keyverse RP desired-state `PUT`. See
[`../../docs/rp-onboarding.md`](../../docs/rp-onboarding.md).

## OIDC relying-party desired-state pattern

`oidc-rp-client.json` is the generic closed, secret-free Keycloak client
representation. Render its placeholders into a private file, call the
authenticated Keyverse `POST /clients/relying-parties:validate` route, require
exact HTTP 200 and `ready_to_apply=true`, then send the **same original rendered
file** to `PUT /clients/relying-parties/{client_id}`. Require
`convergence_state=in_sync` and `last_apply_receipt_matches=true` after Keyverse
re-observes the live client. Do not apply the representation directly from the
public deployment path to Keycloak Admin REST.

The base profile requires authorization code plus PKCE `S256`, exact HTTPS
redirects and origins, public/confidential authentication consistency, a bounded
access-token lifetime, backchannel logout, and exactly the portable `basic`,
`profile`, and `email` scopes. Wildcards, `+`, queries, fragments, userinfo,
encoded path delimiters, unresolved placeholders, credential fields, and broad
scope expansion fail closed. Preflight performs no client creation, secret
generation, KV write, DNS lookup, HTTP request, or Keycloak call.

### Naruon runtime mapper profile

`oidc-rp-naruon.json` is the reviewed public `naruon-web` runtime artifact. It
adds six deployment placeholders: exact redirect, web-origin, and post-logout
URIs plus bounded `role`, `org`, and `workspace` routing values. The claim values
are visible product routing/authorization data and must not carry credentials,
bearer material, personal secrets, or unreviewed tenant data.

The template carries this exact mapper order:

1. `keyverse-audience` using `oidc-audience-mapper`, with
   `included.client.audience=naruon-web`;
2. `keyverse-claim-role`;
3. `keyverse-claim-org`;
4. `keyverse-claim-workspace`.

The three claim entries use only `oidc-hardcoded-claim-mapper`. The closed policy
rejects scripts, user attributes, groups, regex, arbitrary claim names, unknown
mapper types, extra nested fields, and credential material. Keycloak-generated
mapper IDs and vendor return ordering may be normalized for observation, but an
unknown, malformed, duplicate, or semantically changed live mapper is drift.

Render → preflight → Keyverse desired-state PUT → exact `in_sync` receipt is the
configuration path. It is not authentication or authorization proof. Before
routing users, run controlled authorization-code/PKCE acceptance and verify that
the downstream boundary validates token signature, issuer, expiry, the reviewed
`naruon-web` audience, and expected `role`, `org`, and `workspace` semantics.

### LineageWeave account-derived mapper profile

`oidc-rp-lineageweave.json` is the ADR-0009 confidential `lineageweave-web`
artifact. It renders only the exact HTTPS redirect, origin, and post-logout URI.
The fixed mapper order projects a self-pinned audience, client roles from
`lineageweave-web`, and the exact `org` and `workspace` Keyverse account
attributes. The template never contains a role value, company/PU value, or
client secret.

Before apply, provision a real account with both attributes and a recognized
client role through the approved Keyverse identity lifecycle. Preflight and
reconciliation validate issuer-side metadata only. Record a real
authorization-code/PKCE login and downstream tenant/resource ABAC, role
downgrade, logout, and rollback evidence before enabling production routing.

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
