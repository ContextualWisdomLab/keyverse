# LDAP and Active Directory onboarding

## Scope

This procedure renders the private LDAP component template, validates it through
Keyverse, and applies the original private payload to Keycloak Admin REST. It is
valid for standalone Keyverse, a CWL deployment controller, or a Naruon parent
module using the same network and secret boundaries.

The current increment validates configuration only. It does not connect to the
directory or persist LDAP desired state in Keyverse.

## Prerequisites

- the Keyverse operator API is reachable only through the approved WAF/admin
  path;
- the Keycloak Admin REST API is reachable only from the deployment controller;
- the directory endpoint is available through an approved egress route;
- the deployment controller can read the LDAP bind credential and Keyverse and
  Keycloak operator credentials from its secret manager;
- the LDAPS certificate chain is trusted by Keycloak's configured truststore;
- the directory service account is read-only and limited to the required user
  subtree and attributes.

## Closed first-profile policy

The preflight accepts only the following operating profile:

| Setting | Required value |
| --- | --- |
| Provider | Keycloak LDAP user-storage component |
| Transport | One or more unique `ldaps://` authorities |
| Edit mode | `READ_ONLY` |
| Import users | `true` |
| Registration sync | `false` |
| Kerberos | `false` |
| Trust email | `false` |
| Truststore SPI | `always` |
| Search scope | one-level (`1`) or subtree (`2`) |
| Connection pooling | `true` |
| Priority | `0` through `1000` |
| Connection/read timeout | `100` through `30000` milliseconds |

`trustEmail=false` is intentional. An LDAP email value is not automatically a
verified proof of mailbox control. Keyverse account linking continues to require
an exact provider subject or a separately reviewed verified-email contract.

## Render and preflight

Keep every credential and payload in a mode-0600 file. Do not use shell xtrace
while reading secrets or writing curl configuration.

```bash
set -euo pipefail
KEYVERSE_ADMIN="https://keyverse-admin.example"
PAYLOAD="$(mktemp)"
RESPONSE="$(mktemp)"
AUTH_CONFIG=""
cleanup() {
  rm -f "$PAYLOAD" "$RESPONSE"
  [ -z "${AUTH_CONFIG:-}" ] || rm -f "$AUTH_CONFIG"
}
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$RESPONSE"

XTRACE_WAS_ON=0
case $- in
  *x*) XTRACE_WAS_ON=1; set +x ;;
esac
TOKEN="$(kv get secret/keyverse/operator-api-token)"
AUTH_CONFIG="$(mktemp)"
chmod 0600 "$AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

render deploy/templates/ldap-source.json >"$PAYLOAD"

STATUS="$(
  curl --config "$AUTH_CONFIG" \
    --silent \
    --show-error \
    --max-redirs 0 \
    --output "$RESPONSE" \
    --write-out '%{http_code}' \
    --header "Content-Type: application/json" \
    --data-binary @"$PAYLOAD" \
    "$KEYVERSE_ADMIN/federation/user-directories:validate"
)"
if [ "$STATUS" != "200" ]; then
  printf 'directory preflight returned HTTP %s\n' "$STATUS" >&2
  cat "$RESPONSE" >&2
  exit 1
fi

python3 - "$RESPONSE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
if response.get("ready_to_apply") is not True:
    raise SystemExit("preflight did not confirm ready_to_apply=true")
registration = response.get("registration")
if not isinstance(registration, dict):
    raise SystemExit("preflight response omitted registration")
config = registration.get("config")
if not isinstance(config, dict):
    raise SystemExit("preflight response omitted config")
if config.get("bindCredential") != ["<redacted>"]:
    raise SystemExit("preflight response did not redact bindCredential")
if config.get("bindDn") != ["<redacted>"]:
    raise SystemExit("preflight response did not redact bindDn")
PY
```

The response is a readiness receipt. It is not an apply payload because private
values are redacted.

## Apply the original private payload

Acquire a short-lived Keycloak Admin token through the deployment controller's
existing secret-safe flow and place it in a second private curl configuration.
Then post the original `$PAYLOAD` file:

```bash
set -euo pipefail
KEYCLOAK_ADMIN="https://keycloak-admin.internal"
REALM="cwl"
KEYCLOAK_AUTH_CONFIG="$(mktemp)"
trap 'rm -f "$KEYCLOAK_AUTH_CONFIG"' EXIT
chmod 0600 "$KEYCLOAK_AUTH_CONFIG"

XTRACE_WAS_ON=0
case $- in
  *x*) XTRACE_WAS_ON=1; set +x ;;
esac
TOKEN="$(keycloak-admin-token)"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" \
  >"$KEYCLOAK_AUTH_CONFIG"
unset TOKEN
if [ "$XTRACE_WAS_ON" -eq 1 ]; then
  set -x
fi

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

A production deployment should use its existing idempotent component controller
rather than creating duplicates blindly. Full Keyverse LDAP desired-state CRUD
and reconciliation remain a follow-up.

## Post-apply verification

Perform verification from a restricted operations environment. Do not place the
bind credential in command arguments or logs.

1. Read the component through Keycloak Admin REST and confirm the component name,
   provider, enabled state, edit mode, connection URL, base DN, attributes,
   timeouts, and trust policy.
2. Confirm the rendered bind credential is not returned by operator tooling.
3. Use Keycloak's directory connection and authentication tests through the
   administrative interface or a reviewed automation path.
4. Perform one user lookup inside the configured base DN and one negative lookup
   outside it.
5. Confirm an imported directory user can authenticate only through the intended
   directory/passkey policy and does not gain a local password path.
6. Confirm an LDAP mail value alone does not trigger account linking.
7. Record component ID, deployment revision, template digest, Keycloak version,
   directory endpoint identifiers, and verification result in the change record.

## Failure and rollback

### Preflight HTTP 400

Do not apply. Correct only the named field in the private render source, render a
new file, and run preflight again. Error responses deliberately omit the rejected
value.

### Keycloak apply failure

Retain the private rendered source and bounded error receipt in the protected
change system. Do not paste them into an issue or PR. Resolve permissions,
network, truststore, or Keycloak validation, then repeat preflight before retrying
apply.

### Login or synchronization regression

Disable or remove the newly created component through the private Keycloak Admin
REST path, verify normal login recovery, preserve audit evidence, and investigate
before re-enabling. Do not switch to `WRITABLE`, `UNSYNCED`, cleartext LDAP,
trusted email, or Kerberos as an incident workaround.

### Secret exposure

Rotate the directory bind credential and any exposed operator token immediately,
remove the evidence from accessible logs or artifacts, review directory access
logs, and rerun the protected configuration flow with new credentials.

## What preflight does not prove

- DNS or endpoint ownership;
- TLS certificate validity, hostname match, revocation, or expiry;
- bind credential correctness;
- users DN existence;
- directory schema and matching rules;
- replication consistency;
- query performance or login SLO;
- password, Kerberos, or write-back behavior;
- successful component creation or deduplication.

Those are post-preflight deployment and operational checks.

## References

The standards interpretation and APA 7th references are recorded in
[`doctoring/ldap-directory-preflight.md`](doctoring/ldap-directory-preflight.md).
The implementation design is in
[`superpowers/specs/2026-08-05-keyverse-ldap-directory-preflight-design.md`](superpowers/specs/2026-08-05-keyverse-ldap-directory-preflight-design.md).
