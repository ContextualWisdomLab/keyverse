#!/usr/bin/env bash
# cwl-idp — Keycloak post-import bootstrap (config-as-code, secrets from KV).
#
# The realm SHAPE lives in realm-cwl.json and is imported at container start.
# This script patches the pieces that must NOT be committed (secrets, env URLs)
# by reading them from the KV store and applying them with Keycloak's admin CLI
# (`kcadm.sh`, shipped in the Keycloak image, Apache-2.0). Run it once after the
# realm is imported and Keycloak is READY.
#
#   deploy/keycloak/kcadm-bootstrap.sh
#
# Requires: kcadm.sh on PATH (or run inside the keycloak container), and a `kv`
# helper that reads your platform secret manager. Nothing here echoes secrets.
set -euo pipefail

REALM="${KC_REALM:-cwl}"
KC_SERVER="${KC_SERVER:-http://localhost:8080}"
# Bootstrap transport only: the admin credentials come from KV, used once to
# obtain an admin session, then discarded.
ADMIN_USER="$(kv get secret/idp/bootstrap-admin-username)"
ADMIN_PASS="$(kv get secret/idp/bootstrap-admin-password)"

# Do NOT pass the admin password on the kcadm.sh command line: argv is visible
# to any same-host process via /proc/<pid>/cmdline. Obtain a short-lived admin
# token by handing the password to curl through a restricted temp file
# (--data-urlencode "@file", never argv), then configure kcadm with that
# bearer token. The reusable password never appears in any process's argv.
_pass_file="$(mktemp)"
chmod 600 "${_pass_file}"
_kcadm_token=""
cleanup() {
  rm -f "${_pass_file}"
  unset ADMIN_PASS _kcadm_token
}
trap cleanup EXIT
printf '%s' "${ADMIN_PASS}" > "${_pass_file}"
unset ADMIN_PASS

_kcadm_token="$(curl -sf \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=admin-cli" \
  --data-urlencode "username=${ADMIN_USER}" \
  --data-urlencode "password@${_pass_file}" \
  "${KC_SERVER}/realms/master/protocol/openid-connect/token" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
rm -f "${_pass_file}"
if [ -z "${_kcadm_token}" ]; then
  echo "ERROR: failed to obtain a bootstrap admin token" >&2
  exit 1
fi

kcadm.sh config credentials \
  --server "${KC_SERVER}" --realm master \
  --token "${_kcadm_token}"

# NOTE: external federation (the employer ADFS SAML IdP, corporate LDAP/AD)
# is deliberately NOT part of this bootstrap. Those are deployment data, not
# realm code: register them at runtime through the account-unification
# service's /federation/identity-providers API, which persists the desired
# state in the KV/DB store and converges Keycloak via the Admin REST API.
# See deploy/templates/ for ready-made request payloads.

echo "==> patching account-unification-svc client secret from KV"
SVC_CLIENT_UUID="$(kcadm.sh get clients -r "${REALM}" \
  --query 'clientId=account-unification-svc' --fields id --format csv --noquotes | head -n1)"
kcadm.sh update "clients/${SVC_CLIENT_UUID}" -r "${REALM}" \
  -s "secret=$(kv get secret/idp/account-unification-client-secret)"

echo "==> granting realm-management roles to the service account"
# view-users/manage-users: account unification + SCIM shim.
# manage-identity-providers: the runtime federation registry API.
SVC_SA_USER_ID="$(kcadm.sh get "clients/${SVC_CLIENT_UUID}/service-account-user" \
  -r "${REALM}" --fields id --format csv --noquotes)"
REALM_MGMT_UUID="$(kcadm.sh get clients -r "${REALM}" \
  --query 'clientId=realm-management' --fields id --format csv --noquotes | head -n1)"
kcadm.sh add-roles -r "${REALM}" \
  --uid "${SVC_SA_USER_ID}" \
  --cclientid realm-management \
  --rolename view-users --rolename manage-users \
  --rolename manage-identity-providers

echo "==> mirroring the service client secret into KV for the admin service"
# The account-unification service reads keycloak_client_secret from KV; keep it
# in sync so both sides use the same credential.
kv put secret/idp/account-unification-client-secret \
  "$(kcadm.sh get "clients/${SVC_CLIENT_UUID}/client-secret" -r "${REALM}" \
       --fields value --format csv --noquotes)"

echo "OK: kcadm bootstrap complete for realm '${REALM}'."
