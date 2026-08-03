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
# Bootstrap transport only: the admin credentials come from KV, are used once
# to create an Admin CLI session, and are then discarded.
ADMIN_USER="$(kv get secret/idp/bootstrap-admin-username)"
ADMIN_PASS="$(kv get secret/idp/bootstrap-admin-password)"

# Use Keycloak's documented sensitive-option environment variable rather than
# placing the reusable password in process arguments. Keep the resulting access
# and refresh tokens in a private, short-lived HOME so no Admin CLI session
# survives this bootstrap process. HOME is scoped only to kcadm invocations;
# the platform `kv` helper keeps its original credential/configuration home.
_kcadm_home="$(mktemp -d)"
chmod 700 "${_kcadm_home}"
cleanup() {
  rm -rf "${_kcadm_home}"
  unset ADMIN_PASS
}
trap cleanup EXIT
kcadm() {
  HOME="${_kcadm_home}" kcadm.sh "$@"
}

KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm config credentials \
  --server "${KC_SERVER}" --realm master \
  --user "${ADMIN_USER}"
unset ADMIN_PASS

# NOTE: external federation (the employer ADFS SAML IdP, corporate LDAP/AD)
# is deliberately NOT part of this bootstrap. Those are deployment data, not
# realm code: register them at runtime through the account-unification
# service's /federation/identity-providers API, which persists the desired
# state in the KV/DB store and converges Keycloak via the Admin REST API.
# See deploy/templates/ for ready-made request payloads.

echo "==> patching account-unification-svc client secret from KV"
SVC_CLIENT_UUID="$(kcadm get clients -r "${REALM}" \
  --query 'clientId=account-unification-svc' --fields id --format csv --noquotes | head -n1)"
kcadm update "clients/${SVC_CLIENT_UUID}" -r "${REALM}" \
  -s "secret=$(kv get secret/idp/account-unification-client-secret)"

echo "==> granting realm-management roles to the service account"
# view-users/manage-users: account unification + SCIM shim.
# manage-identity-providers: the runtime federation registry API.
SVC_SA_USER_ID="$(kcadm get "clients/${SVC_CLIENT_UUID}/service-account-user" \
  -r "${REALM}" --fields id --format csv --noquotes)"
REALM_MGMT_UUID="$(kcadm get clients -r "${REALM}" \
  --query 'clientId=realm-management' --fields id --format csv --noquotes | head -n1)"
kcadm add-roles -r "${REALM}" \
  --uid "${SVC_SA_USER_ID}" \
  --cclientid realm-management \
  --rolename view-users --rolename manage-users \
  --rolename manage-identity-providers

echo "==> scoping the granted roles into the service-account access token"
# The client is fullScopeAllowed:false (least privilege), so a granted role
# only reaches the token when it is ALSO in the client's scope mappings AND a
# client-role protocol mapper emits resource_access. Without both, every
# Admin REST call from the service fails 403 on a fresh bring-up.
REALM_MGMT_ROLE_JSON="$(kcadm get "clients/${REALM_MGMT_UUID}/roles" -r "${REALM}" \
  --fields id,name \
  | python3 -c 'import json,sys; roles=json.load(sys.stdin); print(json.dumps([r for r in roles if r["name"] in ("view-users","manage-users","manage-identity-providers")]))')"
kcadm create "clients/${SVC_CLIENT_UUID}/scope-mappings/clients/${REALM_MGMT_UUID}" \
  -r "${REALM}" -b "${REALM_MGMT_ROLE_JSON}"
kcadm create "clients/${SVC_CLIENT_UUID}/protocol-mappers/models" -r "${REALM}" \
  -b '{"name":"realm-management roles","protocol":"openid-connect","protocolMapper":"oidc-usermodel-client-role-mapper","config":{"usermodel.clientRoleMapping.clientId":"realm-management","claim.name":"resource_access.realm-management.roles","multivalued":"true","jsonType.label":"String","access.token.claim":"true","id.token.claim":"false","userinfo.token.claim":"false"}}'

echo "==> mirroring the service client secret into KV for the admin service"
# The account-unification service reads keycloak_client_secret from KV; keep it
# in sync so both sides use the same credential.
kv put secret/idp/account-unification-client-secret \
  "$(kcadm get "clients/${SVC_CLIENT_UUID}/client-secret" -r "${REALM}" \
       --fields value --format csv --noquotes)"

echo "OK: kcadm bootstrap complete for realm '${REALM}'."
