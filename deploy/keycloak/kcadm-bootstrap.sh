#!/usr/bin/env bash
# cwl-idp — Keycloak post-import bootstrap (config-as-code, secrets from KV).
#
# The realm SHAPE lives in realm-cwl.json and is imported at container start.
# This script patches the pieces that must NOT be committed (secrets, env URLs)
# by reading them from the KV store and applying them with Keycloak's admin CLI
# (`kcadm.sh`, shipped in the Keycloak image, Apache-2.0). Run it after the realm
# is imported and Keycloak is READY; every operation is safe to repeat.
#
# Requires: kcadm.sh on PATH (or run inside the Keycloak container), and a `kv`
# helper that reads the platform secret manager. Nothing here echoes secrets.
set -euo pipefail
umask 077

REALM="${KC_REALM:-cwl}"
KC_SERVER="${KC_SERVER:-http://localhost:8080}"
ADMIN_USER="$(kv get secret/idp/bootstrap-admin-username)"
ADMIN_PASS="$(kv get secret/idp/bootstrap-admin-password)"

# Use Keycloak's documented sensitive-option environment variable rather than
# placing the reusable password in process arguments. Scope the Admin CLI HOME
# to one private directory so its access and refresh tokens are destroyed at
# process exit while the platform `kv` helper retains its normal HOME.
_kcadm_home="$(mktemp -d)"
cleanup() {
  rm -rf "${_kcadm_home}"
  unset ADMIN_PASS SERVICE_CLIENT_SECRET
}
trap cleanup EXIT
kcadm() {
  HOME="${_kcadm_home}" kcadm.sh "$@"
}
require_nonempty() {
  local value_name="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    echo "bootstrap failed: ${value_name} was not resolved" >&2
    exit 1
  fi
}

require_nonempty "bootstrap admin username" "${ADMIN_USER}"
require_nonempty "bootstrap admin password" "${ADMIN_PASS}"
KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm config credentials \
  --server "${KC_SERVER}" --realm master \
  --user "${ADMIN_USER}"
unset ADMIN_PASS

# External federation is deliberately not part of realm bootstrap. Employer
# ADFS, LDAP-fronting brokers, and optional OIDC providers are runtime desired
# state managed by /federation/identity-providers and persisted in the KV store.

echo "==> converging account-unification-svc client secret from KV"
SVC_CLIENT_UUID="$(kcadm get clients -r "${REALM}" \
  --query 'clientId=account-unification-svc' \
  --fields id --format csv --noquotes | head -n1)"
require_nonempty "account-unification service client id" "${SVC_CLIENT_UUID}"

# Write the secret to a 0600 file through stdin. Neither the reusable secret nor
# the JSON representation appears in a child-process argument or command log.
SERVICE_CLIENT_SECRET="$(kv get secret/idp/account-unification-client-secret)"
require_nonempty "account-unification service client secret" \
  "${SERVICE_CLIENT_SECRET}"
SERVICE_SECRET_JSON="${_kcadm_home}/service-client-secret.json"
printf '%s' "${SERVICE_CLIENT_SECRET}" \
  | python3 -c 'import json,sys; json.dump({"secret": sys.stdin.read()}, sys.stdout)' \
  > "${SERVICE_SECRET_JSON}"
unset SERVICE_CLIENT_SECRET
kcadm update "clients/${SVC_CLIENT_UUID}" -r "${REALM}" \
  -f "${SERVICE_SECRET_JSON}"

echo "==> granting realm-management roles to the service account"
SVC_SA_USER_ID="$(kcadm get \
  "clients/${SVC_CLIENT_UUID}/service-account-user" -r "${REALM}" \
  --fields id --format csv --noquotes)"
REALM_MGMT_UUID="$(kcadm get clients -r "${REALM}" \
  --query 'clientId=realm-management' \
  --fields id --format csv --noquotes | head -n1)"
require_nonempty "service-account user id" "${SVC_SA_USER_ID}"
require_nonempty "realm-management client id" "${REALM_MGMT_UUID}"

kcadm add-roles -r "${REALM}" \
  --uid "${SVC_SA_USER_ID}" \
  --cclientid realm-management \
  --rolename view-users --rolename manage-users \
  --rolename manage-identity-providers

echo "==> scoping the granted roles into the service-account access token"
# fullScopeAllowed is false. The roles therefore need both scope mappings and a
# client-role protocol mapper before they appear in resource_access.
REALM_MGMT_ROLE_JSON="$(kcadm get \
  "clients/${REALM_MGMT_UUID}/roles" -r "${REALM}" --fields id,name \
  | python3 -c 'import json,sys; names={"view-users","manage-users","manage-identity-providers"}; print(json.dumps([role for role in json.load(sys.stdin) if role.get("name") in names]))')"
ROLE_COUNT="$(printf '%s' "${REALM_MGMT_ROLE_JSON}" \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
if [[ "${ROLE_COUNT}" -ne 3 ]]; then
  echo "bootstrap failed: required realm-management roles were not resolved" >&2
  exit 1
fi
kcadm create \
  "clients/${SVC_CLIENT_UUID}/scope-mappings/clients/${REALM_MGMT_UUID}" \
  -r "${REALM}" -b "${REALM_MGMT_ROLE_JSON}"

# Reconcile the mapper by name. Older non-idempotent bootstrap runs may have
# produced duplicates; update the first representation and remove the rest.
MAPPER_NAME="realm-management roles"
MAPPER_PAYLOAD='{"name":"realm-management roles","protocol":"openid-connect","protocolMapper":"oidc-usermodel-client-role-mapper","config":{"usermodel.clientRoleMapping.clientId":"realm-management","claim.name":"resource_access.realm-management.roles","multivalued":"true","jsonType.label":"String","access.token.claim":"true","id.token.claim":"false","userinfo.token.claim":"false"}}'
MAPPER_IDS="$(kcadm get \
  "clients/${SVC_CLIENT_UUID}/protocol-mappers/models" -r "${REALM}" \
  | python3 -c 'import json,sys; name=sys.argv[1]; print("\n".join(mapper["id"] for mapper in json.load(sys.stdin) if mapper.get("name") == name and mapper.get("id")))' \
      "${MAPPER_NAME}")"
MAPPER_ID="$(printf '%s\n' "${MAPPER_IDS}" | head -n1)"
if [[ -n "${MAPPER_ID}" ]]; then
  kcadm update \
    "clients/${SVC_CLIENT_UUID}/protocol-mappers/models/${MAPPER_ID}" \
    -r "${REALM}" -b "${MAPPER_PAYLOAD}"
else
  kcadm create "clients/${SVC_CLIENT_UUID}/protocol-mappers/models" \
    -r "${REALM}" -b "${MAPPER_PAYLOAD}"
fi
if [[ -n "${MAPPER_IDS}" ]]; then
  printf '%s\n' "${MAPPER_IDS}" | tail -n +2 \
    | while IFS= read -r duplicate_mapper_id; do
        if [[ -n "${duplicate_mapper_id}" ]]; then
          kcadm delete \
            "clients/${SVC_CLIENT_UUID}/protocol-mappers/models/"\
"${duplicate_mapper_id}" -r "${REALM}"
        fi
      done
fi

echo "OK: kcadm bootstrap complete for realm '${REALM}'."
