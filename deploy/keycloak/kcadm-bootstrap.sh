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

kcadm.sh config credentials \
  --server "${KC_SERVER}" --realm master \
  --user "${ADMIN_USER}" --password "${ADMIN_PASS}"

echo "==> patching employer-adfs SAML metadata URL from KV"
ADFS_METADATA_URL="$(kv get config/idp/employer-adfs-metadata-url)"
IDP_ID="$(kcadm.sh get "identity-provider/instances/employer-adfs" -r "${REALM}" --fields internalId --format csv --noquotes)"
kcadm.sh update "identity-provider/instances/employer-adfs" -r "${REALM}" \
  -s "config.metadataDescriptorUrl=${ADFS_METADATA_URL}" \
  -s "config.singleSignOnServiceUrl=${ADFS_METADATA_URL}" \
  -s "config.useMetadataDescriptorUrl=true"

echo "==> patching corp-ldap bind credential + connection from KV"
LDAP_COMPONENT_ID="$(kcadm.sh get components -r "${REALM}" \
  --query 'name=corp-ldap' --fields id --format csv --noquotes | head -n1)"
kcadm.sh update "components/${LDAP_COMPONENT_ID}" -r "${REALM}" \
  -s "config.connectionUrl=[\"$(kv get config/idp/ldap-connection-url)\"]" \
  -s "config.usersDn=[\"$(kv get config/idp/ldap-users-dn)\"]" \
  -s "config.bindDn=[\"$(kv get secret/idp/ldap-bind-dn)\"]" \
  -s "config.bindCredential=[\"$(kv get secret/idp/ldap-bind-password)\"]"

echo "==> patching account-unification-svc client secret from KV"
SVC_CLIENT_UUID="$(kcadm.sh get clients -r "${REALM}" \
  --query 'clientId=account-unification-svc' --fields id --format csv --noquotes | head -n1)"
kcadm.sh update "clients/${SVC_CLIENT_UUID}" -r "${REALM}" \
  -s "secret=$(kv get secret/idp/account-unification-client-secret)"

echo "==> granting realm-management view-users + manage-users to the service account"
SVC_SA_USER_ID="$(kcadm.sh get "clients/${SVC_CLIENT_UUID}/service-account-user" \
  -r "${REALM}" --fields id --format csv --noquotes)"
REALM_MGMT_UUID="$(kcadm.sh get clients -r "${REALM}" \
  --query 'clientId=realm-management' --fields id --format csv --noquotes | head -n1)"
kcadm.sh add-roles -r "${REALM}" \
  --uid "${SVC_SA_USER_ID}" \
  --cclientid realm-management \
  --rolename view-users --rolename manage-users

echo "==> mirroring the service client secret into KV for the admin service"
# The account-unification service reads keycloak_client_secret from KV; keep it
# in sync so both sides use the same credential.
kv put secret/idp/account-unification-client-secret \
  "$(kcadm.sh get "clients/${SVC_CLIENT_UUID}/client-secret" -r "${REALM}" \
       --fields value --format csv --noquotes)"

echo "OK: kcadm bootstrap complete for realm '${REALM}'."
