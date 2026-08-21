#!/usr/bin/env bash
# Reconcile the closed LineageWeave account-attribute profile after realm import.
set -euo pipefail
umask 077

REALM="${KC_REALM:-cwl}"
KC_SERVER="${KC_SERVER:-http://idp_engine:8080}"
ADMIN_USER="${KC_BOOTSTRAP_ADMIN_USERNAME:?bootstrap admin username is required}"
ADMIN_PASS="${KC_BOOTSTRAP_ADMIN_PASSWORD:?bootstrap admin password is required}"
KCADM_HOME="$(mktemp -d)"
cleanup() {
  rm -rf "${KCADM_HOME}"
  unset ADMIN_PASS KC_CLI_PASSWORD KC_BOOTSTRAP_ADMIN_PASSWORD
}
trap cleanup EXIT
kcadm() {
  HOME="${KCADM_HOME}" /opt/keycloak/bin/kcadm.sh "$@"
}

for attempt in $(seq 1 30); do
  if KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm config credentials \
    --server "${KC_SERVER}" --realm master --user "${ADMIN_USER}"; then
    break
  fi
  if [[ "${attempt}" -eq 30 ]]; then
    echo "profile bootstrap failed: Keycloak admin login did not become ready" >&2
    exit 1
  fi
  sleep 1
done
unset ADMIN_PASS KC_BOOTSTRAP_ADMIN_PASSWORD

kcadm update "realms/${REALM}/users/profile" \
  -f /opt/keycloak/lineageweave-user-profile.json
profile="$(kcadm get "realms/${REALM}/users/profile")"
for attribute in org workspace; do
  if ! printf '%s' "${profile}" \
    | grep -Eq '"name"[[:space:]]*:[[:space:]]*"'"${attribute}"'"'; then
    echo "profile bootstrap failed: account attribute ${attribute} is missing" >&2
    exit 1
  fi
done
# Keycloak 26.3.2 represents the closed unmanaged-attribute policy as null,
# which is omitted from the Admin API JSON; DISABLED is not an accepted enum.
if printf '%s' "${profile}" | grep -Eq '"unmanagedAttributePolicy"'; then
  echo "profile bootstrap failed: unmanaged attributes must stay disabled" >&2
  exit 1
fi
