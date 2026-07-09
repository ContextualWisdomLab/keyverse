#!/usr/bin/env bash
# Readiness probe for the cwl-idp stack. Exit 0 only when both the IdP engine
# (Keycloak) and the account-unification admin service report healthy. Usable as
# a standalone gate in CI, a k8s exec probe, or a manual bring-up check.
#
#   deploy/scripts/healthz.sh            # uses defaults below
#   IDP_BASE=https://idp.example deploy/scripts/healthz.sh
#
# Keycloak's dedicated /health endpoints live on the management port (9000) and
# are typically not published to the host, so the public-port readiness signal
# here is the realm's OIDC discovery document (200 once the realm is serving).
# When the management port IS reachable, set KC_MGMT_BASE to probe /health/ready.
set -euo pipefail

IDP_BASE="${IDP_BASE:-http://localhost:8080}"
IDP_REALM="${IDP_REALM:-cwl}"
KC_MGMT_BASE="${KC_MGMT_BASE:-}"
UNIFICATION_BASE="${UNIFICATION_BASE:-http://localhost:8099}"
TIMEOUT="${TIMEOUT:-5}"

check() {
  local name="$1" url="$2"
  if curl -fsS --max-time "${TIMEOUT}" "${url}" >/dev/null 2>&1; then
    echo "ok    ${name} (${url})"
    return 0
  fi
  echo "FAIL  ${name} (${url})"
  return 1
}

rc=0
if [ -n "${KC_MGMT_BASE}" ]; then
  # Keycloak management health endpoint (200 + status UP when ready).
  check "idp-engine" "${KC_MGMT_BASE}/health/ready" || rc=1
else
  # Public-port readiness: realm OIDC discovery document.
  check "idp-engine" "${IDP_BASE}/realms/${IDP_REALM}/.well-known/openid-configuration" || rc=1
fi
# account-unification service readiness.
check "account-unification" "${UNIFICATION_BASE}/healthz" || rc=1

if [ "${rc}" -eq 0 ]; then
  echo "READY: cwl-idp is up."
else
  echo "NOT READY: one or more components failed." >&2
fi
exit "${rc}"
