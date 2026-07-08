#!/usr/bin/env bash
# Readiness probe for the cwl-idp stack. Exit 0 only when both the IdP engine
# and the account-unification admin service report healthy. Usable as a
# standalone gate in CI, a k8s exec probe, or a manual bring-up check.
#
#   deploy/scripts/healthz.sh            # uses defaults below
#   IDP_BASE=https://idp.example deploy/scripts/healthz.sh
set -euo pipefail

IDP_BASE="${IDP_BASE:-http://localhost:8080}"
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
# ZITADEL debug readiness endpoint (200 when serving).
check "idp-engine" "${IDP_BASE}/debug/healthz" || rc=1
# account-unification service readiness.
check "account-unification" "${UNIFICATION_BASE}/healthz" || rc=1

if [ "${rc}" -eq 0 ]; then
  echo "READY: cwl-idp is up."
else
  echo "NOT READY: one or more components failed." >&2
fi
exit "${rc}"
