#!/bin/sh
# Root bootstrap adapter for the upstream Keycloak image.
#
# Keycloak natively consumes these bootstrap values from its process environment.
# The deployment contract therefore mounts supervisor/KMS-materialized files and
# converts them only in this final process boundary. This is not a general CWL
# application-secret path and is never a dotenv fallback.
set -eu
umask 077

read_required_secret() {
    secret_path="$1"
    if [ ! -f "$secret_path" ] || [ ! -r "$secret_path" ]; then
        exit 78
    fi
    secret_value=""
    IFS= read -r secret_value < "$secret_path" || [ -n "$secret_value" ] || exit 78
    if [ -z "$secret_value" ]; then
        exit 78
    fi
}

read_required_secret /run/secrets/idp_database_password
export KC_DB_PASSWORD="$secret_value"
unset secret_value

read_required_secret /run/secrets/idp_bootstrap_admin_username
export KC_BOOTSTRAP_ADMIN_USERNAME="$secret_value"
unset secret_value

read_required_secret /run/secrets/idp_bootstrap_admin_password
export KC_BOOTSTRAP_ADMIN_PASSWORD="$secret_value"
unset secret_value secret_path

exec /opt/keycloak/bin/kc.sh "$@"
