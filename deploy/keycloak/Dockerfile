FROM quay.io/keycloak/keycloak:26.3.2@sha256:98fab020a3a490aba0978f237e2a06cd0ea42bf149c6cf10f11c0aaf27728ff2

# Keycloak directory import recognizes <realm>-realm.json at container start.
COPY cwl-realm.json /opt/keycloak/data/import/cwl-realm.json
COPY lineageweave-user-profile.json /opt/keycloak/lineageweave-user-profile.json
COPY --chmod=755 reconcile-lineageweave-user-profile.sh /opt/keycloak/reconcile-lineageweave-user-profile.sh
USER 1000
