# ADR-0001: Keep Keycloak and Keyverse as the ecosystem identity hub

**Status:** Accepted  
**Date:** 2026-08-09

Keyverse uses Keycloak as the standards-based identity engine and adds CWL-owned control services around it. Employer/customer ADFS, LDAP/AD, external OIDC, and HR/IGA are federation/provisioning sources rather than peer hubs. CWL relying parties trust the Keyverse/Keycloak boundary instead of administering those external systems directly. Customer-specific federation remains deployment data, not portable realm code.

## Compose and Helm realm-import invariant

Keycloak directory import discovers a realm only when its target is named
`<realm>-realm.json`. The portable file is therefore `cwl-realm.json`. Compose
packages that file in a derivative of the pinned Keycloak image instead of
bind-mounting a leaf below `/opt/keycloak/data`; Docker Desktop can present such
a leaf mount as a directory and make the import fail. Helm maps its ConfigMap
key to the same filename. A container health check alone is insufficient: it can
be healthy while the intended realm was never imported. Deployment acceptance
therefore verifies the realm discovery endpoint, and a static deployment contract
locks the filename mapping in both packaging paths.
