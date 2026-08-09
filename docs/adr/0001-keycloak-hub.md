# ADR-0001: Keep Keycloak and Keyverse as the ecosystem identity hub

**Status:** Accepted  
**Date:** 2026-08-09

Keyverse uses Keycloak as the standards-based identity engine and adds CWL-owned control services around it. Employer/customer ADFS, LDAP/AD, external OIDC, and HR/IGA are federation/provisioning sources rather than peer hubs. CWL relying parties trust the Keyverse/Keycloak boundary instead of administering those external systems directly. Customer-specific federation remains deployment data, not portable realm code.