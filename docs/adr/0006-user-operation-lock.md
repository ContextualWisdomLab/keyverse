# ADR-0006: Share one user-operation lock across merge and SCIM replacement

**Status:** Accepted  
**Date:** 2026-08-09

Account merge/link operations and SCIM user replacement can target the same Keycloak user and must not race through independent locks. Keyverse uses one cross-process user-operation lock boundary so identity lifecycle changes serialize consistently, preserve tombstone/survivor invariants, and can be retried/recovered from observed durable state.