# ADR-0005: Separate portable configuration from deployment-private values

**Status:** Accepted  
**Date:** 2026-08-09

Portable realm configuration and ordinary desired-state records contain only the fields needed for reproducible identity policy. Deployment-specific confidential values remain owned by the deployment controller and its approved configuration store. Public repository artifacts, ordinary responses, and routine logs do not copy those private values. This keeps the portable realm reusable across tenants and supports controlled rotation and rollback.