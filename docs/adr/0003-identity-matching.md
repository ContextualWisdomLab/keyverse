# ADR-0003: Use exact external subject, then verified email, then explicit link

**Status:** Accepted  
**Date:** 2026-08-09

Account matching precedence is exact `(identity_provider, subject)`, then verified email under policy, then explicit operator link. Unverified email never authorizes automatic linking or merge. Merged duplicate accounts remain disabled tombstones with survivor lineage. This decision is shared by account unification, federation, and SCIM so one path cannot weaken another's identity evidence.