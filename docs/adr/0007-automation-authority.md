# ADR-0007: Separate autonomous development from review, merge, and release authority

**Status:** Accepted  
**Date:** 2026-08-09

Autonomous development may inspect exact repository state, produce a bounded patch, and submit ordinary reviewable work after independent verification. It cannot create its own qualifying approval, bypass branch protection, merge protected main, tag, or publish a release. Model-provider credentials remain separate from reviewer, publication, and release credentials. PR #74 refines the hourly implementation while preserving this authority boundary.