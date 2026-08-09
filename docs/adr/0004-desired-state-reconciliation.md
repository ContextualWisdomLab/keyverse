# ADR-0004: Use side-effect-free preflight and re-observed desired-state reconciliation

**Status:** Accepted  
**Date:** 2026-08-09

Federation, directory, and relying-party onboarding separate deterministic local preflight from external apply. Where Keyverse owns desired state, intent is persisted before remote mutation, duplicate remote matches fail closed, and a canonical apply receipt is written only after exact live re-observation. Delete uses remote-first ordering where local-first deletion could create false success. Preflight success never means external login/bind/provisioning success.