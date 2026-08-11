# ADR-0002: Keep ecosystem-local accounts passwordless-first

**Status:** Accepted  
**Date:** 2026-08-09

The portable local browser flow uses WebAuthn/passkeys and does not include an ordinary password authenticator. Registration creates no password and uses a controlled enrollment action. External federation may rely on its upstream authentication policy, but Keyverse does not silently add a local password fallback for ecosystem-local accounts. Changing this boundary requires explicit security/product review and migration evidence.