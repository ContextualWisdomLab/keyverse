# Keyvault foundation evidence

## Question

What is the smallest safe foundation for Keyverse to hold service secrets
without weakening the identity and authorization boundaries of consuming
products?

## Decision record

The implementation stores encrypted values and append-only audit events in one
transaction boundary. The administrator API can mutate and inspect metadata but
cannot retrieve plaintext. Consumer reads remain unimplemented until a signed
workload identity can be restricted to one namespace and explicit read scope.
This follows least privilege and avoids treating a shared administrator bearer
credential as service identity.

PBKDF2-HMAC-SHA256 derives the Fernet key with a work factor. The earlier bare
SHA-256 branch revision never reached protected main, so admitting a permanent
weak legacy fallback would add attack surface without deployed data to recover.

## References

National Institute of Standards and Technology. (2020). *Recommendation for
key management: Part 1—General* (NIST SP 800-57 Part 1 Rev. 5).
https://doi.org/10.6028/NIST.SP.800-57pt1r5

Open Worldwide Application Security Project. (2024). *Password storage cheat
sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

Red Hat. (2026). *Keycloak server administration guide*.
https://www.keycloak.org/docs/latest/server_admin/
