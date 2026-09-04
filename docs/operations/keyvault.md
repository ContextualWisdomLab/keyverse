# Keyvault operations

Keyvault is opt-in. Configure its database path and passphrase in Keyverse's
existing private configuration store. If the passphrase is absent, every
Keyvault administrator operation fails closed as unavailable.

Administrators can list secret metadata, set or rotate a value, inspect its
audit history, and delete it. The API never returns plaintext. Use the product
form only for values being created or rotated; after submission, show presence,
last change time, and outcome. Do not echo the submitted value in UI state,
logs, screenshots, notifications, or error text.

Each set or delete and its audit event commit in one database transaction. On
failure, retry only after checking metadata and audit history. Back up and
restore the Keyvault database as one unit. A wrong passphrase fails
authentication during decryption; it is not an empty vault.

Noema and contextual-orchestrator keep their current stores until a separate
consumer PR proves all of these together: signed workload identity, one
namespace-bound read scope, denied cross-namespace access, rotation, Keyverse
outage behavior, and rollback. An administrator session is never a substitute
for workload identity.
