# ADR-0014: Keyverse Key Vault authority and separate secret-lifecycle context

**Status:** Proposed; foundation and bootstrap repair are unmerged PR work.
**Original date:** 2026-09-02. **Updated:** 2026-09-09.
**Owner line:** PR #129. **Organization rollout:** ContextualWisdomLab/.github#2063.

## Problem and observed implementation

The owner requested both a namespaced Key Vault and, on 2026-09-09, removal of
CWL code's dependence on `.env`. Keyverse must provide secret custody and
lifecycle without confusing identity, authorization, ordinary configuration and
product-specific credential meaning.

PR #129 at `0f10ac556a318c3c3f5ce7eab0802573ecce0c4c` adds
`app/keyvault.py`, `app/keyvault_admin.py`, encrypted SQLite values and atomic
mutation/audit records. Administrator routes expose metadata and write/delete
outcomes, not plaintext reads. The vault is opt-in; absent configuration means
unavailable, not an apparently empty vault.

The earlier ADR called this Accepted while it was still an open PR. It also
called plaintext internal configuration suitable merely because it was not
read from process environment. Both statements are corrected here: changing
transport does not establish confidentiality, and an unmerged implementation is
not accepted production evidence.

`idp_config_entries` currently stores ordinary configuration and some legacy
service credentials as text. It is not a general-purpose credential vault. In
particular, the root unlocking credential must not be stored there alongside
configuration backups. Other legacy credentials require their own controlled
migration; this bootstrap repair does not falsely claim to have removed them.

CO already exposes a `CredentialBackend` port in `credentials.py`. That is a
consumer seam, not justification to copy CO's storage implementation into
Keyverse or to give CO an administrator token. Authorization-plane PR #103 and
ADRs 0015/0016 remain separate owner work.

## Alternatives

### Retain dotenv or rename it to a plaintext KV table

Rejected. Neither a filename nor avoiding `os.getenv` provides workload
identity, narrow authority, rotation, revocation or encryption-key separation.

### Give every application a direct cloud-vault integration

Rejected as the default CWL product contract. It duplicates lifecycle and
access semantics across consumers. Deployment-specific KMS/HSM and external
vault providers belong behind Keyverse-owned ports and anti-corruption layers;
consumer business data and provider selection remain in their owning domains.

### Extend Keycloak's internal credential store as a generic secret database

Rejected. Keycloak's supported vault integration resolves selected Keycloak
credentials. It does not supply the versioned CWL-wide workload API requested
here. Identity records, password authenticators and application secret values
have different invariants and must not share an undifferentiated model.

### Keyverse-owned secret context with separate identity/authorization contexts

Selected direction, pending implementation and independent acceptance. The
existing foundation is preserved, repaired and evolved rather than discarded.
New secret-service/security runtime is Rust; the Python change in this child
is limited to the already-existing bootstrap/config adapter. It does not add a
new Python cryptographic engine or duplicate the future Rust data plane.

## Decision and responsibility boundary

Keyverse owns secret references, encrypted custody, secret versions, authorized
resolution, rotation/revocation, leases and access audit. Identity establishes
who a human/workload is; authorization grants narrowly scoped operations;
secret custody performs them. Product consumers retain their domain truth and
what a credential is used for. Billing, ontology, configuration, and LLM
provider/model routing are not moved into the vault.

The minimal shared kernel consists of value-free reference and verified-context
contracts. Separate persistence and public API boundaries are required. The
foundation's `keyvault_secrets`/`keyvault_audit_log` are not extensions of
`idp_config_entries`, account-merge audit, or Keycloak realm records.

The administrator surface remains metadata-only on reads. A consumer may not
use an operator session/token, set its own trusted namespace, query another
service's DB, import an open PR's source, or obtain all secrets in a catalog.
A namespace must be bound by verified policy to tenant, environment and workload;
its name alone is not authorization.

## Implemented bootstrap repair

The existing configuration loader rejects any plaintext `keyvault_passphrase`
entry. It accepts only `keyvault_passphrase_file`, a non-secret locator resolved
by the existing bootstrap boundary. There is no process-environment, dotenv,
home-directory or plaintext-DB fallback.

The POSIX reader validates every path component with descriptor-relative,
no-follow opens. The actual opened object must be a root/service-owned regular
file, mode 0400 or 0600, one link, bounded to 4096 bytes, valid UTF-8 and nonempty.
It rejects FIFOs, directories, symlinks, dot segments, invalid ownership and
unsafe permissions, detects changes during reading, and closes all descriptors.
It removes one terminal newline only. OS/decoder failures are converted to a
value-free error. Configuration repr excludes all declared credential fields;
this does not make arbitrary dataclass serialization safe.

This root-only supervisor transport is an explicit bootstrap exception: the
vault cannot call its own locked service to retrieve its unlock credential.
The locator belongs in configuration, the credential in an independently
protected supervisor mount. A regular private file is not an HSM and does not
protect against host/root compromise or Python string retention.

Production native runtime must support managed workload identity and external
KMS/HSM envelope-key custody. Standard Kubernetes projected Secret symlinks are
not silently accepted by the compatibility reader; a trusted controller must
provide a private regular-file snapshot or a separately reviewed adapter.

## Required workload-resolution contract — not yet implemented

- Verify signature, allowed algorithm, exact issuer/audience, subject, time
  claims and workload profile before accepting identity. Do not trust decoded
  JWT claims or caller-provided tenant headers.
- Bind secret resolution to tenant/environment, namespace, key, version,
  operation and bounded lease. Deny unknown/missing/ambiguous scope.
- GitHub OIDC integrations bind repository/owner IDs, event/ref/environment,
  trusted workflow identity and immutable workflow revision. PR/fork source
  never receives general provider or administrator credentials.
- Store encrypted values with authenticated context binding; separate wrapping
  keys from ciphertext. Parent PBKDF2 fixed salt/value-only encryption is not
  the final multi-tenant cryptographic contract.
- Publish durable immutable versions, audited rotation/revocation, idempotent
  updates, concurrency control and recoverable migrations. Preserve ciphertext
  and key-version relationships through backup/restore and rollback.
- Return no-store responses. Audit denial and permitted access without secret
  values; audit-store failure cannot silently become successful resolution.
- A consumer may use a still-valid lease only under its explicit revocation
  policy. Expired cache and dotenv fallback are not allowed during outages.
- Emit no credentials into frontend bundles, event buses, logs, traces,
  screenshots, command arguments, generated artifacts or model context.

CO consumes only an immutable owner API release through its existing port.
Provider keys stay inside CO's approved execution boundary; other CWL products
use CO rather than holding those keys. Model-backed Actions retain
`orchestrator/free`; routing and provider discovery stay in CO.

## Migration and consequences

The child preserves canonical PR #129 and never force-pushes over another writer.
No consumer is switched before owner release. A private operator must transfer
the existing root value unchanged to the supervisor before removing the legacy
DB entry. Replacing its value without rewrap would break old ciphertext.
Deleting the row is not secure erasure of SQLite pages, WAL or backups. Retire
those copies and rotate/rewrap only under tested recovery procedures.

No prior bare-SHA key derivation fallback is introduced. The parent's premise
that that format never reached a release must be checked against actual private
deployment evidence before any legacy migration is needed.

Standalone operation remains an explicit deployment profile, not an invisible
fallback. Failure modes and risk are visible: unavailable authority, expired
lease, wrong key, missing audit store and unsupported bootstrap platform are
errors, not empty inventories or synthetic success. The result adds operational
complexity but avoids a hidden second authority and uncontrolled key fan-out.

## Verification and acceptance

The child has observed RED tests and 42 passing focused bootstrap/config tests.
Changed executable-line coverage is 61/61 with no missing changed-line arcs.
Full service coverage, docstrings, locked dependencies, security review and
hosted Checks remain independent gates. These results do not validate the
unimplemented remote API, KMS/HSM, deployment or organization-wide migration.
See the gap baseline and operations guide for exact source blobs and limitations.

Before promotion: full exact-head suite and 100% production coverage/docstrings,
independent review, protected merge, immutable release, recovery and consumer
contract tests. No claim of SOC 2/CSAP certification or vault completeness is
made from this ADR or from tests of a single bootstrap component.

## References — APA 7th

Evans, E. (2003). *Domain-driven design: Tackling complexity in the heart of software*. Addison-Wesley.

Vernon, V. (2013). *Implementing domain-driven design*. Addison-Wesley.

OWASP Foundation. (n.d.). *Secrets management cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

GitHub. (n.d.). *OpenID Connect reference*. https://docs.github.com/en/actions/reference/security/oidc

Keycloak. (n.d.). *Using a vault*. https://www.keycloak.org/server/vault
