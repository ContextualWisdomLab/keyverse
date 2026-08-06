# OIDC Relying-Party Desired-State Reconciliation — Doctoring Record

## Scope

This record documents Keyverse's secret-free lifecycle for a closed Keycloak
OIDC relying-party `ClientRepresentation`: local validation, durable intent,
exact client discovery, create/update/delete ordering, realm-rebuild recovery,
observable status, and canonical apply receipts.

It does not claim to validate a live authorization endpoint, TLS certificate,
DNS answer, client secret, user session, token audience, login, refresh, or
logout. Those remain controlled acceptance tests after apply.

## Evidence categories

- **Standards requirements:** OAuth security guidance and PKCE from IETF RFCs.
- **Protocol metadata:** OIDC client-registration metadata semantics.
- **Vendor behavior:** Keycloak Admin REST client collection/resource behavior.
- **Product policy:** Keyverse's closed, secret-free metadata profile and
  fail-closed duplicate policy.
- **Measured evidence:** repository tests, exact-head coverage, package and
  deployment validation, and GitHub security checks.
- **Assumptions:** one process-local reconciler per client ID until a shared lock
  backend is configured for multiple replicas.
- **Limitations:** a successful observable apply does not prove login success or
  prevent later out-of-band changes.

No formal OAuth, OIDC, Keycloak, NIST, or other conformance claim is made.

## Security relationship

RFC 9700 updates OAuth security best current practice. The upstream preflight
implements a deliberately narrower product profile: authorization code flow,
PKCE `S256`, exact HTTPS redirect metadata, disabled implicit and password-style
grants, bounded token metadata, and least portable scopes. Reconciliation does
not relax that policy; every stored record is revalidated before use.

RFC 7636 defines proof key for code exchange and the `S256` transformation.
Keyverse stores only the client metadata requiring `S256`; code verifiers and
authorization codes are runtime values and never enter desired state.

OpenID Connect Dynamic Client Registration defines client metadata such as
redirect URIs and authentication methods. Keyverse does not expose a general
registration endpoint. It accepts only the reviewed subset implemented by
`RelyingPartyRegistration` and rejects unknown fields, including client-secret
and registration-access-token fields.

## Stable identity and duplicate policy

Keycloak generates an opaque internal UUID, but the deployment-owned stable key
is the validated public `clientId`. Exact live discovery therefore classifies:

- zero exact matches: create one client;
- one exact match: compare and update when required;
- more than one exact match: `ambiguous`, with no mutation.

The generated UUID is diagnostic operational state and is validated before it
can enter a resource path. It is never used as the durable desired-state key.

## Storage and receipt model

Desired state and apply receipts use:

```text
relying_party_sources
relying_party_apply_receipts
```

Both are multi-word `snake_case`. The standalone implementation reuses the
existing `idp_config_entries` SQLite object and introduces no schema migration.

The desired record is alias-preserving JSON for the exact validated
representation. The receipt is SHA-256 over canonical UTF-8 JSON with sorted
keys and compact separators. Equivalent mapping order therefore produces one
stable digest.

The receipt is not a credential. It means Keyverse re-observed one exact live
client whose closed observable metadata matched the desired revision when the
receipt was written. It does not prove successful authorization-code exchange,
secret equality, or absence of later manual changes.

## Secret non-observability

The closed desired model has no `secret`, `clientSecret`,
`registrationAccessToken`, initial-access token, bearer token, authorization
code, or PKCE verifier field. Reconciliation neither generates nor retrieves a
client secret. Confidential-client credential provisioning remains a separate
secret-management responsibility and must not be added to this lifecycle by
loosening the model.

## Locking and failure semantics

A state lock protects KV access only. A process-local keyed lock serializes
mutations for the same `clientId`; different relying parties can reconcile
independently. Keycloak network I/O never runs while the state lock is held.

Desired state is stored before remote convergence. Temporary outage or mutation
failure therefore preserves operator intent. Bulk reconciliation snapshots only
keys and re-reads each current value under its keyed lock, preventing a stale
snapshot from recreating a concurrently deleted record.

Delete is remote-first. Local desired state and receipt are removed only after
the exact live client is absent or successfully deleted. Observation failure,
duplicate clients, or delete failure retains recovery intent.

Create and update are not accepted solely because the HTTP mutation returned a
success code. Keyverse re-lists the exact `clientId`, requires one client,
validates the observed UUID, compares the closed metadata, and only then records
the receipt.

## Keycloak vendor relationship

Keycloak Admin REST exposes realm client collection and individual client
resources. Keyverse queries the collection with validated `clientId`, filters
exact matches, creates at the collection, and updates or deletes only a
validated opaque UUID resource.

The adapter subclasses the established product HTTP client and therefore reuses
one httpx pool, bearer-token cache, absolute realm route guard, and exactly-once
HTTP 401 reauthentication boundary. It does not create another service-account
credential or token cache.

## Verification contract

Realistic tests cover:

- empty-realm create and live re-observation;
- repeat PUT with no mutation;
- observable drift repair;
- realm rebuild recreation;
- Keycloak outage with retained desired intent;
- create and update failure;
- missing, duplicated, identity-changed, mismatched, or unavailable post-apply
  observation;
- duplicate pre-apply fail-closed behavior;
- malformed or mis-keyed stored state without reflection;
- remote-first delete failure and success;
- deterministic sorted inventory;
- canonical key-order-independent receipt;
- blocked network I/O while another state read advances;
- stale key snapshots that cannot resurrect deleted intent;
- exact authenticated HTTP lifecycle;
- exact collection query, Location parsing, body-ID pinning, unsafe UUID
  rejection, malformed response rejection, and one-shot 401 refresh.

Completion requires locked installation, Ruff, compilation, production
docstrings 100%, production statement coverage 100%, production branch coverage
100%, complete pytest, package build, realm/Compose/template validation, CodeQL,
Semgrep, Security Scan, current-head review, zero unresolved threads, and
protected merge policy.

## Modularity

The same service supports standalone Keyverse with SQLite-backed `KvStore`, CWL
platform storage, and Naruon deployment controllers. The pure preflight remains
callable without storage or Keycloak. Stateful reconciliation depends only on
`KvStore` and `RelyingPartyAdminApi`.

No LLM, contextual orchestrator, `NVIDIA_NIM_API_KEY`,
`COPILOT_GITHUB_TOKEN`, or review-agent credential is used for deterministic
client metadata or reconciliation.

## Residual risk and follow-up

- Multi-replica deployment requires a shared advisory-lock implementation or one
  elected reconciler.
- Controlled authorization-code/PKCE login, refresh, and logout E2E remains
  mandatory before production routing.
- Confidential client-secret creation, storage, rotation, and revocation need a
  separate secret-management port and audit contract.
- Out-of-band changes between observations remain possible.
- Release still requires immutable image digest, SBOM, provenance, backup and
  restore, rollback rehearsal, and operating SLO evidence.

## References — APA 7th

Lodderstedt, T., Bradley, J., Labunets, A., & Fett, D. (2025). *Best current
practice for OAuth 2.0 security* (RFC 9700). Internet Engineering Task Force.
https://doi.org/10.17487/RFC9700

OpenID Foundation. (n.d.). *OpenID Connect Dynamic Client Registration 1.0
incorporating errata set 2*. Retrieved August 7, 2026, from
https://openid.net/specs/openid-connect-registration-1_0.html

Sakimura, N., Bradley, J., & Agarwal, N. (2015). *Proof Key for Code Exchange by
OAuth public clients* (RFC 7636). Internet Engineering Task Force.
https://doi.org/10.17487/RFC7636

Keycloak. (n.d.). *Keycloak Admin REST API*. Retrieved August 7, 2026, from
https://www.keycloak.org/docs-api/latest/rest-api/index.html
