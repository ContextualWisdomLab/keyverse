# LDAP/Active Directory Federation Preflight Design

**Date:** 2026-08-05  
**Status:** Approved implementation slice under the standing autonomous commercialization mandate  
**Roadmap:** Issue #2 — cross-system SSO and external federation

## Problem

Keyverse already provides side-effect-free preflight validation for external
SAML and OIDC identity providers. Corporate LDAP and Microsoft Active Directory
remain a raw Keycloak `ComponentRepresentation` template that operators render
and send directly to Keycloak Admin REST. A typo, cleartext LDAP URL, writable
edit mode, registration synchronization, ambiguous distinguished name, unsafe
bind credential, or malformed timeout can therefore enter the identity control
plane before a buyer receives a bounded validation result.

That is a material enterprise onboarding gap. Directory federation often has
access to the authoritative workforce identity source and can affect every
login. The first LDAP product slice must fail closed before network access or
mutation while remaining directly compatible with Keycloak's component API.

## Scope

Add one authenticated endpoint:

```text
POST /federation/user-directories:validate
```

The request is the same Keycloak component-shaped JSON that an operator later
submits to:

```text
POST /admin/realms/{realm}/components
```

The endpoint performs deterministic local validation only and returns a
redacted representation plus `ready_to_apply: true`. It performs no KV/DB
write, Keycloak call, DNS lookup, socket connection, bind, search, trust-store
probe, or directory mutation.

This slice does **not** persist or reconcile LDAP desired state. Component CRUD,
mapper management, live connectivity tests, synchronization, and drift
reconciliation remain follow-up work after the validation boundary is proven.

## Alternatives considered

### A. Keep direct Keycloak application with documentation only

Smallest change, but it leaves the highest-risk inputs unvalidated and cannot
produce an executable policy gate. Rejected.

### B. Add complete component CRUD and live connection testing now

Provides a full desired-state lifecycle, but combines validation, privileged
mutation, secret storage, network egress, Keycloak component identifiers,
mapper creation, and operational rollback in one large change. Rejected for
this bounded slice.

### C. Add a side-effect-free component-shaped preflight first

Recommended. It closes the immediate buyer-visible configuration gap, preserves
Keycloak interoperability, keeps the trust boundary small, and creates a stable
contract that a later desired-state service can reuse unchanged.

## API contract

### Request

The request mirrors the subset of Keycloak `ComponentRepresentation` required
for an LDAP user-storage provider:

```json
{
  "name": "corp-ldap",
  "providerId": "ldap",
  "providerType": "org.keycloak.storage.UserStorageProvider",
  "config": {
    "enabled": ["true"],
    "priority": ["1"],
    "editMode": ["READ_ONLY"],
    "importEnabled": ["true"],
    "syncRegistrations": ["false"],
    "vendor": ["ad"],
    "connectionUrl": ["ldaps://ad-01.corp.example:636 ldaps://ad-02.corp.example:636"],
    "usersDn": ["OU=Users,DC=corp,DC=example"],
    "bindDn": ["CN=svc-keycloak,OU=ServiceAccounts,DC=corp,DC=example"],
    "bindCredential": ["rendered-secret"],
    "usernameLDAPAttribute": ["sAMAccountName"],
    "rdnLDAPAttribute": ["cn"],
    "uuidLDAPAttribute": ["objectGUID"],
    "userObjectClasses": ["person, organizationalPerson, user"],
    "searchScope": ["2"],
    "trustEmail": ["false"],
    "useTruststoreSpi": ["always"],
    "connectionPooling": ["true"],
    "connectionTimeout": ["10000"],
    "readTimeout": ["10000"],
    "allowKerberosAuthentication": ["false"]
  }
}
```

Top-level extra fields and unknown configuration keys fail closed. Every
configuration entry must be an array containing exactly one bounded string.
This prevents ambiguous Keycloak `MultivaluedHashMap` coercion and keeps the
first contract auditable.

### Response

```json
{
  "registration": {
    "name": "corp-ldap",
    "providerId": "ldap",
    "providerType": "org.keycloak.storage.UserStorageProvider",
    "config": {
      "enabled": ["true"],
      "connectionUrl": ["ldaps://ad-01.corp.example:636 ldaps://ad-02.corp.example:636"],
      "usersDn": ["OU=Users,DC=corp,DC=example"],
      "bindDn": ["<redacted>"],
      "bindCredential": ["<redacted>"]
    }
  },
  "ready_to_apply": true
}
```

Only an explicit non-secret allowlist is disclosed. Bind DN and credential are
redacted because distinguished names can reveal internal organization
structure and service-account identity. Unknown fields are rejected rather
than reflected.

### Errors

Validation failures return HTTP 400 with a bounded field-oriented message that
never contains the rejected value. Authentication and path-security behavior
remain inherited from the existing operator router boundary.

## Validation policy

### Component identity

- `name` is an ASCII lowercase slug of 1–63 characters.
- `providerId` is exactly `ldap`.
- `providerType` is exactly
  `org.keycloak.storage.UserStorageProvider`.
- Unresolved `{{...}}` placeholders are rejected.

### Transport security

- `connectionUrl` contains one or more URLs separated by exactly one ASCII
  space.
- Every URL uses `ldaps`.
- Every URL has a hostname and an optional valid port.
- Userinfo, query, fragment, encoded controls, raw controls, backslashes, and
  non-root paths are rejected.
- Duplicate endpoints are rejected.
- Preflight does not resolve names, inspect certificates, or follow network
  redirects.
- `useTruststoreSpi` is exactly `always`, matching current Keycloak guidance for
  the deprecated setting.

RFC 4513 requires confidentiality protection for password authentication. This
profile therefore does not accept cleartext `ldap://` or defer protection to a
later operator step.

### Mutation and login policy

- `enabled` is `true`.
- `editMode` is `READ_ONLY`.
- `importEnabled` is `true` so local Keycloak features and deterministic account
  unification can operate on imported users.
- `syncRegistrations` is `false` so Keyverse cannot create workforce directory
  accounts.
- `allowKerberosAuthentication` is `false`; SPNEGO/Kerberos requires a separate
  realm-flow, keytab, principal, browser, and replay-protection design.
- `trustEmail` is `false` by default. Email linking becomes eligible only after
  a separate reviewed authority and mapper contract proves that the directory
  attribute is verified.

### Directory structure

- `usersDn` and `bindDn` use a bounded RFC 4514 lexical profile.
- Empty RDNs, empty AVAs, unescaped separators, dangling escapes, malformed hex
  escapes, leading unescaped `#`, unescaped leading/trailing spaces, and control
  characters are rejected.
- Attribute descriptors are ASCII LDAP descriptors or numeric OIDs.
- `usernameLDAPAttribute`, `rdnLDAPAttribute`, and `uuidLDAPAttribute` use that
  same descriptor profile.
- `userObjectClasses` is a comma-and-single-space list of unique LDAP
  descriptors.
- `searchScope` is `1` or `2`; the supplied enterprise template uses subtree
  scope `2`.
- Custom search filters are not accepted in this slice. Supporting RFC 4515
  filters later requires a dedicated parser, filter-size budget, and injection
  tests rather than string heuristics.

### Resource bounds

- The component contains at most 32 configuration entries.
- Keys and values are bounded.
- `priority` is 0–1000.
- connection and read timeouts are 100–30000 milliseconds.
- All required fields are present exactly once.

## Module boundary

Add `app/directory_federation.py` containing:

- request and redacted response models;
- deterministic validation helpers;
- RFC 4514 lexical validation;
- Keycloak component configuration validation; and
- the authenticated router endpoint.

`app/main.py` includes the new router under the same operator authentication and
admin path-security dependencies as the existing federation router. The module
has no dependency on KV, Keycloak transport, or the account-unification engine,
which makes it usable by the standalone service and by a parent CWL/Naruon
control plane.

## Testing strategy

The first commit adds behavior tests before production code. The RED condition
is the absent module/endpoint. Tests then prove:

- a live-format Active Directory payload returns HTTP 200;
- bind DN, bind credential, and rejected values never appear in responses;
- operator authentication remains mandatory;
- no KV or Keycloak dependency is touched;
- cleartext LDAP, URL ambiguity, duplicate endpoints, unsafe DNs, malformed
  attribute descriptors, writable edit modes, registration sync, Kerberos,
  trusted email, unsupported filters, unresolved templates, unknown keys,
  multivalued ambiguity, and timeout overflow fail closed;
- one and multiple LDAPS replica endpoints pass;
- escaped RFC 4514 separators and hex escapes pass;
- production statement, branch, and docstring coverage remain 100%; and
- the deployment template passes the same production validator after rendering
  only the secret/placeholders in test fixtures.

## Operational follow-up

A later slice may add persisted directory desired state and Keycloak Component
CRUD. That design must bind a stable Keyverse alias to the generated Keycloak
component ID, compare normalized applied state, manage default LDAP mappers,
retain secrets outside operator responses, and preserve desired state when
Keycloak is unavailable.

## References

Harrison, R. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Authentication methods and security mechanisms* (RFC 4513). Internet
Engineering Task Force. https://www.rfc-editor.org/rfc/rfc4513

Keycloak. (2026). *Server Administration Guide: Lightweight Directory Access
Protocol (LDAP) and Active Directory*. https://www.keycloak.org/docs/latest/server_admin/

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
The protocol* (RFC 4511). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc4511

Smith, M., & Howes, T. (2006). *Lightweight Directory Access Protocol (LDAP):
String representation of search filters* (RFC 4515). Internet Engineering Task
Force. https://www.rfc-editor.org/rfc/rfc4515

Zeilenga, K. (2006). *Lightweight Directory Access Protocol (LDAP): String
representation of distinguished names* (RFC 4514). Internet Engineering Task
Force. https://www.rfc-editor.org/rfc/rfc4514
