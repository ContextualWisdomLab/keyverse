# LDAP and Active Directory Preflight — Doctoring Record

## Scope

This record covers the deterministic Keyverse preflight for a rendered
Keycloak LDAP user-storage component. It does not claim to validate a live
directory, credential, certificate chain, DNS answer, schema, replication
relationship, or Keycloak component mutation.

The endpoint is intentionally side-effect-free. It parses a private request,
validates a closed security profile, and returns a redacted readiness receipt.
The private request—not the response—remains the only payload suitable for a
later Keycloak Admin REST apply because the response replaces bind identity and
credential material with `<redacted>`.

## Buyer and operator risk addressed

Without preflight, an unsafe directory component can be stored before its
failure is visible. The resulting failure can occur on the interactive login
path and affect every user whose lookup reaches the component. The preflight
therefore rejects configuration that is likely to create one of the following
classes of buyer-visible failure:

- cleartext credential transport;
- ambiguous or malformed endpoint syntax;
- malformed LDAP distinguished names;
- accidental write-back or registration synchronization;
- Kerberos activation without a separately reviewed realm and keytab contract;
- email assertions treated as verified without an upstream verification
  contract;
- unresolved deployment secrets;
- ambiguous Keycloak multivalued configuration;
- duplicate directory endpoints;
- unbounded connection and read latency;
- secret disclosure through operator responses.

## Standards interpretation

### LDAP protocol and transport

RFC 4511 defines LDAP operations and protocol data structures. RFC 4513 defines
LDAP authentication and security mechanisms and notes that some authentication
methods expose credentials unless protected by an integrity and confidentiality
service. The first Keyverse directory profile therefore accepts only `ldaps://`
locations and does not permit simple LDAP over cleartext transport.

This is a configuration invariant, not a TLS conformance claim. Certificate
trust, revocation, approved destination policy, DNS behavior, and network
segmentation remain deployment controls. Preflight performs no connection and
cannot prove them.

### Directory information and identifiers

RFC 4512 defines LDAP descriptors and numeric object identifiers. Keyverse
accepts those two lexical forms for attribute and object-class references and
rejects options or arbitrary punctuation in this first profile.

RFC 4514 defines the string representation of distinguished names. The
implementation validates a bounded lexical profile that supports escaped
specials, hexadecimal escapes, hexadecimal attribute values, multi-valued
RDNs, descriptors, and numeric OIDs. It does not canonicalize names or compare
DN equivalence because those operations require directory schema and matching
rules that are outside side-effect-free preflight.

### Search filters

RFC 4515 defines LDAP search-filter strings. The first preflight profile does
not admit a custom user filter, so it avoids creating a second parser and an
operator-controlled filter-injection surface. A future filter feature must add
an RFC 4515 parser, realistic directory tests, and a separate security review.

### Keycloak operating mode

Keycloak documents `READ_ONLY`, `WRITABLE`, and `UNSYNCED` LDAP edit modes.
The initial Keyverse profile permits only `READ_ONLY` and disables registration
synchronization. It also disables Kerberos and trusted email. This is a product
policy choice for the first bounded integration, not a claim that Keycloak's
other modes are incorrect.

The accepted vendor identifiers mirror Keycloak's LDAP provider values:
`ad`, `other`, `rhds`, `tivoli`, and `edirectory`. Vendor selection does not
replace explicit attribute configuration, which remains validated independently.

## Applied repository controls

| Control area | Repository implementation |
| --- | --- |
| Privileged access | Router uses the existing constant-time operator bearer-token dependency and privileged path-security dependency. |
| Side-effect isolation | Validation imports no network client and performs no storage or Keycloak call. Tests replace DNS and socket entry points with fail-fast sentinels. |
| Transport | One or more unique `ldaps://` authorities; no userinfo, query, fragment, arbitrary path, raw/encoded control, percent encoding, or backslash. |
| Mutation policy | `READ_ONLY`, `syncRegistrations=false`, `allowKerberosAuthentication=false`, and imported users only. |
| Identity policy | `trustEmail=false`; verified-email linking remains unavailable until a separate upstream contract is reviewed. |
| Secret handling | `bindDn` and `bindCredential` are redacted in success responses; validation errors contain only field names and requirements. |
| Schema | Closed single-valued component configuration; LDAP descriptors or numeric OIDs; unique object classes. |
| Latency | Inclusive priority and timeout bounds prevent accidental effectively unbounded login-path waits. |
| Modularity | The payload remains a standard Keycloak component representation usable by standalone, CWL, and Naruon deployment controllers. |
| Quality | Realistic AD payloads, hostile counterexamples, 100% production docstrings, and 100% statement/branch coverage. |

## Deliberate limitations and follow-up

- No live bind or search is performed, so credentials and server reachability
  are not verified.
- No certificate chain or hostname verification is performed by preflight.
- No custom LDAP filter is supported.
- No Keycloak component is persisted, reconciled, or deleted by this increment.
- No LDAP email attribute is considered verified.
- No writable, unsynced, Kerberos, StartTLS, or password-modification workflow
  is supported.
- No formal RFC, NIST, or Keycloak conformance claim is made.

A later desired-state increment may add a multi-word snake_case storage
namespace, component CRUD, exact desired/applied comparison, duplicate detection,
drift reporting, recovery convergence, and safe deletion. That change requires
new Keycloak permissions and must not be inferred from this preflight.

## References — APA 7th

Harrison, R. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
Authentication methods and security mechanisms* (RFC 4513). Internet
Engineering Task Force. https://doi.org/10.17487/RFC4513

Keycloak. (n.d.). *Server Administration Guide: LDAP and Active Directory*.
Retrieved August 5, 2026, from
https://www.keycloak.org/docs/latest/server_admin/

Sermersheim, J. (Ed.). (2006). *Lightweight Directory Access Protocol (LDAP):
The protocol* (RFC 4511). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4511

Smith, M., & Howes, T. (2006). *Lightweight Directory Access Protocol (LDAP):
String representation of search filters* (RFC 4515). Internet Engineering Task
Force. https://doi.org/10.17487/RFC4515

Zeilenga, K. (Ed.). (2006a). *Lightweight Directory Access Protocol (LDAP):
Directory information models* (RFC 4512). Internet Engineering Task Force.
https://doi.org/10.17487/RFC4512

Zeilenga, K. (Ed.). (2006b). *Lightweight Directory Access Protocol (LDAP):
String representation of distinguished names* (RFC 4514). Internet Engineering
Task Force. https://doi.org/10.17487/RFC4514
