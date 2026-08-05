"""Finalize canonical LDAP receipts and operator documentation once."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _replace_once(path: Path, old: str, new: str) -> None:
    """Replace one exact block or fail rather than drifting silently."""
    text = path.read_text(encoding="utf-8")
    occurrences = text.count(old)
    if occurrences != 1:
        raise RuntimeError(
            f"expected one replacement in {path}, observed {occurrences}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _fix_canonical_receipts() -> None:
    """Make private desired-state receipts independent of mapping order."""
    path = (
        ROOT
        / "services"
        / "account_unification"
        / "app"
        / "directory_federation_state.py"
    )
    text = path.read_text(encoding="utf-8")
    if "import json\n" not in text:
        text = text.replace("import hashlib\n", "import hashlib\nimport json\n", 1)
    old = '''def _desired_digest(registration: DirectoryFederationRegistration) -> str:
    """Return one deterministic SHA-256 receipt for the private desired state."""
    serialized = registration.model_dump_json(by_alias=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
'''
    new = '''def _desired_digest(registration: DirectoryFederationRegistration) -> str:
    """Return one canonical SHA-256 receipt for the private desired state."""
    serialized = json.dumps(
        registration.model_dump(by_alias=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
'''
    if old not in text:
        raise RuntimeError("non-canonical directory digest implementation was not found")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _update_readme() -> None:
    """Describe the Keyverse-owned LDAP desired-state lifecycle."""
    path = ROOT / "README.md"
    _replace_once(
        path,
        '''- LDAP and Active Directory:
  `POST /federation/user-directories:validate`, followed by deployment-owned
  private Keycloak component apply. The first profile is LDAPS-only,
  read-only, Kerberos-disabled, and `trustEmail=false`.

LDAP preflight performs no DNS lookup, socket connection, bind, search, KV/DB
write, or Keycloak call. Its response redacts `bindDn` and `bindCredential` and
must never be used as the apply payload; apply the original private file only.
''',
        '''- LDAP and Active Directory:
  `POST /federation/user-directories:validate`, followed by
  `PUT /federation/user-directories/{directory_name}`. Keyverse stores the
  original private component in KV/DB and idempotently creates or updates one
  exact Keycloak user-storage component. The first profile is LDAPS-only,
  read-only, Kerberos-disabled, and `trustEmail=false`.

Preflight performs no DNS lookup, socket connection, bind, search, KV/DB write,
or Keycloak call. Desired-state responses redact `bindDn` and
`bindCredential`. Rebuild recovery uses
`POST /federation/user-directories:reconcile`; duplicate exact components fail
closed instead of being guessed or overwritten.
''',
    )


def _update_architecture() -> None:
    """Move LDAP component apply ownership from deployment tooling to Keyverse."""
    path = ROOT / "ARCHITECTURE.md"
    _replace_once(
        path,
        '''- applies the current LDAP component payload directly to private Keycloak Admin
  REST only after Keyverse preflight succeeds;
''',
        '''- submits the private LDAP component to Keyverse desired-state CRUD after
  preflight; Keyverse owns exact component create/update/delete and rebuild
  reconciliation through private Keycloak Admin REST;
''',
    )
    _replace_once(
        path,
        '''### LDAP and Active Directory

The first LDAP increment is a preflight boundary around the existing Keycloak
component representation:

```text
private rendered component
    -> authenticated local preflight
    -> redacted readiness receipt
    -> deployment-owned private Keycloak component apply
```

Preflight performs no DNS lookup, socket connection, bind, search, store write,
or Keycloak call. It requires LDAPS, read-only operation, no trusted-email
auto-linking, no Kerberos, bounded timeouts, valid RFC 4514 DN syntax, and a
closed config shape. Desired-state CRUD and reconciliation are a later module.
''',
        '''### LDAP and Active Directory

LDAP uses the same split between pure validation and protected desired state:

```text
private rendered component
    -> authenticated local preflight
    -> KV/DB private desired state
    -> exact Keycloak component reconciliation
    -> redacted observable status
```

Preflight performs no DNS lookup, socket connection, bind, search, store write,
or Keycloak call. Desired state uses `directory_federation_sources`; successful
private apply receipts use `directory_federation_apply_receipts`. Reconciliation
creates zero matches, updates one match when observable state or the private
revision receipt differs, and fails closed on duplicates. Keycloak does not
expose the stored bind secret for equality proof, so status reports
`secret_observation=not_observable` and never claims live secret equivalence.
''',
    )


def _update_claude() -> None:
    """Align agent guidance with stateful LDAP reconciliation."""
    path = ROOT / "CLAUDE.md"
    _replace_once(
        path,
        '''- `deploy/templates/` — explicit private deployment contracts. SAML/OIDC use
  Keyverse desired-state endpoints. LDAP is preflighted through Keyverse and
  then applied through private Keycloak Admin REST in this release. All
  `{{placeholders}}` are resolved from KV before use.
''',
        '''- `deploy/templates/` — explicit private deployment contracts. SAML, OIDC,
  and LDAP are preflighted and then persisted through Keyverse desired-state
  endpoints. Keyverse reconciles private LDAP intent through Keycloak Admin
  REST. All `{{placeholders}}` are resolved from KV before use.
''',
    )
    _replace_once(
        path,
        '''- **LDAP/AD input is preflighted before private Keycloak apply.** Use
  `POST /federation/user-directories:validate`. The first profile requires
  LDAPS, `READ_ONLY`, no registration sync, no Kerberos, no trusted email,
  truststore enforcement, bounded latency, RFC 4514 DN syntax, and a closed
  single-valued config shape. Preflight performs no DNS lookup, socket, bind,
  search, storage write, or Keycloak call. Its redacted response is never an
  apply payload.
''',
        '''- **LDAP/AD input is preflighted and reconciled as private desired state.**
  Use `POST /federation/user-directories:validate`, then
  `PUT /federation/user-directories/{directory_name}`. The first profile
  requires LDAPS, `READ_ONLY`, no registration sync, no Kerberos, no trusted
  email, truststore enforcement, bounded latency, RFC 4514 DN syntax, and a
  closed single-valued config shape. Preflight performs no DNS lookup, socket,
  bind, search, storage write, or Keycloak call. Network I/O never runs while
  the desired-state storage lock is held. Duplicate exact components fail
  closed, delete is remote-first, and responses never expose bind identity or
  credentials.
''',
    )


def _update_template_guide() -> None:
    """Point the LDAP template at Keyverse desired-state apply."""
    path = ROOT / "deploy" / "templates" / "README.md"
    _replace_once(
        path,
        '''| `ldap-source.json` | Keycloak component contract | external directory → Keycloak | `POST /federation/user-directories:validate` | `POST /admin/realms/{realm}/components` |
''',
        '''| `ldap-source.json` | Keyverse directory desired-state API | external directory → Keyverse | `POST /federation/user-directories:validate` | `PUT /federation/user-directories/corp-ldap` |
''',
    )
    _replace_once(
        path,
        '''LDAP is still applied as a
Keycloak user-storage component in this release, but its rendered payload must
first pass the authenticated Keyverse directory preflight described below.
''',
        '''LDAP is stored as private Keyverse desired state after authenticated
preflight, then reconciled into one exact Keycloak user-storage component.
''',
    )


def _update_onboarding() -> None:
    """Replace the direct-apply procedure with desired-state operations."""
    path = ROOT / "docs" / "ldap-directory-onboarding.md"
    path.write_text(
        '''# LDAP and Active Directory onboarding

## Scope

This procedure renders a private LDAP component, validates it through Keyverse,
stores it as desired state, and lets Keyverse reconcile one exact Keycloak
user-storage component. The same contract works for standalone deployments and
CWL/Naruon deployment controllers.

The service does not perform a live bind or search. It owns configuration
lifecycle only.

## Prerequisites

- Keyverse operator API is reachable only through the approved admin/WAF path;
- Keycloak Admin REST remains private to the Keyverse service account;
- the directory endpoint is reachable through approved egress;
- the LDAPS chain is trusted by Keycloak;
- the bind account is read-only and scoped to the required subtree;
- only one active Keyverse directory reconciler runs per deployment until a
  shared advisory-lock backend is introduced.

## Validate and persist

Render `deploy/templates/ldap-source.json` into a mode-0600 file. Keep the
operator bearer token in a private curl configuration, not the command line.

```bash
set -euo pipefail
BASE="https://keyverse-admin.example"
NAME="corp-ldap"
PAYLOAD="$(mktemp)"
RESPONSE="$(mktemp)"
AUTH_CONFIG="$(mktemp)"
cleanup() { rm -f "$PAYLOAD" "$RESPONSE" "$AUTH_CONFIG"; }
trap cleanup EXIT
chmod 0600 "$PAYLOAD" "$RESPONSE" "$AUTH_CONFIG"

set +x
TOKEN="$(kv get secret/keyverse/operator-api-token)"
printf 'header = "Authorization: Bearer %s"\\n' "$TOKEN" >"$AUTH_CONFIG"
unset TOKEN

render deploy/templates/ldap-source.json >"$PAYLOAD"

curl --config "$AUTH_CONFIG" --fail-with-body --silent --show-error \\
  --max-redirs 0 --header "Content-Type: application/json" \\
  --data-binary @"$PAYLOAD" \\
  "$BASE/federation/user-directories:validate" >"$RESPONSE"
python3 - "$RESPONSE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    receipt = json.load(stream)
if receipt.get("ready_to_apply") is not True:
    raise SystemExit("directory preflight did not authorize desired-state write")
PY

curl --config "$AUTH_CONFIG" --fail-with-body --silent --show-error \\
  --max-redirs 0 --request PUT \\
  --header "Content-Type: application/json" \\
  --data-binary @"$PAYLOAD" \\
  "$BASE/federation/user-directories/$NAME" >"$RESPONSE"
python3 - "$RESPONSE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    status = json.load(stream)
if status.get("convergence_state") != "in_sync":
    raise SystemExit("directory desired state was stored but did not converge")
config = status["registration"]["config"]
assert config["bindCredential"] == ["<redacted>"]
assert config["bindDn"] == ["<redacted>"]
assert status["secret_observation"] == "not_observable"
PY
```

The private payload is stored in `directory_federation_sources`. A canonical
SHA-256 receipt for the last successful private apply is stored separately in
`directory_federation_apply_receipts`. Neither endpoint returns private values.

## Observe and recover

```bash
curl --config "$AUTH_CONFIG" --fail-with-body --silent --show-error \\
  "$BASE/federation/user-directories"

curl --config "$AUTH_CONFIG" --fail-with-body --silent --show-error \\
  --request POST "$BASE/federation/user-directories:reconcile"
```

Use reconcile after realm rebuild, restore, or confirmed component loss.
Statuses mean:

- `in_sync`: one exact component, all observable non-secret fields match, and
  the canonical desired revision has a successful local apply receipt;
- `drifted`: one component exists but observable state or the private revision
  receipt differs;
- `absent`: no exact component exists;
- `ambiguous`: multiple exact components exist; no mutation occurs;
- `unavailable`: Keycloak observation failed; desired state is retained;
- `apply_failed`: create or update failed; desired state is retained.

`secret_observation=not_observable` is permanent: Keycloak does not expose bind
credential bytes for equality comparison. `in_sync` is not a claim that an
out-of-band secret change can be detected.

## Rotation

Render a new private payload with the rotated credential and repeat the same
PUT. The canonical private revision changes, forcing one update even when all
observable non-secret fields are unchanged. Retire the prior credential only
after the PUT reports `in_sync` and a live authentication test succeeds.

## Delete

```bash
curl --config "$AUTH_CONFIG" --fail-with-body --silent --show-error \\
  --request DELETE "$BASE/federation/user-directories/$NAME"
```

Delete is remote-first. Desired state and its receipt are removed only after
Keycloak confirms component deletion. A remote failure preserves recovery data.
Duplicate exact components return HTTP 409 and must be investigated manually.

## Incident handling

- **Preflight 400/422:** correct only the named field in the private source and
  rerender. Error text never includes the rejected value.
- **Unavailable/apply_failed:** keep desired state, restore Keycloak or network
  health, then reconcile.
- **Ambiguous:** disable automated mutation, inventory exact component IDs,
  preserve audit evidence, choose the legitimate component, remove duplicates
  through the private incident procedure, then reconcile.
- **Secret exposure:** rotate the bind credential and affected operator token,
  remove exposed evidence, review directory access logs, and repeat protected
  PUT plus live validation.
- **Login regression:** disable the exact component through incident tooling,
  verify normal login recovery, and investigate; never switch to cleartext LDAP,
  writable mode, Kerberos, or trusted email as a workaround.

## Post-apply evidence

A production change record should contain the Keyverse desired-state name,
component ID, template digest, Keycloak version, approved directory endpoint
identifiers, status, live bind/search test result, login result, rollback test,
and operator identity. Do not include DN or credential values.

## Limitations

Keyverse does not prove DNS ownership, TLS validity/revocation, bind correctness,
base DN existence, schema, matching rules, replication, or login SLO through
preflight. Those require controlled live post-apply tests.

## References

Standards interpretation and APA 7th references are in
`docs/doctoring/ldap-directory-desired-state.md` and
`docs/doctoring/ldap-directory-preflight.md`.
''',
        encoding="utf-8",
    )


def _update_changelog() -> None:
    """Record the desired-state lifecycle under Unreleased."""
    path = ROOT / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    added = '''### Added

- KV/DB-backed LDAP and Active Directory desired-state CRUD with exact Keycloak
  component create/update/delete, rebuild reconciliation, canonical private
  revision receipts, duplicate protection, and redacted convergence status.
'''
    if "KV/DB-backed LDAP and Active Directory desired-state CRUD" not in text:
        text = text.replace("### Added\n", added, 1)
    fixed_marker = "### Fixed\n"
    fixed = '''### Fixed

- Prevented direct LDAP component lifecycle drift by retaining private desired
  state across Keycloak outages, performing remote-first deletion, releasing
  storage locks before network calls, and forcing secret rotation updates
  through order-independent canonical apply receipts.
'''
    if "Prevented direct LDAP component lifecycle drift" not in text:
        text = text.replace(fixed_marker, fixed, 1)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    """Finalize implementation and documentation, then return zero."""
    _fix_canonical_receipts()
    _update_readme()
    _update_architecture()
    _update_claude()
    _update_template_guide()
    _update_onboarding()
    _update_changelog()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
