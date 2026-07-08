#!/usr/bin/env python3
"""Validate the cwl-idp Keycloak realm config-as-code.

Parses the realm JSON and asserts the ecosystem-policy invariants hold, so a
broken realm export is caught in CI before it ever reaches Keycloak:

  * valid JSON, realm named and enabled;
  * a passwordless browser flow is bound and contains NO password authenticator
    but DOES use the WebAuthn passwordless authenticator (passkey-first);
  * self-service password registration + reset are OFF;
  * the employer ADFS is registered as an INBOUND SAML IdP with trustEmail;
  * an LDAP/AD user-federation source is present;
  * an OIDC/OAuth2.1 RP client template and the account-unification service
    account client exist; no committed client secret is a real value.

Usage: python scripts/validate_realm.py [path-to-realm.json]
Exit 0 = valid, 1 = invalid (prints the failing checks).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PASSWORD_AUTHENTICATORS = {
    "auth-password-form",
    "auth-username-password-form",
    "password",
}
PASSWORDLESS_AUTHENTICATOR = "webauthn-authenticator-passwordless"
SECRET_PLACEHOLDER = "__set_from_kv__"


def _executions(realm: dict, alias: str) -> list[dict]:
    for flow in realm.get("authenticationFlows", []):
        if flow.get("alias") == alias:
            return flow.get("authenticationExecutions", [])
    return []


def _all_authenticators(realm: dict, alias: str, seen: set[str] | None = None) -> set[str]:
    """Collect authenticator ids reachable from a flow, following subflows."""
    seen = seen if seen is not None else set()
    if alias in seen:
        return set()
    seen.add(alias)
    found: set[str] = set()
    for execution in _executions(realm, alias):
        if execution.get("authenticator"):
            found.add(execution["authenticator"])
        subflow = execution.get("flowAlias")
        if subflow:
            found |= _all_authenticators(realm, subflow, seen)
    return found


def validate(realm: dict) -> list[str]:
    errors: list[str] = []

    if realm.get("realm") != "cwl":
        errors.append("realm name must be 'cwl'")
    if not realm.get("enabled", False):
        errors.append("realm must be enabled")

    # Passwordless-first browser flow.
    browser_flow = realm.get("browserFlow")
    if not browser_flow:
        errors.append("browserFlow must be set")
    else:
        authenticators = _all_authenticators(realm, browser_flow)
        if not authenticators:
            errors.append(f"browserFlow '{browser_flow}' has no executions defined")
        password_used = authenticators & PASSWORD_AUTHENTICATORS
        if password_used:
            errors.append(
                f"browserFlow uses a password authenticator {sorted(password_used)}; "
                "ecosystem policy is passwordless"
            )
        if PASSWORDLESS_AUTHENTICATOR not in authenticators:
            errors.append(
                f"browserFlow must use '{PASSWORDLESS_AUTHENTICATOR}' (passkey-first)"
            )

    if realm.get("registrationAllowed", False):
        errors.append("registrationAllowed must be false")
    if realm.get("resetPasswordAllowed", False):
        errors.append("resetPasswordAllowed must be false")

    # Employer ADFS inbound SAML IdP.
    idps = {i.get("alias"): i for i in realm.get("identityProviders", [])}
    adfs = idps.get("employer-adfs")
    if adfs is None:
        errors.append("identity provider 'employer-adfs' is missing")
    else:
        if adfs.get("providerId") != "saml":
            errors.append("employer-adfs must be a SAML identity provider")
        if not adfs.get("trustEmail", False):
            errors.append("employer-adfs must set trustEmail (verified-email auto-link)")

    # LDAP/AD federation.
    storage = realm.get("components", {}).get(
        "org.keycloak.storage.UserStorageProvider", []
    )
    if not any(c.get("providerId") == "ldap" for c in storage):
        errors.append("an LDAP user-storage provider is required")

    # Clients: RP template + service account, no committed real secret.
    clients = {c.get("clientId"): c for c in realm.get("clients", [])}
    if "ecosystem-rp-template" not in clients:
        errors.append("OIDC RP client template 'ecosystem-rp-template' is missing")
    else:
        rp = clients["ecosystem-rp-template"]
        if rp.get("implicitFlowEnabled", False):
            errors.append("RP template must not enable the implicit flow (OAuth 2.1)")
        if rp.get("attributes", {}).get("pkce.code.challenge.method") != "S256":
            errors.append("RP template must require PKCE S256")
    svc = clients.get("account-unification-svc")
    if svc is None:
        errors.append("service-account client 'account-unification-svc' is missing")
    elif not svc.get("serviceAccountsEnabled", False):
        errors.append("account-unification-svc must enable service accounts")

    for client_id, client in clients.items():
        secret = client.get("secret")
        if secret is not None and secret != SECRET_PLACEHOLDER:
            errors.append(f"client '{client_id}' commits a non-placeholder secret")

    return errors


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path("deploy/keycloak/realm-cwl.json")
    try:
        realm = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID: cannot parse {path}: {exc}", file=sys.stderr)
        return 1

    errors = validate(realm)
    if errors:
        print(f"INVALID: {path}", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {path} is a valid cwl-idp realm (passwordless, ADFS, LDAP, OIDC RP).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
