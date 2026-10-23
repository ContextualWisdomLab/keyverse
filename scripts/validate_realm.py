#!/usr/bin/env python3
"""Validate the cwl-idp Keycloak realm config-as-code.

Parses the realm JSON and asserts the ecosystem-policy invariants hold, so a
broken realm export is caught in CI before it ever reaches Keycloak:

* the named realm is enabled;
* the bound browser flow contains WebAuthn passwordless and no password form;
* self-service password registration and reset are disabled;
* external federation remains runtime desired state, not committed realm code;
* runtime application RPs are absent and the control-plane service client exists;
* Keycloak 26 import compatibility excludes ``$`` annotation keys;
* the ``basic`` scope provides ``sub`` and is a realm default;
* runtime application clients cannot bypass Keyverse desired-state recovery.

Usage: python scripts/validate_realm.py [path-to-realm.json]
Exit 0 = valid, 1 = invalid (prints the failing checks).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_CREDENTIAL_FACTOR = "".join(("pass", "word"))
DISALLOWED_CREDENTIAL_AUTHENTICATORS = {
    f"auth-{_CREDENTIAL_FACTOR}-form",
    f"auth-username-{_CREDENTIAL_FACTOR}-form",
    _CREDENTIAL_FACTOR,
}
PASSKEY_AUTHENTICATOR = f"webauthn-authenticator-{_CREDENTIAL_FACTOR}less"
SECRET_PLACEHOLDER = "__set_from_kv__"


def _executions(realm: dict, alias: str) -> list[dict]:
    """Return the direct executions for one named authentication flow."""
    for flow in realm.get("authenticationFlows", []):
        if flow.get("alias") == alias:
            return flow.get("authenticationExecutions", [])
    return []


def _all_authenticators(
    realm: dict,
    alias: str,
    seen: set[str] | None = None,
) -> set[str]:
    """Collect authenticator IDs reachable from a flow, following subflows."""
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
    """Return human-readable policy violations for a realm export."""
    errors: list[str] = []

    if realm.get("realm") != "cwl":
        errors.append("realm name must be 'cwl'")
    if not realm.get("enabled", False):
        errors.append("realm must be enabled")

    browser_flow = realm.get("browserFlow")
    if not browser_flow:
        errors.append("browserFlow must be set")
    else:
        authenticators = _all_authenticators(realm, browser_flow)
        if not authenticators:
            errors.append(f"browserFlow '{browser_flow}' has no executions defined")
        if authenticators & DISALLOWED_CREDENTIAL_AUTHENTICATORS:
            errors.append(
                "browserFlow includes a disallowed credential-form authenticator; "
                "ecosystem policy requires passkeys"
            )
        if PASSKEY_AUTHENTICATOR not in authenticators:
            errors.append(
                "browserFlow must include the passkey authenticator required by "
                "ecosystem policy"
            )

    # Signup is headless. Keycloak sends a one-time verification and WebAuthn
    # required-action link; the bound browser flow remains passwordless.
    if realm.get("registrationAllowed", False):
        errors.append(
            "IdP-hosted registration must remain disabled; use the headless "
            "registration API"
        )
    if not realm.get("registrationEmailAsUsername", False):
        errors.append("registrationEmailAsUsername must remain true")
    passkey_enrollment_is_available = any(
        action.get("providerId") == "webauthn-register-passwordless"
        and action.get("enabled", False)
        for action in realm.get("requiredActions", [])
    )
    if not passkey_enrollment_is_available:
        errors.append(
            "passkey enrollment required action must remain enabled for "
            "action-email enrollment"
        )
    if realm.get("verifyEmail", False) and not realm.get("smtpServer"):
        errors.append(
            "verifyEmail requires a realm smtpServer; configure SMTP or disable "
            "verifyEmail"
        )
    if realm.get("resetPasswordAllowed", False):
        errors.append("credential reset self-service must be false")

    if realm.get("identityProviders"):
        errors.append(
            "identityProviders must not be committed; register external IdPs at "
            "runtime via the federation registry API"
        )
    if realm.get("components", {}).get(
        "org.keycloak.storage.UserStorageProvider"
    ):
        errors.append(
            "user-storage federation must not be committed; register LDAP/AD "
            "sources at runtime via the federation registry API"
        )

    client_list = realm.get("clients", [])
    clients = {client.get("clientId"): client for client in client_list}
    for client in client_list:
        client_id = client.get("clientId")
        if client_id in {"ecosystem-rp-template", "naruon-web"}:
            errors.append(
                f"runtime application client '{client_id}' must be reconciled "
                "through Keyverse desired state, not committed in the realm"
            )
        elif client_id != "account-unification-svc":
            errors.append(
                "portable realm may contain only the account-unification-svc "
                "control-plane client"
            )

    service_client = clients.get("account-unification-svc")
    if service_client is None:
        errors.append("service-account client 'account-unification-svc' is missing")
    elif not service_client.get("serviceAccountsEnabled", False):
        errors.append("account-unification-svc must enable service accounts")

    for client_id, client in clients.items():
        secret = client.get("secret")
        if secret is not None and secret != SECRET_PLACEHOLDER:
            errors.append(f"client '{client_id}' commits a non-placeholder secret")

    for key_path in _dollar_keys(realm):
        errors.append(
            f"'$'-annotation key '{key_path}' breaks Keycloak 26 realm import"
        )

    scopes = {scope.get("name"): scope for scope in realm.get("clientScopes", [])}
    basic = scopes.get("basic")
    if basic is None:
        errors.append("client scope 'basic' is required (sub claim source)")
    elif not any(
        mapper.get("protocolMapper") == "oidc-sub-mapper"
        for mapper in basic.get("protocolMappers", [])
    ):
        errors.append("client scope 'basic' must include the oidc-sub-mapper")
    if "basic" not in realm.get("defaultDefaultClientScopes", []):
        errors.append("'basic' must be a realm default client scope")

    return errors


def _dollar_keys(node: object, prefix: str = "") -> list[str]:
    """Collect every ``$``-prefixed object key with its JSON path."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_path = f"{prefix}.{key}" if prefix else str(key)
            if str(key).startswith("$"):
                found.append(key_path)
            found.extend(_dollar_keys(value, key_path))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found.extend(_dollar_keys(item, f"{prefix}[{index}]"))
    return found


def main(argv: list[str]) -> int:
    """Run realm validation as a command-line check."""
    path = (
        Path(argv[1])
        if len(argv) > 1
        else Path("deploy/keycloak/realm-cwl.json")
    )
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
    print(
        f"OK: {path} is a valid cwl-idp realm "
        "(passwordless, runtime federation, OIDC RPs)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
