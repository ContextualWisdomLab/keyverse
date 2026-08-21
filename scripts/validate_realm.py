#!/usr/bin/env python3
"""Validate the cwl-idp Keycloak realm config-as-code.

Parses the realm JSON and asserts the ecosystem-policy invariants hold, so a
broken realm export is caught in CI before it ever reaches Keycloak:

* the named realm is enabled;
* the bound browser flow contains WebAuthn passwordless and no password form;
* self-service password registration and reset are disabled;
* external federation remains runtime desired state, not committed realm code;
* RP and service-account clients exist without committed real secrets;
* Keycloak 26 import compatibility excludes ``$`` annotation keys;
* the ``basic`` scope provides ``sub`` and is a realm default;
* ``naruon-web`` is a bounded-token public PKCE client with required claims.
* the post-import product authorization profile is explicit and admin-only.

Usage: python scripts/validate_realm.py [path-to-realm.json] [path-to-user-profile.json]
The profile path defaults to a sibling ``lineageweave-user-profile.json``;
validation fails closed when that artifact is absent or invalid.
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
MAX_PUBLIC_TOKEN_LIFESPAN = 900
USER_PROFILE_FILENAME = "lineageweave-user-profile.json"
BUILTIN_USER_PROFILE_ATTRIBUTES = {"username", "email", "firstName", "lastName"}


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


def _public_token_lifespan(client: dict) -> int | None:
    """Parse one optional client access-token lifespan as a positive integer."""
    raw_value = client.get("attributes", {}).get("access.token.lifespan")
    if raw_value is None:
        return None
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return -1
    return value if str(value) == str(raw_value).strip() else -1


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

    clients = {client.get("clientId"): client for client in realm.get("clients", [])}
    if "ecosystem-rp-template" not in clients:
        errors.append("OIDC RP client template 'ecosystem-rp-template' is missing")
    else:
        rp = clients["ecosystem-rp-template"]
        if rp.get("implicitFlowEnabled", False):
            errors.append("RP template must not enable the implicit flow (OAuth 2.1)")
        if rp.get("attributes", {}).get("pkce.code.challenge.method") != "S256":
            errors.append("RP template must require PKCE S256")

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

    naruon = clients.get("naruon-web")
    if naruon is None:
        errors.append("concrete RP client 'naruon-web' is missing")
    else:
        if not naruon.get("publicClient", False):
            errors.append("naruon-web must be a public (PKCE) client")
        if naruon.get("implicitFlowEnabled", False):
            errors.append("naruon-web must not enable the implicit flow")
        if naruon.get("attributes", {}).get("pkce.code.challenge.method") != "S256":
            errors.append("naruon-web must require PKCE S256")
        token_lifespan = _public_token_lifespan(naruon)
        if (
            token_lifespan is not None
            and not 0 < token_lifespan <= MAX_PUBLIC_TOKEN_LIFESPAN
        ):
            errors.append(
                "naruon-web access.token.lifespan must be an integer at or below "
                f"{MAX_PUBLIC_TOKEN_LIFESPAN} seconds"
            )
        naruon_mappers = {
            mapper.get("protocolMapper")
            for mapper in naruon.get("protocolMappers", [])
        }
        if "oidc-audience-mapper" not in naruon_mappers:
            errors.append("naruon-web must include an audience mapper")
        hardcoded_claims = {
            mapper.get("config", {}).get("claim.name")
            for mapper in naruon.get("protocolMappers", [])
            if mapper.get("protocolMapper") == "oidc-hardcoded-claim-mapper"
        }
        for claim_name in ("role", "org", "workspace"):
            if claim_name not in hardcoded_claims:
                errors.append(
                    f"naruon-web must carry the hardcoded '{claim_name}' claim "
                    "naruon's session contract requires"
                )
        if "basic" not in naruon.get("defaultClientScopes", []):
            errors.append("naruon-web must assign the 'basic' default scope")

    return errors


def validate_user_profile(profile: dict) -> list[str]:
    """Return violations for closed, administrator-managed product attributes."""
    errors: list[str] = []
    # Keycloak 26.3.2 has no DISABLED enum member: a missing/null policy is its
    # fail-closed representation. Sending the documented string makes the API
    # reject the complete profile payload.
    if profile.get("unmanagedAttributePolicy") is not None:
        errors.append(
            "user profile must omit unmanagedAttributePolicy so Keycloak 26 "
            "disables unmanaged attributes"
        )
    attributes = {
        item.get("name"): item
        for item in profile.get("attributes", [])
        if isinstance(item, dict)
    }
    if not BUILTIN_USER_PROFILE_ATTRIBUTES <= attributes.keys():
        errors.append(
            "user profile must retain Keycloak built-in account attributes when "
            "the Admin API replaces the complete profile"
        )
    for name in ("org", "workspace"):
        attribute = attributes.get(name)
        if not isinstance(attribute, dict):
            errors.append(f"user profile must define '{name}'")
            continue
        if attribute.get("multivalued") is not False:
            errors.append(f"user profile '{name}' must be scalar")
        if attribute.get("permissions") != {"view": ["admin"], "edit": ["admin"]}:
            errors.append(f"user profile '{name}' must be admin-managed")
        if "required" in attribute:
            errors.append(
                f"user profile '{name}' must remain optional during account creation"
            )
        validations = attribute.get("validations")
        length = validations.get("length") if isinstance(validations, dict) else None
        maximum = length.get("max") if isinstance(length, dict) else None
        if not (maximum == "64" or (type(maximum) is int and maximum == 64)):
            errors.append(f"user profile '{name}' must have a maximum length of 64")
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
    """Run realm validation with an optional explicit user-profile artifact."""
    if len(argv) > 3:
        print(
            "USAGE: validate_realm.py [realm_path] [user_profile_path]",
            file=sys.stderr,
        )
        return 1
    path = (
        Path(argv[1])
        if len(argv) > 1
        else Path("deploy/keycloak/cwl-realm.json")
    )
    try:
        realm = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID: cannot parse {path}: {exc}", file=sys.stderr)
        return 1

    errors = validate(realm)
    profile_path = (
        Path(argv[2]) if len(argv) > 2 else path.with_name(USER_PROFILE_FILENAME)
    )
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if errors:
            print(f"INVALID: {path}", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
        print(f"INVALID: cannot parse {profile_path}: {exc}", file=sys.stderr)
        return 1
    errors.extend(validate_user_profile(profile))
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
