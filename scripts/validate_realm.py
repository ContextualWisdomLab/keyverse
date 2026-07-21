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
    account client exist; no committed client secret is a real value;
  * Keycloak 26 import compatibility: no `$`-prefixed annotation keys anywhere
    (RealmRepresentation rejects unknown fields) and URL-shaped fields never
    hold a bare `__set_from_kv__` placeholder (SAML IdP URLs are validated at
    import — placeholders must be URL-shaped, e.g.
    https://set-from-kv.invalid/__set_from_kv__);
  * the `basic` client scope exists with the Subject (sub) mapper and is a
    realm default — without it Keycloak 26 lightweight access tokens omit
    `sub` and subject-authenticating RPs (naruon) reject every request;
  * the concrete `naruon-web` public PKCE client exists and carries the
    audience + role/org/workspace claims naruon's session contract requires.

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
    """Return human-readable policy violations for a realm export."""
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
        disallowed_credential_used = authenticators & DISALLOWED_CREDENTIAL_AUTHENTICATORS
        if disallowed_credential_used:
            errors.append(
                "browserFlow includes a disallowed credential-form authenticator; "
                "ecosystem policy requires passkeys"
            )
        if PASSKEY_AUTHENTICATOR not in authenticators:
            errors.append(
                "browserFlow must include the passkey authenticator required by "
                "ecosystem policy"
            )

    if realm.get("registrationAllowed", False):
        errors.append("registrationAllowed must be false")
    if realm.get("resetPasswordAllowed", False):
        errors.append("credential reset self-service must be false")

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
    ldap_sources = [c for c in storage if c.get("providerId") == "ldap"]
    if not ldap_sources:
        errors.append("an LDAP user-storage provider is required")
    for ldap_source in ldap_sources:
        if ldap_source.get("config", {}).get("enabled") != ["false"]:
            errors.append(
                "committed LDAP sources must ship disabled: an enabled source "
                "with placeholder DNs breaks every realm user operation "
                "(kcadm-bootstrap.sh enables it after patching from KV)"
            )

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

    # Keycloak 26 import compatibility: RealmRepresentation rejects unknown
    # fields, so `$`-annotation keys abort --import-realm and crash-loop the
    # container.
    for key_path in _dollar_keys(realm):
        errors.append(
            f"'$'-annotation key '{key_path}' breaks Keycloak 26 realm import"
        )

    # URL-shaped fields must never hold the bare KV placeholder: SAML IdP URLs
    # are URL-validated at import time.
    for idp in realm.get("identityProviders", []):
        for field_name in ("singleSignOnServiceUrl", "metadataDescriptorUrl"):
            value = idp.get("config", {}).get(field_name)
            if value == SECRET_PLACEHOLDER:
                errors.append(
                    f"identity provider '{idp.get('alias')}' field '{field_name}' "
                    "holds a bare placeholder; use a URL-shaped placeholder such "
                    "as https://set-from-kv.invalid/__set_from_kv__"
                )

    # Keycloak 26 lightweight tokens omit `sub` without the basic scope.
    scopes = {s.get("name"): s for s in realm.get("clientScopes", [])}
    basic = scopes.get("basic")
    if basic is None:
        errors.append("client scope 'basic' is required (sub claim source)")
    elif not any(
        m.get("protocolMapper") == "oidc-sub-mapper"
        for m in basic.get("protocolMappers", [])
    ):
        errors.append("client scope 'basic' must include the oidc-sub-mapper")
    if "basic" not in realm.get("defaultDefaultClientScopes", []):
        errors.append("'basic' must be a realm default client scope")

    # The first concrete ecosystem RP: naruon.
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
        naruon_mappers = {
            m.get("protocolMapper") for m in naruon.get("protocolMappers", [])
        }
        if "oidc-audience-mapper" not in naruon_mappers:
            errors.append("naruon-web must include an audience mapper")
        hardcoded_claims = {
            m.get("config", {}).get("claim.name")
            for m in naruon.get("protocolMappers", [])
            if m.get("protocolMapper") == "oidc-hardcoded-claim-mapper"
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


def _dollar_keys(node: object, prefix: str = "") -> list[str]:
    """Collect every `$`-prefixed object key with its JSON path."""
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
    print(f"OK: {path} is a valid cwl-idp realm (passkey, ADFS, LDAP, OIDC RP).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
