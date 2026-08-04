#!/usr/bin/env python3
"""Make the validated federation provider dispatch structurally exhaustive."""
from __future__ import annotations

from pathlib import Path


TARGET = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "account_unification"
    / "app"
    / "federation.py"
)

OLD_CONSTANT = '_OIDC_PROVIDER_IDS = frozenset({"oidc", "keycloak-oidc"})\n'

OLD_DISPATCH = '''    if registration.provider_id == "saml":
        _validate_saml_registration(registration.provider_config)
    elif registration.provider_id in _OIDC_PROVIDER_IDS:
        _validate_oidc_registration(registration.provider_config)
'''

NEW_DISPATCH = '''    if registration.provider_id == "saml":
        _validate_saml_registration(registration.provider_config)
    else:
        _validate_oidc_registration(registration.provider_config)
'''


def replace_once(content: str, old: str, new: str, *, label: str) -> str:
    """Replace one exact generated anchor and fail closed on source drift."""
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return content.replace(old, new, 1)


def main() -> None:
    """Dispatch every post-validation provider through SAML or OIDC policy."""
    content = TARGET.read_text(encoding="utf-8")
    content = replace_once(
        content,
        OLD_CONSTANT,
        "",
        label="redundant OIDC provider set",
    )
    content = replace_once(
        content,
        OLD_DISPATCH,
        NEW_DISPATCH,
        label="exhaustive provider dispatch",
    )
    TARGET.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
