#!/usr/bin/env python3
"""Remove a generator-only branch from OIDC scope-set validation."""
from __future__ import annotations

from pathlib import Path


TARGET = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "account_unification"
    / "app"
    / "federation.py"
)

OLD_CONSTANT = (
    '_OAUTH_SCOPE_TOKEN = re.compile(r"^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$")\n'
)
NEW_CONSTANT = (
    '_OAUTH_SCOPE_SET = re.compile(\n'
    '    r"^[\\x21\\x23-\\x5B\\x5D-\\x7E]+"\n'
    '    r"(?: [\\x21\\x23-\\x5B\\x5D-\\x7E]+)*$"\n'
    ')\n'
)

OLD_VALIDATION = '''    valid = (
        all(tokens)
        and all(_OAUTH_SCOPE_TOKEN.fullmatch(token) for token in tokens)
        and len(tokens) == len(set(tokens))
        and tokens.count("openid") == 1
    )
'''

NEW_VALIDATION = '''    valid = (
        _OAUTH_SCOPE_SET.fullmatch(raw_scope) is not None
        and len(tokens) == len(set(tokens))
        and tokens.count("openid") == 1
    )
'''


def replace_once(content: str, old: str, new: str, *, label: str) -> str:
    """Replace one exact generated anchor and fail closed on source drift."""
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return content.replace(old, new, 1)


def main() -> None:
    """Use one whole-scope regex so every policy branch is directly testable."""
    content = TARGET.read_text(encoding="utf-8")
    content = replace_once(
        content,
        OLD_CONSTANT,
        NEW_CONSTANT,
        label="OAuth scope-set regular expression",
    )
    content = replace_once(
        content,
        OLD_VALIDATION,
        NEW_VALIDATION,
        label="OAuth scope-set validation",
    )
    TARGET.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
