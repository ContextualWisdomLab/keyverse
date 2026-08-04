#!/usr/bin/env python3
"""Replace generator-based OIDC control detection with a direct regex check."""
from __future__ import annotations

from pathlib import Path


TARGET = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "account_unification"
    / "app"
    / "federation.py"
)

OLD_CONSTANTS = """_OAUTH_SCOPE_SET = re.compile(
    r"^[\\x21\\x23-\\x5B\\x5D-\\x7E]+"
    r"(?: [\\x21\\x23-\\x5B\\x5D-\\x7E]+)*$"
)
_PERCENT_ENCODED_CONTROL = re.compile(
"""

NEW_CONSTANTS = """_OAUTH_SCOPE_SET = re.compile(
    r"^[\\x21\\x23-\\x5B\\x5D-\\x7E]+"
    r"(?: [\\x21\\x23-\\x5B\\x5D-\\x7E]+)*$"
)
_RAW_CONTROL = re.compile(r"[\\x00-\\x1F\\x7F]")
_PERCENT_ENCODED_CONTROL = re.compile(
"""

OLD_CHECK = """        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in raw_value
        )
"""

NEW_CHECK = """        or _RAW_CONTROL.search(raw_value) is not None
"""


def replace_once(content: str, old: str, new: str, *, label: str) -> str:
    """Replace one exact generated anchor and fail closed on source drift."""
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return content.replace(old, new, 1)


def main() -> None:
    """Make both control-present and control-absent outcomes directly measurable."""
    content = TARGET.read_text(encoding="utf-8")
    content = replace_once(
        content,
        OLD_CONSTANTS,
        NEW_CONSTANTS,
        label="raw-control regular expression",
    )
    content = replace_once(
        content,
        OLD_CHECK,
        NEW_CHECK,
        label="required-text raw-control check",
    )
    TARGET.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
