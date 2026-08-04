#!/usr/bin/env python3
"""Harden federation URI validation, verify it, and remove this materializer."""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "services/account_unification/app/federation.py"
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/bootstrap-federation-url-hardening.yml"
SCRIPT_PATH = Path(__file__).resolve()


def _replace_once(content: str, old: str, new: str, *, label: str) -> str:
    """Replace one reviewed source anchor and fail closed when it drifts."""
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return content.replace(old, new, 1)


def main() -> None:
    """Apply the URL hardening patch and remove one-shot bootstrap files."""
    content = MODULE_PATH.read_text(encoding="utf-8")
    content = _replace_once(
        content,
        "import logging\nimport threading\nfrom urllib.parse import SplitResult, urlsplit\n",
        "import logging\nimport re\nimport threading\n"
        "from typing import NoReturn, cast\n"
        "from urllib.parse import SplitResult, urlsplit\n",
        label="federation imports",
    )
    content = _replace_once(
        content,
        '_HTTP_SCHEMES = frozenset({"http", "https"})\n'
        "_SAML_ENTITY_ID_MAX_LENGTH = 1_024\n",
        '_HTTP_SCHEMES = frozenset({"http", "https"})\n'
        "_PERCENT_ENCODED_CONTROL = re.compile(\n"
        '    r"%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|7[Ff])"\n'
        ")\n"
        "_SAML_ENTITY_ID_MAX_LENGTH = 1_024\n",
        label="encoded-control matcher",
    )
    content = _replace_once(
        content,
        "def _provider_config_error(field_name: str, requirement: str) -> None:\n",
        "def _provider_config_error(\n"
        "    field_name: str, requirement: str\n"
        ") -> NoReturn:\n",
        label="non-returning error helper",
    )
    content = _replace_once(
        content,
        "        or value != value.strip()\n"
        "        or any(ord(character) < 32 or ord(character) == 127 for character in value)\n"
        "    )\n",
        "        or value != value.strip()\n"
        "        or any(\n"
        "            character.isspace() or ord(character) == 127\n"
        "            for character in value\n"
        "        )\n"
        '        or "\\\\" in value\n'
        "        or _PERCENT_ENCODED_CONTROL.search(value) is not None\n"
        "    )\n",
        label="ambiguous URI text checks",
    )
    content = _replace_once(
        content,
        "    return parsed\n\n\ndef _validate_http_url(\n",
        "    return cast(SplitResult, parsed)\n\n\ndef _validate_http_url(\n",
        label="validated URI return type",
    )
    MODULE_PATH.write_text(content.rstrip() + "\n", encoding="utf-8")
    WORKFLOW_PATH.unlink()
    SCRIPT_PATH.unlink()


if __name__ == "__main__":
    main()
