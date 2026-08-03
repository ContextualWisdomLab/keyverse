"""Static security and compatibility checks for the Keycloak bootstrap script."""
from __future__ import annotations

from pathlib import Path


def _bootstrap_script() -> str:
    """Return the repository's Keycloak Admin CLI bootstrap source."""
    repository_root = Path(__file__).resolve().parents[3]
    return (
        repository_root / "deploy" / "keycloak" / "kcadm-bootstrap.sh"
    ).read_text(encoding="utf-8")


def test_bootstrap_uses_documented_password_environment_variable() -> None:
    """Authenticate with Keycloak's documented KC_CLI_PASSWORD mechanism."""
    script = _bootstrap_script()

    credentials_command = (
        'KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm.sh config credentials'
    )
    assert credentials_command in script
    assert '--user "${ADMIN_USER}"' in script
    assert "--password" not in script
    assert "--token" not in script
    assert "curl -sf" not in script


def test_bootstrap_discards_reusable_admin_password_after_login() -> None:
    """The reusable bootstrap password is unset immediately after login."""
    script = _bootstrap_script()
    credentials_position = script.index(
        'KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm.sh config credentials'
    )
    unset_position = script.index("unset ADMIN_PASS", credentials_position)
    next_bootstrap_step = script.index("# NOTE: external federation", unset_position)

    assert credentials_position < unset_position < next_bootstrap_step
