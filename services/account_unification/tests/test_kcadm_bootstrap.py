"""Security, compatibility, and idempotency checks for Keycloak bootstrap."""
from __future__ import annotations

import subprocess
from pathlib import Path


def _bootstrap_path() -> Path:
    """Return the repository's Keycloak Admin CLI bootstrap path."""
    repository_root = Path(__file__).resolve().parents[3]
    return repository_root / "deploy" / "keycloak" / "kcadm-bootstrap.sh"


def _bootstrap_script() -> str:
    """Return the repository's Keycloak Admin CLI bootstrap source."""
    return _bootstrap_path().read_text(encoding="utf-8")


def test_bootstrap_has_valid_bash_syntax() -> None:
    """Reject malformed shell before a deployment attempts bootstrap."""
    subprocess.run(
        ["bash", "-n", str(_bootstrap_path())],
        check=True,
        capture_output=True,
        text=True,
    )


def test_bootstrap_uses_documented_password_environment_variable() -> None:
    """Authenticate with Keycloak's documented KC_CLI_PASSWORD mechanism."""
    script = _bootstrap_script()

    credentials_command = (
        'KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm config credentials'
    )
    assert credentials_command in script
    assert '--user "${ADMIN_USER}"' in script
    assert "--password" not in script
    assert "--token" not in script
    assert "curl -sf" not in script


def test_bootstrap_isolates_kcadm_without_replacing_kv_home() -> None:
    """Scope the temporary HOME to kcadm so later KV commands keep working."""
    script = _bootstrap_script()

    assert "kcadm() {" in script
    assert 'HOME="${_kcadm_home}" kcadm.sh "$@"' in script
    assert "export HOME=" not in script


def test_bootstrap_discards_reusable_admin_password_after_login() -> None:
    """The reusable bootstrap password is unset immediately after login."""
    script = _bootstrap_script()
    credentials_position = script.index(
        'KC_CLI_PASSWORD="${ADMIN_PASS}" kcadm config credentials'
    )
    unset_position = script.index("unset ADMIN_PASS", credentials_position)
    next_bootstrap_step = script.index("# NOTE: external federation", unset_position)

    assert credentials_position < unset_position < next_bootstrap_step


def test_service_client_secret_never_enters_process_arguments() -> None:
    """Patch the client from a private JSON file, never a secret argv value."""
    script = _bootstrap_script()

    assert "umask 077" in script
    assert "SERVICE_SECRET_JSON" in script
    assert (
        'kcadm update "clients/${SVC_CLIENT_UUID}" -r "${REALM}" '
        '-f "${SERVICE_SECRET_JSON}"'
    ) in script
    assert '-s "secret=$(kv get' not in script
    assert "kv put secret/idp/account-unification-client-secret" not in script


def test_protocol_mapper_is_converged_idempotently() -> None:
    """Update one mapper and remove historical duplicates on every run."""
    script = _bootstrap_script()

    assert "MAPPER_IDS=" in script
    assert "MAPPER_ID=" in script
    assert 'if [[ -n "${MAPPER_ID}" ]]' in script
    assert "protocol-mappers/models/${MAPPER_ID}" in script
    assert "tail -n +2" in script
    assert "duplicate_mapper_id" in script
    assert "kcadm delete" in script
