"""Static deployment contract tests for Compose and Helm packaging."""
from __future__ import annotations

import tomllib
from pathlib import Path

import yaml


def _repository_root() -> Path:
    """Return the repository root from the account-unification tests."""
    return Path(__file__).resolve().parents[3]


def _helm_values() -> dict:
    """Return parsed Helm values for the cwl-idp chart."""
    return yaml.safe_load(
        (_repository_root() / "helm" / "cwl-idp" / "values.yaml").read_text(
            encoding="utf-8"
        )
    )


def _compose_values() -> dict:
    """Return the standalone Compose document without runtime interpolation."""
    return yaml.safe_load(
        (_repository_root() / "docker-compose.yml").read_text(encoding="utf-8")
    )


def _seed_tool_source() -> str:
    """Return the local configuration seed tool source."""
    return (
        _repository_root()
        / "services"
        / "account_unification"
        / "tools"
        / "seed_config_store.py"
    ).read_text(encoding="utf-8")


def test_compose_persists_account_unification_state() -> None:
    """Standalone restarts retain audit and user-operation lock databases."""
    compose = _compose_values()
    service = compose["services"]["account_unification_service"]
    assert (
        "account_unification_data:/var/lib/account-unification"
        in service["volumes"]
    )
    assert "account_unification_data" in compose["volumes"]


def test_standalone_distribution_has_no_dotenv_credential_template() -> None:
    """Operators are not instructed to materialize repository-local dotenv secrets."""
    assert not (_repository_root() / ".env.example").exists()
    readme = (_repository_root() / "README.md").read_text(encoding="utf-8")
    assert "cp .env.example .env" not in readme


def test_compose_bootstrap_credentials_are_file_mounted_not_interpolated() -> None:
    """Self-bootstrap secrets enter only through the explicit supervisor mount."""
    compose = _compose_values()
    postgres_environment = compose["services"]["idp_database"]["environment"]
    keycloak_environment = compose["services"]["idp_engine"]["environment"]
    keycloak_secrets = compose["services"]["idp_engine"]["secrets"]
    postgres_secrets = compose["services"]["idp_database"]["secrets"]

    assert "POSTGRES_PASSWORD" not in postgres_environment
    assert postgres_environment["POSTGRES_PASSWORD_FILE"] == "/run/secrets/idp_database_password"
    assert "KC_DB_PASSWORD" not in keycloak_environment
    assert "KC_BOOTSTRAP_ADMIN_USERNAME" not in keycloak_environment
    assert "KC_BOOTSTRAP_ADMIN_PASSWORD" not in keycloak_environment
    assert {item["target"] for item in postgres_secrets} == {"idp_database_password"}
    assert {item["target"] for item in keycloak_secrets} == {
        "idp_database_password",
        "idp_bootstrap_admin_username",
        "idp_bootstrap_admin_password",
    }


def test_compose_bootstrap_secret_sources_live_outside_repository() -> None:
    """The standalone profile consumes supervisor/KMS materialized files only."""
    compose = _compose_values()
    secret_files = {
        secret_name: secret_config["file"]
        for secret_name, secret_config in compose["secrets"].items()
    }
    assert secret_files == {
        "idp_database_password": "/run/keyverse-bootstrap/idp_database_password",
        "idp_bootstrap_admin_username": "/run/keyverse-bootstrap/idp_bootstrap_admin_username",
        "idp_bootstrap_admin_password": "/run/keyverse-bootstrap/idp_bootstrap_admin_password",
    }


def test_keycloak_secret_entrypoint_has_bounded_secret_transport() -> None:
    """Keycloak gets only its native process environment immediately before exec."""
    entrypoint_path = _repository_root() / "deploy" / "keycloak" / "secret-entrypoint.sh"
    assert entrypoint_path.is_file()
    source = entrypoint_path.read_text(encoding="utf-8")
    assert "set -eu" in source
    assert "umask 077" in source
    assert "/run/secrets/idp_database_password" in source
    assert "/run/secrets/idp_bootstrap_admin_username" in source
    assert "/run/secrets/idp_bootstrap_admin_password" in source
    assert "export KC_DB_PASSWORD" in source
    assert "export KC_BOOTSTRAP_ADMIN_USERNAME" in source
    assert "export KC_BOOTSTRAP_ADMIN_PASSWORD" in source
    assert 'exec /opt/keycloak/bin/kc.sh "$@"' in source
    assert "cat " not in source
    assert "echo " not in source


def test_helm_can_fail_closed_on_missing_account_image_digest() -> None:
    """Production values can require an immutable account-service image."""
    image = _helm_values()["accountUnification"]["image"]
    assert image["requireDigest"] is False
    template = (
        _repository_root()
        / "helm"
        / "cwl-idp"
        / "templates"
        / "account-unification.yaml"
    ).read_text(encoding="utf-8")
    assert "accountUnification.image.requireDigest" in template
    assert "accountUnification.image.digest is required" in template


def test_helm_mounts_durable_account_unification_storage() -> None:
    """The chart mounts deployment-owned state at the service data path."""
    persistence = _helm_values()["accountUnification"]["persistence"]
    assert persistence["enabled"] is True
    assert persistence["size"]
    template = (
        _repository_root()
        / "helm"
        / "cwl-idp"
        / "templates"
        / "account-unification.yaml"
    ).read_text(encoding="utf-8")
    assert "kind: PersistentVolumeClaim" in template
    assert "mountPath: /var/lib/account-unification" in template


def test_helm_image_tag_matches_package_version() -> None:
    """Unreleased chart metadata cannot advertise an unbuilt package version."""
    pyproject_path = (
        _repository_root()
        / "services"
        / "account_unification"
        / "pyproject.toml"
    )
    project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
    helm_tag = _helm_values()["accountUnification"]["image"]["tag"]
    assert helm_tag == project["version"]


def test_local_seed_avoids_global_temporary_audit_storage() -> None:
    """Development defaults stay inside the project bootstrap directory."""
    seed_tool = _seed_tool_source()
    assert "/tmp/keyverse-account-audit.sqlite3" not in seed_tool
    assert "account_unification_audit.sqlite3" in seed_tool


def test_local_seed_keeps_registration_disabled_by_default() -> None:
    """A developer must explicitly supply the dedicated signup credential."""
    seed_tool = _seed_tool_source()
    assert '"--registration-token"' in seed_tool
    assert 'default=""' in seed_tool
    assert "if not args.registration_token" in seed_tool
