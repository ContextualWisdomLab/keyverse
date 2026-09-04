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
    compose = yaml.safe_load(
        (_repository_root() / "docker-compose.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["account_unification_service"]
    assert (
        "account_unification_data:/var/lib/account-unification"
        in service["volumes"]
    )
    assert "account_unification_data" in compose["volumes"]


def test_keycloak_import_packages_realm_and_profile_contracts() -> None:
    """Keep Compose and Helm compatible with Keycloak's separate profile API."""
    root = _repository_root()
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    engine = compose["services"]["idp_engine"]
    assert engine["build"] == {"context": "./deploy/keycloak", "dockerfile": "Dockerfile"}
    assert engine["image"] == "cwl-idp/keycloak:local"
    dockerfile = (root / "deploy" / "keycloak" / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM quay.io/keycloak/keycloak:26.3.2@sha256:" in dockerfile
    assert "COPY cwl-realm.json /opt/keycloak/data/import/cwl-realm.json" in dockerfile
    assert "COPY lineageweave-user-profile.json" in dockerfile
    assert "COPY --chmod=755 reconcile-lineageweave-user-profile.sh" in dockerfile
    assert "\nUSER 1000\n" in dockerfile
    bootstrap_script = (
        root / "deploy" / "keycloak" / "reconcile-lineageweave-user-profile.sh"
    ).read_text(encoding="utf-8")
    assert "/opt/keycloak/bin/kcadm.sh" in bootstrap_script
    profile = compose["services"]["idp_profile_bootstrap"]
    assert profile["depends_on"]["idp_engine"]["condition"] == "service_healthy"
    assert profile["entrypoint"] == ["/opt/keycloak/reconcile-lineageweave-user-profile.sh"]
    service = compose["services"]["account_unification_service"]
    assert (
        service["depends_on"]["idp_profile_bootstrap"]["condition"]
        == "service_completed_successfully"
    )

    keycloak = (
        root / "helm" / "cwl-idp" / "templates" / "keycloak.yaml"
    ).read_text(encoding="utf-8")
    assert _helm_values()["keycloak"]["realmImport"]["fileName"] == "cwl-realm.json"
    assert "key: {{ .Values.keycloak.realmImport.fileName }}" in keycloak
    assert "path: cwl-realm.json" in keycloak


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
