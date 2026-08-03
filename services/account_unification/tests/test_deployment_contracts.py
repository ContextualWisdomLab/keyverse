"""Static deployment contract tests for Compose and Helm packaging."""
from __future__ import annotations

from pathlib import Path

import yaml


def _repository_root() -> Path:
    """Return the repository root from the account-unification tests."""
    return Path(__file__).resolve().parents[3]


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


def test_helm_can_fail_closed_on_missing_account_image_digest() -> None:
    """Production values can require an immutable account-service image."""
    values = yaml.safe_load(
        (_repository_root() / "helm" / "cwl-idp" / "values.yaml").read_text(
            encoding="utf-8"
        )
    )
    image = values["accountUnification"]["image"]
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
    values = yaml.safe_load(
        (_repository_root() / "helm" / "cwl-idp" / "values.yaml").read_text(
            encoding="utf-8"
        )
    )
    persistence = values["accountUnification"]["persistence"]
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
