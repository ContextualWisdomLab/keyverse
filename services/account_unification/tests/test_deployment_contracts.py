"""Static and executable deployment contract tests for Compose and Helm packaging."""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest
import yaml

from app.config import (
    KEY_PASSWORD_REGISTRATION_API_TOKEN,
    KEY_REGISTRATION_API_TOKEN,
)
from app.kv_store import SqliteKvStore
from tools import seed_config_store


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


@pytest.mark.parametrize(
    ("token_option", "entry_key"),
    [
        ("--registration-token", KEY_REGISTRATION_API_TOKEN),
        ("--password-registration-token", KEY_PASSWORD_REGISTRATION_API_TOKEN),
    ],
    ids=["passwordless-registration", "password-registration"],
)
def test_local_reseed_revokes_omitted_signup_token(
    tmp_path: Path,
    monkeypatch,
    token_option: str,
    entry_key: str,
) -> None:
    """Omitting a signup token on a later seed revokes stale endpoint authority."""
    database_path = tmp_path / f"{entry_key}.db"
    namespace = "account_unification"
    stale_token = f"old-{entry_key}-token"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed_config_store.py",
            "--db",
            str(database_path),
            "--namespace",
            namespace,
            token_option,
            stale_token,
        ],
    )
    assert seed_config_store.main() == 0

    store = SqliteKvStore(str(database_path))
    try:
        assert store.get(namespace, entry_key) == stale_token
    finally:
        store.close()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "seed_config_store.py",
            "--db",
            str(database_path),
            "--namespace",
            namespace,
        ],
    )
    assert seed_config_store.main() == 0

    store = SqliteKvStore(str(database_path))
    try:
        assert store.get(namespace, entry_key) is None
    finally:
        store.close()
