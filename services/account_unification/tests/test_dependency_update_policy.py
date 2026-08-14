"""Contracts for atomic dependency updates and dual-lock verification."""

from __future__ import annotations

from pathlib import Path

import yaml


def _repository_root() -> Path:
    """Return the Keyverse repository root from this test module."""
    return Path(__file__).resolve().parents[3]


def _dependabot_document() -> dict[str, object]:
    """Parse and return the repository Dependabot configuration."""
    document = yaml.safe_load(
        (_repository_root() / ".github" / "dependabot.yml").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(document, dict)
    return document


def _pip_update() -> dict[str, object]:
    """Return the account-unification pip update configuration."""
    updates = _dependabot_document().get("updates")
    assert isinstance(updates, list)

    for update in updates:
        if not isinstance(update, dict):
            continue
        if update.get("package-ecosystem") != "pip":
            continue
        if update.get("directory") != "/services/account_unification":
            continue
        return update
    raise AssertionError("account-unification pip update configuration is missing")


def _ci_source() -> str:
    """Return the repository CI workflow source."""
    return (
        _repository_root() / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")


def test_exact_coupled_dependencies_update_atomically() -> None:
    """Packages with exact child pins remain in one version-update pull request."""
    groups = _pip_update().get("groups")
    assert isinstance(groups, dict)

    expected_groups = {
        "pydantic-runtime": {"pydantic", "pydantic-core"},
        "httpx2-runtime": {"httpx2", "httpcore2"},
    }
    for group_name, expected_patterns in expected_groups.items():
        group = groups.get(group_name)
        assert isinstance(group, dict)
        assert group.get("applies-to") == "version-updates"
        patterns = group.get("patterns")
        assert isinstance(patterns, list)
        assert set(patterns) == expected_patterns


def test_ci_proves_both_lock_representations_are_equivalent() -> None:
    """CI exports, compares, installs, and metadata-checks both lock forms."""
    workflow = _ci_source()

    assert "uv sync --locked --extra dev" in workflow
    assert "Verify uv lock dependency metadata" in workflow
    assert "Verify exported hash lock" in workflow
    assert workflow.count("uv pip check") == 2
    assert "uv export" in workflow
    assert "--format requirements.txt" in workflow
    assert "--extra dev" in workflow
    assert "--no-emit-project" in workflow
    assert '--output-file "${exported_requirements}"' in workflow
    assert 'cmp --silent requirements-dev.txt "${exported_requirements}"' in workflow
    assert 'diff --unified requirements-dev.txt "${exported_requirements}"' in workflow
    assert "--require-hashes" in workflow
    assert "-r requirements-dev.txt" in workflow
    assert 'VIRTUAL_ENV="${export_lock_venv}" uv pip install' in workflow
    assert 'VIRTUAL_ENV="${export_lock_venv}" uv pip check' in workflow
