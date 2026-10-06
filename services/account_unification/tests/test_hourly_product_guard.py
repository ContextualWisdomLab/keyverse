"""Behavior tests for the autonomous product patch boundary."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _repository_root() -> Path:
    """Return the Keyverse repository root from this test module."""
    return Path(__file__).resolve().parents[3]


def _load_guard() -> ModuleType:
    """Load the repository-local guard without making scripts a package."""
    path = _repository_root() / "scripts" / "ci" / "hourly_product_guard.py"
    spec = importlib.util.spec_from_file_location("keyverse_hourly_product_guard", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guard_exposes_semantic_command_helper_name() -> None:
    """Repository-owned command execution uses a bounded semantic helper name."""
    guard = _load_guard()

    assert hasattr(guard, "_run_command")
    assert not hasattr(guard, "_run")


def test_guard_allows_product_files_and_rejects_control_plane_files() -> None:
    """The model may edit product slices but never workflow or dependency controls."""
    guard = _load_guard()

    for allowed_path in (
        "services/account_unification/app/federation.py",
        "services/account_unification/tests/test_federation.py",
        "services/account_unification/tools/seed_config_store.py",
        "deploy/templates/oidc-idp-partner.json",
        "docs/operations/federation.md",
        "README.md",
        "CHANGELOG.md",
    ):
        assert guard._path_allowed(allowed_path)

    for forbidden_path in (
        ".github/workflows/ci.yml",
        "scripts/ci/hourly_product_guard.py",
        "services/account_unification/pyproject.toml",
        "services/account_unification/uv.lock",
        "docker-compose.yml",
        "helm/cwl-idp/values.yaml",
        "deploy/keycloak/realm-cwl.json",
        "../outside.txt",
    ):
        assert not guard._path_allowed(forbidden_path)


def test_guard_rejects_deletion_binary_mode_and_control_plane_patches(tmp_path) -> None:
    """Patch metadata cannot delete, rename, link, execute, or cross the boundary."""
    guard = _load_guard()

    safe_patch = tmp_path / "safe.patch"
    safe_patch.write_text(
        "diff --git a/CHANGELOG.md b/CHANGELOG.md\n"
        "--- a/CHANGELOG.md\n"
        "+++ b/CHANGELOG.md\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "diff --git a/services/account_unification/app/federation.py "
        "b/services/account_unification/app/federation.py\n"
        "--- a/services/account_unification/app/federation.py\n"
        "+++ b/services/account_unification/app/federation.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "diff --git a/services/account_unification/tests/test_federation.py "
        "b/services/account_unification/tests/test_federation.py\n"
        "--- a/services/account_unification/tests/test_federation.py\n"
        "+++ b/services/account_unification/tests/test_federation.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n",
        encoding="utf-8",
    )
    assert guard.validate_patch_text(safe_patch) == [
        "CHANGELOG.md",
        "services/account_unification/app/federation.py",
        "services/account_unification/tests/test_federation.py",
    ]

    documentation_only_patch = tmp_path / "documentation-only.patch"
    documentation_only_patch.write_text(
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n",
        encoding="utf-8",
    )
    with pytest.raises(guard.BoundaryError, match="no production code"):
        guard.validate_patch_text(documentation_only_patch)

    unsafe_patches = (
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n",
        "diff --git a/README.md b/README.md\ndeleted file mode 100644\n",
        "diff --git a/README.md b/README.md\nnew file mode 120000\n",
        "diff --git a/README.md b/README.md\nGIT binary patch\n",
        "diff --git a/README.md b/docs/README.md\n",
    )
    for index, patch_text in enumerate(unsafe_patches):
        patch_path = tmp_path / f"unsafe-{index}.patch"
        patch_path.write_text(patch_text, encoding="utf-8")
        with pytest.raises(guard.BoundaryError):
            guard.validate_patch_text(patch_path)


def test_guard_rejects_model_secret_in_raw_and_encoded_forms(
    monkeypatch, tmp_path
) -> None:
    """The generated patch and PR metadata cannot exfiltrate the NIM credential."""
    guard = _load_guard()
    monkeypatch.setenv("KEYVERSE_FORBIDDEN_SECRET", "nim-sensitive-value")

    patch_path = tmp_path / "secret.patch"
    patch_path.write_text(
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+nim-sensitive-value\n",
        encoding="utf-8",
    )
    with pytest.raises(guard.BoundaryError):
        guard.validate_patch_text(patch_path)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "PR_MESSAGE.md").write_text(
        "Safe title\n\nbmltLXNlbnNpdGl2ZS12YWx1ZQ==\n",
        encoding="utf-8",
    )
    with pytest.raises(guard.BoundaryError):
        guard._read_proposal(workspace)


def test_guard_rejects_model_secret_from_one_way_fingerprints(
    monkeypatch, tmp_path
) -> None:
    """Post-model validation detects a leaked token without receiving the secret."""
    guard = _load_guard()
    secret = b"nim-sensitive-value"
    fingerprint = f"{len(secret)}:{hashlib.sha256(secret).hexdigest()}"
    monkeypatch.delenv("KEYVERSE_FORBIDDEN_SECRET", raising=False)
    monkeypatch.setenv("KEYVERSE_FORBIDDEN_SECRET_FINGERPRINT", fingerprint)

    patch_path = tmp_path / "fingerprinted-secret.patch"
    patch_path.write_bytes(b"safe prefix nim-sensitive-value safe suffix")

    with pytest.raises(guard.BoundaryError):
        guard._reject_forbidden_tokens(patch_path.read_bytes(), label="patch")


def test_guard_sanitizes_bounded_pull_request_metadata(tmp_path) -> None:
    """A model-authored title and body are strict UTF-8, bounded, and removed."""
    guard = _load_guard()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    proposal = workspace / "PR_MESSAGE.md"
    proposal.write_text(
        "feat(federation): add recovery signal\n\n"
        "Closes one buyer-visible recovery gap with exact test evidence.\n",
        encoding="utf-8",
    )

    title, body = guard._read_proposal(workspace)

    assert title == "feat(federation): add recovery signal"
    assert "buyer-visible recovery gap" in body
    assert not proposal.exists()
