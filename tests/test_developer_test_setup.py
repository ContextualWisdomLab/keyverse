"""Keep developer test instructions aligned with the declared optional extras."""
from __future__ import annotations

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_root_readme_installs_declared_test_extra() -> None:
    """A documented test setup must install dev-only pytest, not production deps."""
    manifest = tomllib.loads(
        (ROOT / "services/account_unification/pyproject.toml").read_text()
    )
    assert any(item.startswith("pytest==") for item in manifest["project"]["optional-dependencies"]["dev"])
    assert not any(item.startswith("pytest") for item in manifest["project"]["dependencies"])
    block = (ROOT / "README.md").read_text().split("## Verify the repository", 1)[1].split("```bash", 1)[1].split("```", 1)[0]
    assert "uv sync --locked --extra dev" in block
    assert "uv run pytest -q" in block
