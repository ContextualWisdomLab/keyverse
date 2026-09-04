"""Queue-bounding contracts for repository-owned GitHub Actions workflows."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_ci_cancels_only_superseded_heads_from_the_same_pull_request() -> None:
    workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")

    assert (
        "group: ${{ github.workflow }}-${{ github.repository }}-"
        "${{ github.event_name == 'pull_request' && "
        "github.event.pull_request.number || github.run_id }}"
    ) in workflow
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow


def test_central_codeql_is_not_duplicated_locally() -> None:
    assert not (WORKFLOWS / "codeql.yml").exists()
