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


def test_ci_admits_only_useful_pull_request_events_and_skips_drafts() -> None:
    workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")

    assert "types: [opened, synchronize, reopened, ready_for_review]" in workflow
    assert "converted_to_draft" not in workflow
    assert "closed" not in workflow
    admission = (
        "if: ${{ github.event_name != 'pull_request' || "
        "github.event.pull_request.draft == false }}"
    )
    assert workflow.count(admission) == 3


def test_central_codeql_is_not_duplicated_locally() -> None:
    assert not (WORKFLOWS / "codeql.yml").exists()
