"""Static contract tests for the hourly protected PR steward."""
from __future__ import annotations

from pathlib import Path


def _workflow_source() -> str:
    """Return the repository's hourly PR stewardship workflow source."""
    repository_root = Path(__file__).resolve().parents[3]
    return (
        repository_root / ".github" / "workflows" / "hourly-pr-steward.yml"
    ).read_text(encoding="utf-8")


def _permissions_block(source: str, marker: str, terminator: str) -> str:
    """Return one indentation-sensitive workflow permissions block."""
    block_start = source.index(marker)
    block_end = source.index(terminator, block_start)
    return source[block_start:block_end]


def test_hourly_steward_runs_once_per_hour_with_bounded_concurrency() -> None:
    """The schedule is hourly and overlapping steward runs are serialized."""
    workflow = _workflow_source()
    assert 'cron: "17 * * * *"' in workflow
    assert "group: hourly-pr-steward" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "timeout-minutes: 10" in workflow


def test_hourly_steward_uses_read_only_workflow_token_defaults() -> None:
    """Only the steward job receives its narrowly required write scopes."""
    workflow = _workflow_source()
    top_level_permissions = _permissions_block(
        workflow,
        "permissions:\n",
        "\nconcurrency:",
    )
    job_permissions = _permissions_block(
        workflow,
        "    permissions:\n",
        "    steps:",
    )

    assert "contents: read" in top_level_permissions
    assert "write" not in top_level_permissions
    assert "contents: write" in job_permissions
    assert "pull-requests: write" in job_permissions
    assert "checks: read" in job_permissions
    assert "security-events: write" not in workflow
    assert "actions: write" not in workflow


def test_hourly_steward_is_fail_closed_on_trust_review_and_checks() -> None:
    """Untrusted, unapproved, pending, or failed pull requests remain untouched."""
    workflow = _workflow_source()
    assert 'head_owner" != "ContextualWisdomLab"' in workflow
    assert 'trusted_author" != "true"' in workflow
    assert 'review_decision" != "APPROVED"' in workflow
    assert 'gh pr checks "$number" --repo "$REPOSITORY" --required' in workflow
    assert "--admin" not in workflow


def test_hourly_steward_invalidates_old_evidence_after_branch_update() -> None:
    """A branch update exits the current iteration before merging stale evidence."""
    workflow = _workflow_source()
    update_position = workflow.index("gh pr update-branch")
    continue_position = workflow.index("continue", update_position)
    approval_position = workflow.index('review_decision" != "APPROVED"')
    assert update_position < continue_position < approval_position


def test_hourly_steward_binds_auto_merge_to_the_checked_head() -> None:
    """GitHub auto-merge is armed only for the enumerated exact head SHA."""
    workflow = _workflow_source()
    assert '--auto \\' in workflow
    assert '--squash \\' in workflow
    assert '--match-head-commit "$head_sha"' in workflow
