"""Guard the boundary between central PR governance and local development."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_retired_local_steward_has_no_source_or_test_owner() -> None:
    """Do not restore an obsolete workflow or tests that require its source."""
    assert not (ROOT / ".github/workflows/hourly-pr-steward.yml").exists()
    assert not (
        ROOT / "services/account_unification/tests/test_hourly_pr_steward.py"
    ).exists()
    assert (ROOT / ".github/workflows/hourly-product-development.yml").is_file()


def test_operations_and_architecture_name_central_pr_governance() -> None:
    """Operator guidance must distinguish central review from local authoring."""
    for path in ("ARCHITECTURE.md", "docs/operations/hourly-product-development.md"):
        text = " ".join((ROOT / path).read_text(encoding="utf-8").split())
        assert "`pr-review-merge-scheduler.yml`" in text, path
        assert "exact-head" in text.lower(), path
        assert (
            "the hourly pr steward advances only trusted same-repository prs"
            not in text.lower()
        ), path
    operations = (ROOT / "docs/operations/hourly-product-development.md").read_text(
        encoding="utf-8"
    )
    assert "| `17 * * * *` |" not in operations
    assert "| `41 * * * *` | `hourly-product-development.yml` |" in operations


def test_publication_races_do_not_depend_on_retired_hourly_steward() -> None:
    """Race recovery must use the surviving protected PR governance path."""
    text = " ".join(
        (ROOT / "docs/operations/hourly-product-development.md")
        .read_text(encoding="utf-8").split()
    )
    sections = text.split("## Publication and race handling", 1)
    assert len(sections) == 2, "publication/race section heading is missing or renamed"
    race_section = sections[1].split("## First activation", 1)[0]
    assert "hourly steward" not in race_section
    assert "protected PR path" in race_section
    assert "central PR governance" in race_section


@pytest.mark.parametrize(
    "document", ["ARCHITECTURE.md", "docs/operations/hourly-product-development.md"]
)
def test_ownership_regression_rejects_restored_steward_prose(
    tmp_path, monkeypatch, document
) -> None:
    """Contradictory ownership must fail even when central guidance remains."""
    paths = ("ARCHITECTURE.md", "docs/operations/hourly-product-development.md")
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / path).read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    # The unchanged positive contract must pass before the contradiction is added.
    test_operations_and_architecture_name_central_pr_governance()
    target = tmp_path / document
    target.write_text(
        target.read_text(encoding="utf-8")
        + "\nThe hourly PR steward advances only trusted same-repository PRs "
        "with exact-head approvals and required Checks.\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError):
        test_operations_and_architecture_name_central_pr_governance()
