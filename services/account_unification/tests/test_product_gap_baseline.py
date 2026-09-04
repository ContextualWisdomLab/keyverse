"""CI-executed contracts for the live product and technical gap baseline."""

from __future__ import annotations

import re
from pathlib import Path


_OPEN_ISSUES = (114, 102, 99, 71, 2)
_CURRENT_QUEUE_MARKER = "## Current live queue snapshot"


def _repository_root() -> Path:
    """Return the Keyverse repository root from this test module."""

    return Path(__file__).resolve().parents[3]


def _read(relative_path: str) -> str:
    """Read one repository document using the canonical UTF-8 encoding."""

    return (_repository_root() / relative_path).read_text(encoding="utf-8")


def _current_refresh(baseline: str) -> str:
    """Return the explicitly designated current queue snapshot."""

    start = baseline.find(_CURRENT_QUEUE_MARKER)
    if start < 0:
        raise AssertionError("missing explicit current live queue snapshot")
    rest = baseline[start:]
    for stop in (
        "## Live queue refresh — 2026-08-23",
        "## Historical queue snapshot",
        "## Current capability map",
        "## Live PR inventory",
    ):
        index = rest.find(stop, len(_CURRENT_QUEUE_MARKER))
        if index > 0:
            return rest[:index]
    return rest


def _gap_section(baseline: str, heading: str, terminator: str) -> str:
    """Return one gap-register section bounded by the next heading."""

    start = baseline.find(heading)
    if start < 0:
        raise AssertionError(f"missing gap heading: {heading}")
    end = baseline.find(terminator, start + len(heading))
    if end < 0:
        return baseline[start:]
    return baseline[start:end]


def test_gap_baseline_keeps_required_product_and_loop_headings() -> None:
    """CI must see the buyer-facing baseline sections on every account-unification run."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    for heading in (
        "## Product contract",
        "## Evidence classification",
        "## Live PR inventory",
        "## Open Issue inventory",
        "## Gap register and buyer-visible order",
        "## Hourly loop contract",
    ):
        assert heading in baseline, f"missing baseline heading: {heading}"
    for classification in (
        "implemented-main",
        "active-PR",
        "active-issue",
        "accepted-contract",
        "gap-not-claimed",
    ):
        assert f"`{classification}`" in baseline


def test_live_queue_uses_explicit_current_snapshot_without_promoting_pending_checks() -> None:
    """Current evidence stays explicit while nonterminal or stale results stay unverified."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    refresh = " ".join(_current_refresh(baseline).split())
    lowered = refresh.lower()

    assert "[#100](" in refresh
    assert "source observation head" in lowered
    assert len(re.findall(r"`[0-9a-f]{40}`", refresh)) >= 2
    assert "1 approving review" in lowered
    assert "dismiss stale reviews" in lowered
    assert "review-thread resolution" in lowered
    assert "organization admin bypass" in lowered
    assert "must not be used" in lowered
    assert "queued" in lowered
    assert "pending" in lowered
    assert "skipped" in lowered
    assert "never promoted" in lowered
    assert "independent" in lowered
    assert "blocker" in lowered
    assert "not a merge license" in lowered
    assert "observation" in lowered
    assert "does not recursively rename" in lowered


def test_open_issue_inventory_and_gap_order_match_the_live_queue() -> None:
    """Issues stay inventoried; G1/G8 no longer treat closed PRs as open work."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    issues = _gap_section(
        baseline,
        "## Open Issue inventory",
        "## Gap register and buyer-visible order",
    )
    for number in _OPEN_ISSUES:
        assert f"[#{number}](" in issues, f"missing open issue #{number}"
    gap_g1 = " ".join(_gap_section(baseline, "### G1 —", "### G2 —").split())
    assert "#112" in gap_g1
    assert "#101" in gap_g1
    assert "closed" in gap_g1.lower()
    assert "not a current open-PR" in gap_g1
    gap_g8 = " ".join(_gap_section(baseline, "### G8 —", "### G4 —").split())
    assert (
        "not an open Keyverse PR" in gap_g8
        or "no longer an open Keyverse PR" in gap_g8
    )
    gap_g0 = _gap_section(baseline, "### G0 —", "### G1 —")
    assert "`active-PR`" in gap_g0
    gap_g4 = _gap_section(baseline, "### G4 —", "### G5 —")
    assert "#113" in gap_g4
    assert "`active-PR`" in gap_g4


def test_traceability_and_documentation_map_link_the_gap_baseline() -> None:
    """Operators must reach the baseline from the map and the evidence matrix."""

    documentation = _read("DOCUMENTATION.md")
    assert "](docs/product-technical-gap-baseline.md)" in documentation
    traceability = _read("docs/TRACEABILITY.md")
    assert "](product-technical-gap-baseline.md)" in traceability
    assert "](doctoring/product-technical-gap-baseline.md)" in traceability


def test_hourly_loop_keeps_github_workflows_separate_from_copilot_token() -> None:
    """The documented loop must not reuse Copilot review credentials."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    loop = _gap_section(
        baseline,
        "## Hourly loop contract",
        "## Standards interpretation and design tooling boundary",
    )
    assert "Hourly PR steward" in loop
    assert "Hourly product development" in loop
    assert "COPILOT_GITHUB_TOKEN" in loop
    assert "must not use `COPILOT_GITHUB_TOKEN`" in loop
    steward = _read(".github/workflows/hourly-pr-steward.yml")
    product = _read(".github/workflows/hourly-product-development.yml")
    assert "COPILOT_GITHUB_TOKEN" not in steward
    assert "COPILOT_GITHUB_TOKEN" not in product
    assert 'cron: "17 * * * *"' in steward
    assert 'cron: "41 * * * *"' in product
