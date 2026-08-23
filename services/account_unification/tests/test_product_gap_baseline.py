"""CI-executed contracts for the live product and technical gap baseline."""

from __future__ import annotations

from pathlib import Path


_OBSERVATION_HEADS = {
    113: "9bd33ee0d00ef1874fd5efabac3462f678a256ed",
    112: "ec34ac14fd38c9c7c463cddbd0ced04b4dfccafd",
    103: "77b8f4ea9995329f1c55b916d110b460b4bc7649",
    101: "50dd9c96cab5c230f775685e8baea939fba390dd",
    100: "a1a65b26c1ebcd3ce964e56b1f0976e132d33cb9",
    83: "dd1ab7444a75342b42e3af013ccda6d1dbfb359d",
}
_OPEN_ISSUES = (114, 102, 99, 71, 2)
_PROTECTED_MAIN = "ce207dfd42975db61c82a5963e206fc1db14ac2b"


def _repository_root() -> Path:
    """Return the Keyverse repository root from this test module."""

    return Path(__file__).resolve().parents[3]


def _read(relative_path: str) -> str:
    """Read one repository document using the canonical UTF-8 encoding."""

    return (_repository_root() / relative_path).read_text(encoding="utf-8")


def _current_refresh(baseline: str) -> str:
    """Return the current dated live-queue refresh, not historical snapshots."""

    marker = "## Live queue refresh — 2026-08-23"
    start = baseline.find(marker)
    if start < 0:
        raise AssertionError("missing 2026-08-23 live queue refresh")
    rest = baseline[start:]
    for stop in (
        "## Live queue refresh — 2026-08-22",
        "## Current capability map",
        "## Live PR inventory",
    ):
        index = rest.find(stop, len(marker))
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


def test_live_queue_records_exact_heads_without_promoting_pending_checks() -> None:
    """Current open PRs keep 40-character heads; skipped Checks stay unverified."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    refresh = " ".join(_current_refresh(baseline).split())
    assert _PROTECTED_MAIN in refresh
    assert "REVIEW_REQUIRED" in refresh
    lowered = refresh.lower()
    assert "never promoted" in lowered
    assert "queued" in lowered
    assert "pending" in lowered
    assert "skipped" in lowered
    assert "independent" in lowered
    assert "blocker" in lowered
    assert "not a merge license" in lowered
    for number, sha in _OBSERVATION_HEADS.items():
        assert f"[#{number}](" in refresh, f"missing live PR #{number}"
        assert sha in refresh, f"PR #{number} is missing observation SHA {sha}"
        assert len(sha) == 40
    assert "observation SHA" in refresh
    assert "inventory commit SHA" in refresh
    assert "not recursively named" in lowered
    assert "creates a later #100 head" in refresh
    assert "competing product PR" in refresh
    assert "G4" in refresh
    assert "zero unresolved" in lowered
    assert "strix" in lowered
    assert "unverified" in lowered
    assert "devin" in lowered
    assert "source-fault" in lowered
    assert "later than the observation SHA" in refresh


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
