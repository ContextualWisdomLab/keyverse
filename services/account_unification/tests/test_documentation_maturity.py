"""Guard pinned source maturity, not general natural-language readiness claims."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MAIN = "7d9151cd2da260e118020c938c7358e2ee75d541"
PR103_FEATURES = (
    "hierarchical authorization plane", "start-login helper",
    "programmable application tokens",
)
SCIM_FILES = ("docs/PRD.md", "docs/UML.md", "docs/OPERABILITY.md")
CANDIDATE_FILES = (
    "docs/PRD.md", "docs/UML.md", "docs/OPERABILITY.md",
    "ARCHITECTURE.md", "docs/TRD.md",
)


def _section(text: str, heading: str) -> str:
    """Read one exact level-two section; a missing heading fails closed."""
    marker = heading + "\n"
    assert marker in text, f"missing {heading}"
    return text.split(marker, 1)[1].split("\n## ", 1)[0]


def _status(text: str, marker: str) -> str:
    """Read a complete blank-line-delimited, explicitly labelled paragraph."""
    paragraphs = re.split(r"\n\s*\n", text)
    matches = [" ".join(p.split()) for p in paragraphs if p.startswith(marker)]
    assert len(matches) == 1, f"expected exactly one {marker} paragraph"
    return matches[0]


def _assert_maturity(documents: dict[str, str]) -> None:
    """Enforce labelled paragraphs, scoped capability lists and exact table rows."""
    current = _section(documents["docs/PRD.md"], "## 2. Current protected-main capabilities")
    assert not any(feature in current.lower() for feature in PR103_FEATURES)
    for path in CANDIDATE_FILES:
        paragraph = _status(documents[path], "**PR103 source maturity:**")
        assert "PR #103" in paragraph and "active-PR" in paragraph, path
        assert "unmerged candidate source" in paragraph, path
        assert "not protected-main or deployed readiness" in paragraph, path
        assert all(feature in paragraph.lower() for feature in PR103_FEATURES), path
        assert "implemented-main" not in paragraph, path
        assert not re.search(r"(?:is|are|now|already|remains?) (?:released|implemented|deployed|production-ready)", paragraph, re.I), path
    for path in SCIM_FILES:
        paragraph = _status(documents[path], "**SCIM source maturity:**")
        for value in (MAIN, "implemented-main", "`PUT`", "`PATCH active=false`", "`DELETE`", "shared user-operation lock", "`503`", "not deployed acceptance"):
            assert value in paragraph, (path, value)
        assert "active-PR" not in paragraph, path
        assert not re.search(r"(?:until|after|pending|requires?) (?:protected )?(?:promotion|merge)", paragraph, re.I), path
        assert "is deployed acceptance" not in paragraph, path
        assert not re.search(r"(?:is|are|now|already) (?:deployed|production-ready)", paragraph, re.I), path
        assert "Active PR #113" not in documents[path], path
    trace = documents["docs/TRACEABILITY.md"]
    for marker in ("hierarchical software-unit and menu PDP", "SSO combination scopes", "app start-login helper", "programmable application tokens"):
        rows = [line for line in trace.splitlines() if line.startswith("|") and marker in line]
        assert len(rows) == 1 and rows[0].rstrip().endswith("| active-PR |"), marker
    rows = [line for line in trace.splitlines() if line.startswith("|") and "merge/SCIM PUT/PATCH" in line]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| implemented-main |")
    assert MAIN in rows[0]


def _valid_documents() -> dict[str, str]:
    """Provide a complete otherwise-valid scoped Markdown contract fixture."""
    candidate = (
        "**PR103 source maturity:** PR #103 is active-PR, unmerged candidate source: "
        "hierarchical authorization plane, start-login helper, and programmable "
        "application tokens are not protected-main or deployed readiness."
    )
    scim = (
        f"**SCIM source maturity:** Pinned main `{MAIN}` is implemented-main source: "
        "`PUT`, `PATCH active=false`, and `DELETE` use the shared user-operation lock "
        "and return retryable SCIM `503` on contention. This is not deployed acceptance."
    )
    docs = {path: "# Scoped document\n\n" + candidate + "\n" for path in CANDIDATE_FILES}
    for path in SCIM_FILES:
        docs[path] += "\n" + scim + "\n"
    docs["docs/PRD.md"] = (
        "# Product\n\n## 2. Current protected-main capabilities\n\n"
        "- passwordless WebAuthn;\n- inbound SCIM lifecycle.\n\n"
        "## PR103 candidate capabilities\n\n" + candidate + "\n\n" + scim + "\n"
    )
    docs["docs/TRACEABILITY.md"] = (
        "# Traceability\n\n| Requirement | Evidence | Maturity |\n|---|---|---|\n"
        + "\n".join(f"| {name} | PR #103 local tests | active-PR |" for name in (
            "hierarchical software-unit and menu PDP", "SSO combination scopes", "app start-login helper", "programmable application tokens"))
        + f"\n| merge/SCIM PUT/PATCH shared operation lock | pinned main `{MAIN}` | implemented-main |\n"
    )
    return docs


def test_actual_documents_preserve_pinned_main_and_unmerged_maturity() -> None:
    """Documentation must distinguish source integration from deployed evidence."""
    _assert_maturity({path: (ROOT / path).read_text(encoding="utf-8") for path in (*CANDIDATE_FILES, "docs/TRACEABILITY.md")})


@pytest.mark.parametrize("path", SCIM_FILES)
def test_actual_scim_source_maturity_is_pinned_implementation(path: str) -> None:
    """The current SCIM paragraph must name integrated source, not an open PR."""
    documents = _valid_documents()
    actual = (ROOT / path).read_text(encoding="utf-8")
    scim = _status(actual, "**SCIM source maturity:**")
    documents[path] = documents[path].replace(
        _status(documents[path], "**SCIM source maturity:**"), scim
    )
    _assert_maturity(documents)


def test_actual_scim_traceability_is_not_active_pr() -> None:
    """Actual source integration must be reflected in the exact lock row."""
    documents = _valid_documents()
    documents["docs/TRACEABILITY.md"] = (ROOT / "docs/TRACEABILITY.md").read_text(encoding="utf-8")
    _assert_maturity(documents)


@pytest.mark.parametrize("wrapping", [False, True])
def test_correct_status_paragraphs_pass_with_decimal_versions(wrapping: bool) -> None:
    """Wrapping and ordinary dotted version labels do not change source maturity."""
    documents = _valid_documents()
    for path in CANDIDATE_FILES:
        documents[path] = documents[path].replace("PR #103 is", "LSP 3.18 reference. PR #103 is")
        if wrapping:
            documents[path] = documents[path].replace("unmerged candidate", "unmerged\ncandidate").replace("shared user-operation", "shared\nuser-operation")
    _assert_maturity(documents)


@pytest.mark.parametrize("path", CANDIDATE_FILES)
@pytest.mark.parametrize("mutation", ["same-line-promotion", "wrapped-promotion", "missing-marker", "missing-unmerged", "missing-readiness", "methods-outside-paragraph"])
def test_candidate_maturity_rejects_otherwise_valid_counterexamples(path: str, mutation: str) -> None:
    """Each single contradiction starts with the same accepted fixture corpus."""
    documents = _valid_documents()
    _assert_maturity(documents)
    text = documents[path]
    if mutation in {"same-line-promotion", "wrapped-promotion"}:
        contradiction = " PR #103 is implemented-main and production-ready."
        if mutation == "wrapped-promotion":
            contradiction = "\nPR #103 is\nimplemented-main and production-ready."
        text = text.replace("not protected-main or deployed readiness.", "not protected-main or deployed readiness." + contradiction)
    elif mutation == "missing-marker":
        text = text.replace("**PR103 source maturity:**", "**General note:**")
    elif mutation == "missing-unmerged":
        text = text.replace("unmerged candidate source", "candidate source")
    elif mutation == "missing-readiness":
        text = text.replace("not protected-main or deployed readiness", "protected-main and deployed readiness")
    else:
        text = text.replace("hierarchical authorization plane, start-login helper, and programmable application tokens", "decision design")
        text += "\nHierarchical authorization plane, start-login helper, and programmable application tokens.\n"
    documents[path] = text
    with pytest.raises(AssertionError):
        _assert_maturity(documents)


@pytest.mark.parametrize("path", SCIM_FILES)
@pytest.mark.parametrize("mutation", ["stale-pr", "wrapped-stale", "missing-pin", "missing-method", "deployed-promotion"])
def test_scim_maturity_rejects_otherwise_valid_counterexamples(path: str, mutation: str) -> None:
    """Pinned implementation cannot be demoted to an active PR or a live claim."""
    documents = _valid_documents()
    _assert_maturity(documents)
    text = documents[path]
    if mutation in {"stale-pr", "wrapped-stale"}:
        suffix = " Active PR #113 remains active-PR until protected promotion."
        if mutation == "wrapped-stale":
            suffix = "\nActive PR #113 remains\nactive-PR until protected promotion."
        text = text.replace("not deployed acceptance.", "not deployed acceptance." + suffix)
    elif mutation == "missing-pin":
        text = text.replace(MAIN, "older-main")
    elif mutation == "missing-method":
        text = text.replace("`PATCH active=false`", "deprovisioning")
    else:
        text = text.replace("not deployed acceptance", "is deployed acceptance")
    documents[path] = text
    with pytest.raises(AssertionError):
        _assert_maturity(documents)


@pytest.mark.parametrize("marker", ["hierarchical software-unit and menu PDP", "SSO combination scopes", "app start-login helper", "programmable application tokens", "merge/SCIM PUT/PATCH shared operation lock"])
def test_traceability_mutations_reject_wrong_source_labels(marker: str) -> None:
    """One table-row mutation cannot borrow maturity from an unrelated row."""
    documents = _valid_documents()
    _assert_maturity(documents)
    lines = documents["docs/TRACEABILITY.md"].splitlines()
    for i, line in enumerate(lines):
        if marker in line:
            lines[i] = line.replace("implemented-main", "active-PR") if marker.startswith("merge/") else line.replace("active-PR", "implemented-main")
    documents["docs/TRACEABILITY.md"] = "\n".join(lines)
    with pytest.raises(AssertionError):
        _assert_maturity(documents)


def test_current_capabilities_reject_candidate_feature_even_with_valid_disclaimer() -> None:
    """A later correct future paragraph cannot excuse a current-feature bullet."""
    documents = _valid_documents()
    _assert_maturity(documents)
    documents["docs/PRD.md"] = documents["docs/PRD.md"].replace("- inbound SCIM lifecycle.", "- inbound SCIM lifecycle.\n- hierarchical authorization plane;")
    with pytest.raises(AssertionError):
        _assert_maturity(documents)
