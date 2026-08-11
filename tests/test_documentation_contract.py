"""Contract tests for Keyverse's canonical product and architecture documents."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCUMENTS = (
    "DOCUMENTATION.md",
    "docs/PRD.md",
    "docs/TRD.md",
    "ARCHITECTURE.md",
    "docs/UML.md",
    "docs/ERD.md",
    "docs/THREAT_MODEL.md",
    "docs/TEST_STRATEGY.md",
    "docs/OPERABILITY.md",
    "docs/TRACEABILITY.md",
    "docs/adr/README.md",
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CHANGELOG.md",
)
GOVERNING_ADRS = (
    "0001-keycloak-hub.md",
    "0002-passwordless-local-accounts.md",
    "0003-identity-matching.md",
    "0004-desired-state-reconciliation.md",
    "0005-secret-ownership.md",
    "0006-user-operation-lock.md",
    "0007-automation-authority.md",
    "0008-keyverse-rp-authorization-boundary.md",
)


def _read(relative_path: str) -> str:
    """Read one repository document using the canonical UTF-8 encoding."""

    return (ROOT / relative_path).read_text(encoding="utf-8")


def _row_with(text: str, marker: str) -> str:
    """Return the Markdown table row containing ``marker``."""

    for line in text.splitlines():
        if line.startswith("|") and marker in line:
            return line
    raise AssertionError(f"missing Markdown table row containing {marker!r}")


def test_canonical_identity_documents_exist() -> None:
    """Keep product, architecture, safety, and operating memory discoverable."""

    missing = [path for path in REQUIRED_DOCUMENTS if not (ROOT / path).is_file()]
    assert not missing, f"missing canonical documentation: {missing}"


def test_documentation_map_links_cross_cutting_contracts() -> None:
    """Require the documentation map to link every canonical record."""

    documentation = _read("DOCUMENTATION.md")
    for path in REQUIRED_DOCUMENTS[1:]:
        assert f"]({path})" in documentation, (
            f"documentation map does not link {path}"
        )


def test_integrated_features_are_not_left_as_active_pr() -> None:
    """Keep integrated OIDC and hourly changes labelled as protected-main."""

    prd = _read("docs/PRD.md")
    traceability = _read("docs/TRACEABILITY.md")
    assert any("PR #72" in line and "integrated" in line for line in prd.splitlines())
    assert any("PR #74" in line and "integrated" in line for line in prd.splitlines())
    mapper_row = _row_with(traceability, "RP audience/role/org/workspace mapper profile")
    hourly_row = _row_with(traceability, "work-conserving fail-closed hourly API gate")
    assert mapper_row.rstrip().endswith("| implemented-main |")
    assert "PR #72" in mapper_row
    assert hourly_row.rstrip().endswith("| implemented-main |")
    assert "PR #74" in hourly_row


def test_erd_keeps_keycloak_internal_schema_external() -> None:
    """Prevent the logical ERD from claiming ownership of Keycloak internals."""

    erd = _read("docs/ERD.md")
    assert "Keycloak internal schema remains Keycloak-owned" in erd
    assert "does not duplicate or directly edit unsupported Keycloak internal tables" in erd


def test_adr_index_contains_governing_identity_decisions() -> None:
    """Keep every indexed architecture decision present and reviewable."""

    index = _read("docs/adr/README.md")
    for adr in GOVERNING_ADRS:
        adr_path = ROOT / "docs" / "adr" / adr
        assert adr_path.is_file(), f"ADR file is missing: {adr}"
        assert f"]({adr})" in index, f"ADR index does not link {adr}"
