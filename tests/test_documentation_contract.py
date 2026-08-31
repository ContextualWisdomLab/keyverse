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
    "docs/product-technical-gap-baseline.md",
    "docs/doctoring/product-technical-gap-baseline.md",
    "docs/adr/README.md",
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CHANGELOG.md",
    "docs/product-technical-gap-baseline.md",
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
    "0009-lineageweave-account-derived-rp-claims.md",
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


def test_mcp_authorization_contract_tracks_current_issuer_and_token_rules() -> None:
    """Keep the design-only MCP security contract aligned across its records."""

    adr = _read("docs/adr/0013-mcp-oauth-client-authorization.md")
    doctoring = _read("docs/doctoring/mcp-oauth-authorization.md")
    traceability = _read("docs/TRACEABILITY.md")
    changelog = _read("CHANGELOG.md")
    for text in (adr, doctoring):
        normalized = " ".join(text.split())
        assert "`authorization_response_iss_parameter_supported=true`" in normalized
        assert "simple string comparison" in normalized
        assert "`at+jwt`" in normalized
        assert "`application/at+jwt`" in normalized
        assert "alg=none" in text
        assert "missing `iat`/`jti`" in text
    assert "MCP Authorization 2026-07-28" in traceability
    assert "RFC 9207" in traceability
    assert "mismatch rejects the authorization code" in traceability
    assert "MCP Authorization 2026-07-28" in " ".join(changelog.split())


def test_baseline_carries_mcp_reference_and_current_rp_checklist() -> None:
    """Keep product evidence and README guidance aligned with standards."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    doctoring = _read("docs/doctoring/product-technical-gap-baseline.md")
    readme = _read("README.md")
    for text in (baseline, doctoring):
        assert "RFC 9068" in text
        assert "RFC 9207" in text
    normalized_readme = " ".join(readme.split())
    for requirement in (
        "issuer",
        "signature",
        "allowed algorithm",
        "audience",
        "subject",
        "expiry",
        "iat",
        "exact resource",
        "tenant",
        "purpose",
    ):
        assert requirement in normalized_readme
    assert "before applying its own access-control policy" in normalized_readme


def test_adr_index_contains_governing_identity_decisions() -> None:
    """Keep every indexed architecture decision present and reviewable."""

    index = _read("docs/adr/README.md")
    for adr in GOVERNING_ADRS:
        adr_path = ROOT / "docs" / "adr" / adr
        assert adr_path.is_file(), f"ADR file is missing: {adr}"
        assert f"]({adr})" in index, f"ADR index does not link {adr}"


def test_lineageweave_tenant_contract_is_explicit() -> None:
    """Keep the account-derived tenant mapping deterministic for consumers."""

    adr = _read("docs/adr/0009-lineageweave-account-derived-rp-claims.md")
    operations = _read("docs/operations/oidc-rp-reconciliation.md")
    adr_contract = " ".join(adr.lower().split())
    operations_contract = " ".join(operations.lower().split())
    required_markers = (
        "`org` is the opaque external tenant key",
        "`workspace` is a child namespace under `org`",
        "multiple memberships are not represented by comma-separated values",
        "membership resolution is ambiguous",
        "new token or session renewal",
    )
    for marker in required_markers:
        assert marker in adr_contract, (
            f"ADR-0009 is missing tenant contract marker: {marker}"
        )
        assert marker in operations_contract, (
            "OIDC reconciliation operations are missing tenant contract marker: "
            f"{marker}"
        )


def test_gap_baseline_documents_product_evidence_and_hourly_loop() -> None:
    """Keep the buyer-facing gap baseline current and evidence-classified."""

    baseline = _read("docs/product-technical-gap-baseline.md")
    for heading in (
        "## Product contract",
        "## Evidence classification",
        "## Current live queue snapshot",
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
        assert f"`{classification}`" in baseline, (
            f"baseline is missing evidence class {classification}"
        )
    lowered = baseline.lower()
    assert "never promoted" in lowered
    assert "queued" in lowered
    assert "pending" in lowered
    assert "skipped" in lowered
    assert "review_required" in lowered
    assert "source observation head" in lowered
    assert "does not recursively rename" in lowered


def test_traceability_links_gap_baseline_and_doctoring() -> None:
    """Keep the gap baseline and its doctoring companion discoverable."""

    traceability = _read("docs/TRACEABILITY.md")
    assert "](product-technical-gap-baseline.md)" in traceability
    assert "](doctoring/product-technical-gap-baseline.md)" in traceability
    row = _row_with(traceability, "product and technical gap baseline")
    assert "active-PR" in row
