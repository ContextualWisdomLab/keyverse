"""RED/GREEN contracts for hierarchical authorization attributes and inheritance."""
from __future__ import annotations

import pytest

from app.errors import AuthorizationPolicyError
from app.org_authorization import (
    LINEAGEWEAVE_RESERVED_CLAIM_NAMES,
    ORG_PATH_LEVELS,
    AuthorizationDecisionCode,
    AuthorizationEffect,
    AuthorizationGrant,
    AssignmentSnapshot,
    SsoCombinationScope,
    decide_menu,
    decide_software_unit,
    decide_sso_combination,
    parse_org_path,
    validate_grant,
)


PERSON_PATH = (
    "/group_company/acme/legal_entity/holdco/business_unit/sales/"
    "team/alpha/person/jdoe"
)
SUBSIDIARY_PERSON_PATH = (
    "/group_company/acme/legal_entity/subsidiary/business_unit/ops/"
    "team/beta/person/jane"
)


def _snapshot(org_path: str = PERSON_PATH, **updates) -> AssignmentSnapshot:
    """Return one Orgmetra assignment snapshot bound to a Keyverse subject."""
    values = {
        "keyverse_subject": "sub-jdoe-opaque",
        "org_path": org_path,
        "assignment_record_id": "assignment-record-77",
        "request_attributes": {"purpose": "hr-review"},
    }
    values.update(updates)
    return AssignmentSnapshot.model_validate(values)


def _software_grant(
    org_path: str,
    *,
    grant_key: str = "acme-naruon",
    software_unit_id: str = "naruon-web",
    effect_code: str = "allow",
) -> AuthorizationGrant:
    """Return one software-unit grant at an org node."""
    return AuthorizationGrant(
        grant_key=grant_key,
        tenant_deployment_id="default-deployment",
        grant_scope_code="software_unit",
        org_path=org_path,
        software_unit_id=software_unit_id,
        effect_code=effect_code,
        actor_identity_id="operator-ida",
    )


def _menu_grant(
    org_path: str,
    *,
    grant_key: str = "acme-naruon-invoices",
    menu_path: str = "/invoices",
    effect_code: str = "allow",
    capability_codes: list[str] | None = None,
    attribute_constraints: dict[str, str] | None = None,
) -> AuthorizationGrant:
    """Return one menu grant with optional ABAC constraints."""
    return AuthorizationGrant(
        grant_key=grant_key,
        tenant_deployment_id="default-deployment",
        grant_scope_code="menu",
        org_path=org_path,
        software_unit_id="naruon-web",
        menu_path=menu_path,
        effect_code=effect_code,
        capability_codes=capability_codes or (["menu.read"] if effect_code == "allow" else []),
        attribute_constraints=attribute_constraints or {},
        actor_identity_id="operator-ida",
    )


def test_org_path_levels_are_hierarchical_and_not_lineageweave_names() -> None:
    """Hierarchical attributes stay distinct from PR #100 claim names."""
    parsed = parse_org_path(PERSON_PATH)
    assert [level for level, _identifier in parsed.segments] == list(ORG_PATH_LEVELS)
    attributes = parsed.attribute_map()
    assert set(LINEAGEWEAVE_RESERVED_CLAIM_NAMES).isdisjoint(attributes)
    assert attributes["group_company"] == "acme"
    assert attributes["org_path"] == PERSON_PATH


def test_ancestor_allow_inherits_to_person_unless_restricted() -> None:
    """A group-company allow applies to descendant persons."""
    grants = [_software_grant("/group_company/acme")]
    decision = decide_software_unit(grants, _snapshot(), "naruon-web")
    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.decision_code is AuthorizationDecisionCode.INHERITED_ALLOW
    assert decision.inherited is True
    assert decision.winning_org_path == "/group_company/acme"
    assert decision.pep_enforcement_required is True


def test_more_specific_deny_restricts_inherited_allow() -> None:
    """A legal-entity deny overrides an ancestor allow for that subtree only."""
    grants = [
        _software_grant("/group_company/acme", grant_key="acme-allow"),
        _software_grant(
            "/group_company/acme/legal_entity/subsidiary",
            grant_key="subsidiary-deny",
            effect_code="deny",
        ),
    ]
    holdco = decide_software_unit(grants, _snapshot(PERSON_PATH), "naruon-web")
    subsidiary = decide_software_unit(
        grants, _snapshot(SUBSIDIARY_PERSON_PATH, keyverse_subject="sub-jane"), "naruon-web"
    )
    assert holdco.effect is AuthorizationEffect.ALLOW
    assert subsidiary.effect is AuthorizationEffect.DENY
    assert subsidiary.decision_code is AuthorizationDecisionCode.INHERITED_DENY


def test_absent_grant_is_default_deny() -> None:
    """No matching software-unit grant fails closed."""
    decision = decide_software_unit([], _snapshot(), "naruon-web")
    assert decision.effect is AuthorizationEffect.DENY
    assert decision.decision_code is AuthorizationDecisionCode.DEFAULT_DENY


def test_exact_path_allow_is_specific_not_inherited() -> None:
    """A grant at the person's node is a specific allow."""
    grants = [_software_grant(PERSON_PATH, grant_key="person-allow")]
    decision = decide_software_unit(grants, _snapshot(), "naruon-web")
    assert decision.decision_code is AuthorizationDecisionCode.SPECIFIC_ALLOW
    assert decision.inherited is False


def test_unrelated_software_unit_does_not_authorize() -> None:
    """Software-unit ACL is exact per relying party."""
    grants = [_software_grant("/group_company/acme", software_unit_id="clearfolio-web")]
    decision = decide_software_unit(grants, _snapshot(), "naruon-web")
    assert decision.effect is AuthorizationEffect.DENY


def test_menu_requires_software_unit_allow() -> None:
    """Menu ABAC/RBAC cannot bypass a software-unit deny."""
    grants = [_menu_grant("/group_company/acme")]
    decision = decide_menu(grants, _snapshot(), "naruon-web", "/invoices")
    assert decision.effect is AuthorizationEffect.DENY
    assert decision.decision_code is AuthorizationDecisionCode.SOFTWARE_UNIT_DENIED


def test_menu_inherit_and_more_specific_menu_deny() -> None:
    """Menu grants inherit down the tree and more-specific menu paths restrict."""
    grants = [
        _software_grant("/group_company/acme"),
        _menu_grant(
            "/group_company/acme",
            capability_codes=["menu.read", "menu.approve"],
        ),
        _menu_grant(
            "/group_company/acme/legal_entity/subsidiary",
            grant_key="payroll-deny",
            menu_path="/invoices/payroll",
            effect_code="deny",
        ),
    ]
    invoices = decide_menu(grants, _snapshot(), "naruon-web", "/invoices/approve")
    payroll = decide_menu(
        grants,
        _snapshot(SUBSIDIARY_PERSON_PATH, keyverse_subject="sub-jane"),
        "naruon-web",
        "/invoices/payroll",
    )
    assert invoices.effect is AuthorizationEffect.ALLOW
    assert invoices.capability_codes == ["menu.read", "menu.approve"]
    assert invoices.inherited is True
    assert payroll.effect is AuthorizationEffect.DENY
    assert payroll.capability_codes == []


def test_menu_abac_constraint_mismatch_denies() -> None:
    """ABAC constraints are evaluated before remaining menu capabilities."""
    grants = [
        _software_grant("/group_company/acme"),
        _menu_grant(
            "/group_company/acme",
            attribute_constraints={"purpose": "hr-review", "sensitivity": "internal"},
        ),
    ]
    allowed = decide_menu(
        grants,
        _snapshot(request_attributes={"purpose": "hr-review", "sensitivity": "internal"}),
        "naruon-web",
        "/invoices",
    )
    denied = decide_menu(
        grants,
        _snapshot(request_attributes={"purpose": "hr-review"}),
        "naruon-web",
        "/invoices",
    )
    assert allowed.effect is AuthorizationEffect.ALLOW
    assert denied.effect is AuthorizationEffect.DENY
    assert denied.decision_code is AuthorizationDecisionCode.ATTRIBUTE_MISMATCH


def test_sso_combination_requires_every_member_allowed() -> None:
    """One Keyverse session may cover a combination only when every RP is allowed."""
    grants = [
        _software_grant("/group_company/acme", grant_key="naruon-allow"),
        _software_grant(
            "/group_company/acme",
            grant_key="clearfolio-allow",
            software_unit_id="clearfolio-web",
        ),
    ]
    combination = SsoCombinationScope(
        combination_name="finance-suite",
        tenant_deployment_id="default-deployment",
        software_unit_ids=["naruon-web", "clearfolio-web"],
        actor_identity_id="operator-ida",
    )
    allowed = decide_sso_combination(grants, _snapshot(), combination)
    denied = decide_sso_combination(
        grants,
        _snapshot(),
        combination.model_copy(update={"software_unit_ids": ["naruon-web", "sdp-web"]}),
    )
    assert allowed.effect is AuthorizationEffect.ALLOW
    assert allowed.decision_code is AuthorizationDecisionCode.COMBINATION_ALLOW
    assert denied.effect is AuthorizationEffect.DENY
    assert denied.decision_code is AuthorizationDecisionCode.COMBINATION_DENIED


def test_reserved_lineageweave_names_are_rejected_on_org_and_attributes() -> None:
    """role/org/workspace cannot be smuggled in as hierarchical names."""
    with pytest.raises(AuthorizationPolicyError, match="reserved"):
        parse_org_path("/org/acme")
    with pytest.raises(AuthorizationPolicyError, match="LineageWeave"):
        validate_grant(
            _menu_grant(
                "/group_company/acme",
                attribute_constraints={"role": "member"},
            )
        )


@pytest.mark.parametrize(
    "raw_path",
    [
        "",
        "group_company/acme",
        "/group_company/acme/",
        "/group_company",
        "/legal_entity/holdco",
        "/group_company/acme/team/alpha",
        "/group_company/acme/legal_entity/holdco/business_unit/sales/"
        "team/alpha/person/jdoe/extra/layer",
        "/group_company/ACME",
    ],
)
def test_invalid_org_paths_fail_closed(raw_path: str) -> None:
    """Malformed or skipped org levels never authorize."""
    with pytest.raises(AuthorizationPolicyError):
        parse_org_path(raw_path)


def test_invalid_grant_shapes_fail_closed() -> None:
    """Closed grant policy rejects scope, effect, and deny-payload mistakes."""
    with pytest.raises(AuthorizationPolicyError, match="grant_scope"):
        validate_grant(_software_grant("/group_company/acme").model_copy(
            update={"grant_scope_code": "wildcard"}
        ))
    with pytest.raises(AuthorizationPolicyError, match="effect_code"):
        validate_grant(_software_grant("/group_company/acme").model_copy(
            update={"effect_code": "maybe"}
        ))
    with pytest.raises(AuthorizationPolicyError, match="menu_path"):
        validate_grant(_software_grant("/group_company/acme").model_copy(
            update={"menu_path": "/invoices"}
        ))
    with pytest.raises(AuthorizationPolicyError, match="attribute_constraints"):
        validate_grant(_software_grant("/group_company/acme", effect_code="deny").model_copy(
            update={"attribute_constraints": {"purpose": "hr-review"}}
        ))
    with pytest.raises(AuthorizationPolicyError, match="capability_codes"):
        validate_grant(_software_grant("/group_company/acme", effect_code="deny").model_copy(
            update={"capability_codes": ["menu.read"]}
        ))
    with pytest.raises(AuthorizationPolicyError, match="menu grants require"):
        validate_grant(_menu_grant("/group_company/acme").model_copy(update={"menu_path": None}))
    with pytest.raises(AuthorizationPolicyError, match="deny grants cannot"):
        validate_grant(
            _menu_grant(
                "/group_company/acme",
                effect_code="deny",
                capability_codes=["menu.read"],
            )
        )


def test_specific_deny_and_menu_default_deny() -> None:
    """Exact-node deny and missing menu grants remain fail-closed."""
    grants = [
        _software_grant(PERSON_PATH, grant_key="person-deny", effect_code="deny"),
    ]
    software = decide_software_unit(grants, _snapshot(), "naruon-web")
    assert software.decision_code is AuthorizationDecisionCode.SPECIFIC_DENY
    menu_grants = [_software_grant("/group_company/acme")]
    menu = decide_menu(menu_grants, _snapshot(), "naruon-web", "/settings")
    assert menu.decision_code is AuthorizationDecisionCode.DEFAULT_DENY


def test_closed_slug_capability_and_attribute_bounds() -> None:
    """Hostile slugs, capabilities, and ABAC values are rejected."""
    from app.org_authorization import (
        parse_menu_path,
        validate_capability_codes,
        validate_combination,
        validate_snapshot,
        validate_slug,
    )

    with pytest.raises(AuthorizationPolicyError):
        validate_slug("Not a slug", field_name="grant_key")
    with pytest.raises(AuthorizationPolicyError):
        validate_capability_codes(["menu.read"] * 17)
    with pytest.raises(AuthorizationPolicyError):
        validate_capability_codes(["BAD"])
    with pytest.raises(AuthorizationPolicyError):
        validate_capability_codes(["menu.read", "menu.read"])
    with pytest.raises(AuthorizationPolicyError):
        parse_menu_path("")
    with pytest.raises(AuthorizationPolicyError):
        parse_menu_path("invoices")
    with pytest.raises(AuthorizationPolicyError):
        parse_menu_path("/invoices/")
    with pytest.raises(AuthorizationPolicyError):
        parse_menu_path("/" + "/".join(f"seg{index}" for index in range(9)))
    with pytest.raises(AuthorizationPolicyError):
        parse_menu_path("x" * 257)
    with pytest.raises(AuthorizationPolicyError):
        parse_org_path("x" * 513)
    with pytest.raises(AuthorizationPolicyError):
        parse_org_path(None)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationPolicyError, match="purpose"):
        validate_grant(
            _menu_grant("/group_company/acme", attribute_constraints={"department": "sales"})
        )
    with pytest.raises(AuthorizationPolicyError, match="non-empty"):
        validate_grant(
            _menu_grant("/group_company/acme", attribute_constraints={"purpose": "  "})
        )
    with pytest.raises(AuthorizationPolicyError, match="closed bound"):
        validate_grant(
            _menu_grant(
                "/group_company/acme",
                attribute_constraints={"purpose": "p" * 65},
            )
        )
    with pytest.raises(AuthorizationPolicyError, match="between 2 and 16"):
        validate_combination(
            SsoCombinationScope(
                combination_name="solo",
                tenant_deployment_id="default-deployment",
                software_unit_ids=["naruon-web"],
                actor_identity_id="operator-ida",
            )
        )
    with pytest.raises(AuthorizationPolicyError, match="between 2 and 16"):
        validate_combination(
            SsoCombinationScope(
                combination_name="too-many",
                tenant_deployment_id="default-deployment",
                software_unit_ids=[f"app-{index:02d}" for index in range(17)],
                actor_identity_id="operator-ida",
            )
        )
    with pytest.raises(AuthorizationPolicyError, match="deny grants cannot"):
        validate_grant(
            _menu_grant(
                "/group_company/acme",
                effect_code="deny",
                attribute_constraints={"purpose": "hr-review"},
            )
        )
    with pytest.raises(AuthorizationPolicyError, match="unique"):
        validate_combination(
            SsoCombinationScope(
                combination_name="dupes",
                tenant_deployment_id="default-deployment",
                software_unit_ids=["naruon-web", "naruon-web"],
                actor_identity_id="operator-ida",
            )
        )
    with pytest.raises(AuthorizationPolicyError, match="opaque"):
        validate_snapshot(_snapshot(keyverse_subject="has space"))
    omitted = validate_snapshot(
        AssignmentSnapshot(
            keyverse_subject="sub-no-assignment",
            org_path="/group_company/acme",
        )
    )
    assert omitted.assignment_record_id is None
    assert parse_menu_path("/invoices/approve") == "/invoices/approve"


def test_menu_grant_without_matching_prefix_is_ignored() -> None:
    """A grant for a different menu tree does not authorize the requested menu."""
    grants = [
        _software_grant("/group_company/acme"),
        _menu_grant("/group_company/acme", menu_path="/settings"),
    ]
    decision = decide_menu(grants, _snapshot(), "naruon-web", "/invoices")
    assert decision.decision_code is AuthorizationDecisionCode.DEFAULT_DENY
