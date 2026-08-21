"""Deterministic hierarchical authorization attributes and decisions.

Keyverse is the issuer/PDP of authorization attributes and decisions. Each
relying party remains the PEP and must validate a Keyverse token before
enforcing a local decision (ADR-0008). Employment and org-tree truth stay in
Orgmetra; this module consumes a caller-supplied assignment snapshot and never
treats the snapshot as a source of record.

Hierarchical attribute names are ``group_company``, ``legal_entity``,
``business_unit``, ``team``, ``person``, and structured ``org_path``. They do
not reuse the unmerged LineageWeave ``role``, ``org``, or ``workspace`` claim
names from open PR #100.
"""
from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .errors import AuthorizationPolicyError

ORG_PATH_LEVELS: tuple[str, ...] = (
    "group_company",
    "legal_entity",
    "business_unit",
    "team",
    "person",
)
LINEAGEWEAVE_RESERVED_CLAIM_NAMES: frozenset[str] = frozenset(
    {"role", "org", "workspace"}
)
CLOSED_ATTRIBUTE_CONSTRAINT_KEYS: frozenset[str] = frozenset(
    {"purpose", "sensitivity", "clearance", "residency"}
)
SOFTWARE_UNIT_GRANT_SCOPE = "software_unit"
MENU_GRANT_SCOPE = "menu"
GRANT_SCOPES: frozenset[str] = frozenset(
    {SOFTWARE_UNIT_GRANT_SCOPE, MENU_GRANT_SCOPE}
)
ALLOW_EFFECT = "allow"
DENY_EFFECT = "deny"
GRANT_EFFECTS: frozenset[str] = frozenset({ALLOW_EFFECT, DENY_EFFECT})
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(?:[._][a-z0-9]+){0,6}$")
_MAX_CAPABILITY_CODES = 16
_MAX_MENU_SEGMENTS = 8
_MAX_ORG_PATH_LENGTH = 512
_MAX_MENU_PATH_LENGTH = 256


class AuthorizationEffect(StrEnum):
    """Closed PDP effect returned to a relying-party PEP."""

    ALLOW = ALLOW_EFFECT
    DENY = DENY_EFFECT


class AuthorizationDecisionCode(StrEnum):
    """Why a software-unit, menu, or SSO decision resolved as it did."""

    INHERITED_ALLOW = "inherited_allow"
    SPECIFIC_ALLOW = "specific_allow"
    INHERITED_DENY = "inherited_deny"
    SPECIFIC_DENY = "specific_deny"
    DEFAULT_DENY = "default_deny"
    ATTRIBUTE_MISMATCH = "attribute_mismatch"
    SOFTWARE_UNIT_DENIED = "software_unit_denied"
    COMBINATION_DENIED = "combination_denied"
    COMBINATION_ALLOW = "combination_allow"


class OrganizationPath(BaseModel):
    """A contiguous Macro-to-Micro org path consumed from Orgmetra evidence."""

    model_config = ConfigDict(extra="forbid")

    segments: tuple[tuple[str, str], ...]

    @property
    def serialized(self) -> str:
        """Return the canonical slash-delimited org path."""
        parts: list[str] = []
        for level_name, unit_identifier in self.segments:
            parts.extend((level_name, unit_identifier))
        return "/" + "/".join(parts)

    @property
    def depth(self) -> int:
        """Return how many organization levels are present."""
        return len(self.segments)

    def attribute_map(self) -> dict[str, str]:
        """Return hierarchical attributes without LineageWeave claim names."""
        values = {level_name: unit_identifier for level_name, unit_identifier in self.segments}
        values["org_path"] = self.serialized
        return values

    def ancestor_paths(self) -> list[str]:
        """Return serialized paths from most specific to group company."""
        paths: list[str] = []
        for depth in range(self.depth, 0, -1):
            paths.append(OrganizationPath(segments=self.segments[:depth]).serialized)
        return paths


class AssignmentSnapshot(BaseModel):
    """Caller-supplied Orgmetra assignment evidence bound to a Keyverse subject.

    Keyverse stores the snapshot only as decision input. It does not persist or
    own Orgmetra ``organization_unit`` / ``assignment_record`` trees.
    """

    model_config = ConfigDict(extra="forbid")

    keyverse_subject: str = Field(min_length=1, max_length=128)
    tenant_deployment_id: str = Field(min_length=1, max_length=128)
    org_path: str = Field(min_length=1, max_length=_MAX_ORG_PATH_LENGTH)
    assignment_record_id: str | None = Field(default=None, max_length=128)
    request_attributes: dict[str, str] = Field(default_factory=dict)


class AuthorizationGrant(BaseModel):
    """One software-unit or menu grant attached to an org-path node."""

    model_config = ConfigDict(extra="forbid")

    grant_key: str
    tenant_deployment_id: str
    grant_scope_code: str
    org_path: str
    software_unit_id: str
    menu_path: str | None = None
    effect_code: str
    capability_codes: list[str] = Field(default_factory=list)
    attribute_constraints: dict[str, str] = Field(default_factory=dict)
    actor_identity_id: str = Field(min_length=1, max_length=128)


class AuthorizationDecision(BaseModel):
    """Issuer-side PDP result. The relying party remains the PEP."""

    model_config = ConfigDict(extra="forbid")

    effect: AuthorizationEffect
    decision_code: AuthorizationDecisionCode
    keyverse_subject: str
    software_unit_id: str
    org_path: str
    winning_org_path: str | None = None
    winning_menu_path: str | None = None
    inherited: bool = False
    menu_path: str | None = None
    capability_codes: list[str] = Field(default_factory=list)
    authorization_attributes: dict[str, str] = Field(default_factory=dict)
    pep_enforcement_required: bool = True
    lineageweave_claim_names: list[str] = Field(
        default_factory=lambda: sorted(LINEAGEWEAVE_RESERVED_CLAIM_NAMES)
    )


class SsoCombinationScope(BaseModel):
    """Named set of software units that may share one Keyverse SSO session."""

    model_config = ConfigDict(extra="forbid")

    combination_name: str
    tenant_deployment_id: str
    software_unit_ids: list[str]
    actor_identity_id: str = Field(min_length=1, max_length=128)


class SsoCombinationDecision(BaseModel):
    """Whether one Keyverse session may cover every member of a combination."""

    model_config = ConfigDict(extra="forbid")

    effect: AuthorizationEffect
    decision_code: AuthorizationDecisionCode
    combination_name: str
    keyverse_subject: str
    org_path: str
    member_decisions: list[AuthorizationDecision] = Field(default_factory=list)
    pep_enforcement_required: bool = True


def validate_slug(value: str, *, field_name: str) -> str:
    """Return one lowercase URL-safe slug or raise a policy error."""
    if not isinstance(value, str) or _SLUG.fullmatch(value) is None:
        raise AuthorizationPolicyError(
            f"{field_name} must be a lowercase URL-safe slug"
        )
    return value


def validate_capability_codes(capability_codes: list[str]) -> list[str]:
    """Return a de-duplicated closed capability list or raise a policy error."""
    if len(capability_codes) > _MAX_CAPABILITY_CODES:
        raise AuthorizationPolicyError("capability_codes exceeds the closed bound")
    normalized: list[str] = []
    seen: set[str] = set()
    for capability_code in capability_codes:
        if _CAPABILITY.fullmatch(capability_code) is None:
            raise AuthorizationPolicyError(
                "capability_codes must use closed dotted or underscored tokens"
            )
        if capability_code in seen:
            raise AuthorizationPolicyError("capability_codes must be unique")
        seen.add(capability_code)
        normalized.append(capability_code)
    return normalized


def parse_org_path(raw_org_path: str) -> OrganizationPath:
    """Parse a contiguous Macro-to-Micro org path and reject reserved names."""
    if not isinstance(raw_org_path, str) or not raw_org_path:
        raise AuthorizationPolicyError("org_path is required")
    if len(raw_org_path) > _MAX_ORG_PATH_LENGTH:
        raise AuthorizationPolicyError("org_path exceeds the closed bound")
    if not raw_org_path.startswith("/") or raw_org_path.endswith("/"):
        raise AuthorizationPolicyError(
            "org_path must be an absolute path without a trailing slash"
        )
    body = raw_org_path.split("/")[1:]
    if len(body) < 2 or len(body) % 2 != 0:
        raise AuthorizationPolicyError(
            "org_path must alternate level names and unit identifiers"
        )
    segments: list[tuple[str, str]] = []
    expected_levels = ORG_PATH_LEVELS
    for index in range(0, len(body), 2):
        level_name = body[index]
        unit_identifier = body[index + 1]
        expected_index = index // 2
        if expected_index >= len(expected_levels):
            raise AuthorizationPolicyError("org_path is deeper than the closed tree")
        if level_name in LINEAGEWEAVE_RESERVED_CLAIM_NAMES:
            raise AuthorizationPolicyError(
                "org_path must not use LineageWeave reserved claim names"
            )
        if level_name != expected_levels[expected_index]:
            raise AuthorizationPolicyError(
                "org_path levels must be contiguous from group_company"
            )
        validate_slug(unit_identifier, field_name="org_path unit identifier")
        segments.append((level_name, unit_identifier))
    return OrganizationPath(segments=tuple(segments))


def parse_menu_path(raw_menu_path: str) -> str:
    """Return a canonical menu path with optional descendant prefix matching."""
    if not isinstance(raw_menu_path, str) or not raw_menu_path:
        raise AuthorizationPolicyError("menu_path is required")
    if len(raw_menu_path) > _MAX_MENU_PATH_LENGTH:
        raise AuthorizationPolicyError("menu_path exceeds the closed bound")
    if not raw_menu_path.startswith("/") or raw_menu_path.endswith("/"):
        raise AuthorizationPolicyError(
            "menu_path must be an absolute path without a trailing slash"
        )
    segments = raw_menu_path.split("/")[1:]
    if not segments or len(segments) > _MAX_MENU_SEGMENTS:
        raise AuthorizationPolicyError("menu_path has an invalid segment count")
    for segment in segments:
        validate_slug(segment, field_name="menu_path segment")
    return "/" + "/".join(segments)


def menu_ancestor_paths(menu_path: str) -> list[str]:
    """Return menu paths from most specific to the first segment."""
    canonical = parse_menu_path(menu_path)
    segments = canonical.split("/")[1:]
    return ["/" + "/".join(segments[:depth]) for depth in range(len(segments), 0, -1)]


def validate_attribute_constraints(attribute_constraints: dict[str, str]) -> dict[str, str]:
    """Reject reserved LineageWeave keys and unknown ABAC constraint names."""
    validated: dict[str, str] = {}
    for attribute_key, attribute_value in attribute_constraints.items():
        if attribute_key in LINEAGEWEAVE_RESERVED_CLAIM_NAMES:
            raise AuthorizationPolicyError(
                "attribute_constraints must not redefine LineageWeave claim names"
            )
        if attribute_key not in CLOSED_ATTRIBUTE_CONSTRAINT_KEYS:
            raise AuthorizationPolicyError(
                "attribute_constraints keys must be purpose, sensitivity, "
                "clearance, or residency"
            )
        if not isinstance(attribute_value, str) or not attribute_value.strip():
            raise AuthorizationPolicyError(
                "attribute_constraints values must be non-empty strings"
            )
        if len(attribute_value) > 64:
            raise AuthorizationPolicyError(
                "attribute_constraints values exceed the closed bound"
            )
        validated[attribute_key] = attribute_value
    return validated


def validate_request_attributes(request_attributes: dict[str, str]) -> dict[str, str]:
    """Validate optional ABAC attributes supplied with a decision snapshot."""
    return validate_attribute_constraints(request_attributes)


def validate_grant(grant: AuthorizationGrant) -> AuthorizationGrant:
    """Normalize and close one authorization grant."""
    validate_slug(grant.grant_key, field_name="grant_key")
    validate_slug(grant.tenant_deployment_id, field_name="tenant_deployment_id")
    validate_slug(grant.software_unit_id, field_name="software_unit_id")
    if grant.grant_scope_code not in GRANT_SCOPES:
        raise AuthorizationPolicyError("grant_scope_code must be software_unit or menu")
    if grant.effect_code not in GRANT_EFFECTS:
        raise AuthorizationPolicyError("effect_code must be allow or deny")
    parsed_org = parse_org_path(grant.org_path)
    capability_codes = validate_capability_codes(grant.capability_codes)
    constraints = validate_attribute_constraints(grant.attribute_constraints)
    menu_path: str | None = None
    if grant.grant_scope_code == SOFTWARE_UNIT_GRANT_SCOPE:
        if grant.menu_path is not None:
            raise AuthorizationPolicyError(
                "software_unit grants must not carry a menu_path"
            )
        if constraints:
            raise AuthorizationPolicyError(
                "software_unit grants must not carry attribute_constraints"
            )
        if capability_codes and grant.effect_code == DENY_EFFECT:
            raise AuthorizationPolicyError("deny grants cannot carry capability_codes")
    else:
        if grant.menu_path is None:
            raise AuthorizationPolicyError("menu grants require menu_path")
        menu_path = parse_menu_path(grant.menu_path)
        if grant.effect_code == DENY_EFFECT and (capability_codes or constraints):
            raise AuthorizationPolicyError(
                "deny grants cannot carry capability_codes or attribute_constraints"
            )
    return grant.model_copy(
        update={
            "org_path": parsed_org.serialized,
            "menu_path": menu_path,
            "capability_codes": capability_codes,
            "attribute_constraints": constraints,
        }
    )


def validate_combination(combination: SsoCombinationScope) -> SsoCombinationScope:
    """Normalize one SSO combination of software units."""
    validate_slug(combination.combination_name, field_name="combination_name")
    validate_slug(
        combination.tenant_deployment_id, field_name="tenant_deployment_id"
    )
    if not 2 <= len(combination.software_unit_ids) <= 16:
        raise AuthorizationPolicyError(
            "sso combination must name between 2 and 16 software units"
        )
    seen: set[str] = set()
    software_unit_ids: list[str] = []
    for software_unit_id in combination.software_unit_ids:
        validate_slug(software_unit_id, field_name="software_unit_id")
        if software_unit_id in seen:
            raise AuthorizationPolicyError("sso combination software units must be unique")
        seen.add(software_unit_id)
        software_unit_ids.append(software_unit_id)
    return combination.model_copy(update={"software_unit_ids": software_unit_ids})


def validate_snapshot(snapshot: AssignmentSnapshot) -> AssignmentSnapshot:
    """Validate one assignment snapshot without contacting Orgmetra."""
    if any(character.isspace() or ord(character) < 0x20 for character in snapshot.keyverse_subject):
        raise AuthorizationPolicyError("keyverse_subject must be an opaque bounded token")
    validate_slug(
        snapshot.tenant_deployment_id,
        field_name="tenant_deployment_id",
    )
    parsed_org = parse_org_path(snapshot.org_path)
    if snapshot.assignment_record_id is not None:
        validate_slug(
            snapshot.assignment_record_id, field_name="assignment_record_id"
        )
    request_attributes = validate_request_attributes(snapshot.request_attributes)
    return snapshot.model_copy(
        update={
            "org_path": parsed_org.serialized,
            "request_attributes": request_attributes,
        }
    )


def _constraints_match(
    constraints: dict[str, str], request_attributes: dict[str, str]
) -> bool:
    """Return whether every grant constraint is present and equal."""
    for attribute_key, expected_value in constraints.items():
        if request_attributes.get(attribute_key) != expected_value:
            return False
    return True


def _decision_code(
    *,
    effect: str,
    inherited: bool,
    attribute_mismatch: bool = False,
) -> AuthorizationDecisionCode:
    """Map winning-grant geometry onto a closed decision code."""
    if attribute_mismatch:
        return AuthorizationDecisionCode.ATTRIBUTE_MISMATCH
    if effect == ALLOW_EFFECT and inherited:
        return AuthorizationDecisionCode.INHERITED_ALLOW
    if effect == ALLOW_EFFECT:
        return AuthorizationDecisionCode.SPECIFIC_ALLOW
    if inherited:
        return AuthorizationDecisionCode.INHERITED_DENY
    return AuthorizationDecisionCode.SPECIFIC_DENY


def _build_decision(
    *,
    snapshot: AssignmentSnapshot,
    software_unit_id: str,
    parsed_org: OrganizationPath,
    winning: AuthorizationGrant | None,
    inherited: bool,
    menu_path: str | None,
    attribute_mismatch: bool = False,
    software_unit_denied: bool = False,
) -> AuthorizationDecision:
    """Assemble one issuer-side decision envelope."""
    attributes = parsed_org.attribute_map()
    attributes["software_unit"] = software_unit_id
    if winning is None and software_unit_denied:
        return AuthorizationDecision(
            effect=AuthorizationEffect.DENY,
            decision_code=AuthorizationDecisionCode.SOFTWARE_UNIT_DENIED,
            keyverse_subject=snapshot.keyverse_subject,
            software_unit_id=software_unit_id,
            org_path=parsed_org.serialized,
            inherited=False,
            menu_path=menu_path,
            authorization_attributes=attributes,
        )
    if winning is None:
        return AuthorizationDecision(
            effect=AuthorizationEffect.DENY,
            decision_code=AuthorizationDecisionCode.DEFAULT_DENY,
            keyverse_subject=snapshot.keyverse_subject,
            software_unit_id=software_unit_id,
            org_path=parsed_org.serialized,
            inherited=False,
            menu_path=menu_path,
            authorization_attributes=attributes,
        )
    effect = (
        AuthorizationEffect.DENY
        if winning.effect_code == DENY_EFFECT or attribute_mismatch
        else AuthorizationEffect.ALLOW
    )
    return AuthorizationDecision(
        effect=effect,
        decision_code=_decision_code(
            effect=winning.effect_code,
            inherited=inherited,
            attribute_mismatch=attribute_mismatch,
        ),
        keyverse_subject=snapshot.keyverse_subject,
        software_unit_id=software_unit_id,
        org_path=parsed_org.serialized,
        winning_org_path=winning.org_path,
        winning_menu_path=winning.menu_path,
        inherited=inherited,
        menu_path=menu_path,
        capability_codes=list(winning.capability_codes) if effect is AuthorizationEffect.ALLOW else [],
        authorization_attributes=attributes,
    )


def _select_winning_grant(
    grants: list[AuthorizationGrant],
    *,
    snapshot_path: OrganizationPath,
    tenant_deployment_id: str,
    software_unit_id: str,
    grant_scope_code: str,
    requested_menu_path: str | None,
) -> tuple[AuthorizationGrant | None, bool]:
    """Return the most specific matching grant and whether it was inherited."""
    candidates: list[tuple[int, int, AuthorizationGrant]] = []
    org_rank = {path: index for index, path in enumerate(snapshot_path.ancestor_paths())}
    menu_rank: dict[str, int] = {}
    if requested_menu_path is not None:
        menu_rank = {
            path: index for index, path in enumerate(menu_ancestor_paths(requested_menu_path))
    }
    for grant in grants:
        if grant.tenant_deployment_id != tenant_deployment_id:
            continue
        if grant.grant_scope_code != grant_scope_code:
            continue
        if grant.software_unit_id != software_unit_id:
            continue
        if grant.org_path not in org_rank:
            continue
        if grant_scope_code == MENU_GRANT_SCOPE:
            if grant.menu_path is None or grant.menu_path not in menu_rank:
                continue
            menu_specificity = menu_rank[grant.menu_path]
        else:
            menu_specificity = 0
        candidates.append((menu_specificity, org_rank[grant.org_path], grant))
    if not candidates:
        return None, False
    candidates.sort(key=lambda item: (item[0], item[1]))
    winning = candidates[0][2]
    inherited = winning.org_path != snapshot_path.serialized
    return winning, inherited


def decide_software_unit(
    grants: list[AuthorizationGrant],
    snapshot: AssignmentSnapshot,
    software_unit_id: str,
) -> AuthorizationDecision:
    """Decide whether a subject may use one software unit / relying party."""
    validated_snapshot = validate_snapshot(snapshot)
    validate_slug(software_unit_id, field_name="software_unit_id")
    parsed_org = parse_org_path(validated_snapshot.org_path)
    validated_grants = [validate_grant(grant) for grant in grants]
    winning, inherited = _select_winning_grant(
        validated_grants,
        snapshot_path=parsed_org,
        tenant_deployment_id=validated_snapshot.tenant_deployment_id,
        software_unit_id=software_unit_id,
        grant_scope_code=SOFTWARE_UNIT_GRANT_SCOPE,
        requested_menu_path=None,
    )
    return _build_decision(
        snapshot=validated_snapshot,
        software_unit_id=software_unit_id,
        parsed_org=parsed_org,
        winning=winning,
        inherited=inherited,
        menu_path=None,
        attribute_mismatch=(
            winning is not None
            and winning.effect_code == ALLOW_EFFECT
            and not _constraints_match(
                winning.attribute_constraints,
                validated_snapshot.request_attributes,
            )
        ),
    )


def decide_menu(
    grants: list[AuthorizationGrant],
    snapshot: AssignmentSnapshot,
    software_unit_id: str,
    menu_path: str,
) -> AuthorizationDecision:
    """Decide menu access after software-unit allow, applying ABAC then RBAC."""
    software_decision = decide_software_unit(grants, snapshot, software_unit_id)
    validated_snapshot = validate_snapshot(snapshot)
    parsed_org = parse_org_path(validated_snapshot.org_path)
    canonical_menu = parse_menu_path(menu_path)
    if software_decision.effect is AuthorizationEffect.DENY:
        return _build_decision(
            snapshot=validated_snapshot,
            software_unit_id=software_unit_id,
            parsed_org=parsed_org,
            winning=None,
            inherited=False,
            menu_path=canonical_menu,
            software_unit_denied=True,
        )
    validated_grants = [validate_grant(grant) for grant in grants]
    winning, inherited = _select_winning_grant(
        validated_grants,
        snapshot_path=parsed_org,
        tenant_deployment_id=validated_snapshot.tenant_deployment_id,
        software_unit_id=software_unit_id,
        grant_scope_code=MENU_GRANT_SCOPE,
        requested_menu_path=canonical_menu,
    )
    attribute_mismatch = False
    if (
        winning is not None
        and winning.effect_code == ALLOW_EFFECT
        and not _constraints_match(
            winning.attribute_constraints, validated_snapshot.request_attributes
        )
    ):
        attribute_mismatch = True
    return _build_decision(
        snapshot=validated_snapshot,
        software_unit_id=software_unit_id,
        parsed_org=parsed_org,
        winning=winning,
        inherited=inherited,
        menu_path=canonical_menu,
        attribute_mismatch=attribute_mismatch,
    )


def decide_sso_combination(
    grants: list[AuthorizationGrant],
    snapshot: AssignmentSnapshot,
    combination: SsoCombinationScope,
) -> SsoCombinationDecision:
    """Allow a combination only when every member software unit is allowed."""
    validated_combination = validate_combination(combination)
    validated_snapshot = validate_snapshot(snapshot)
    if (
        validated_combination.tenant_deployment_id
        != validated_snapshot.tenant_deployment_id
    ):
        raise AuthorizationPolicyError(
            "snapshot and combination tenant_deployment_id must match"
        )
    member_decisions = [
        decide_software_unit(grants, validated_snapshot, software_unit_id)
        for software_unit_id in validated_combination.software_unit_ids
    ]
    allowed = all(
        decision.effect is AuthorizationEffect.ALLOW for decision in member_decisions
    )
    return SsoCombinationDecision(
        effect=AuthorizationEffect.ALLOW if allowed else AuthorizationEffect.DENY,
        decision_code=(
            AuthorizationDecisionCode.COMBINATION_ALLOW
            if allowed
            else AuthorizationDecisionCode.COMBINATION_DENIED
        ),
        combination_name=validated_combination.combination_name,
        keyverse_subject=validated_snapshot.keyverse_subject,
        org_path=validated_snapshot.org_path,
        member_decisions=member_decisions,
    )
