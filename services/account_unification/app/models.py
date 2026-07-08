"""Domain models for identity linking and account merge."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class MatchReason(str, Enum):
    """Why two accounts are considered the same human."""

    EXACT_IDP_SUBJECT = "exact_idp_subject"
    VERIFIED_EMAIL = "verified_email"
    EXPLICIT_LINK = "explicit_link"
    NO_MATCH = "no_match"


class IdentityLink(BaseModel):
    """One external identity federated into a ZITADEL user (an idp_link)."""

    idp_id: str
    idp_name: str | None = None
    external_user_id: str = Field(..., description="subject / nameID at the IdP")
    external_user_name: str | None = None


class UserAccount(BaseModel):
    """A ZITADEL human user as seen by the unification service."""

    user_id: str
    user_name: str | None = None
    email: str | None = None
    is_email_verified: bool = False
    state: str = "active"
    idp_links: list[IdentityLink] = Field(default_factory=list)


class UserGrant(BaseModel):
    """A role grant on a project (roles/grants moved during merge)."""

    grant_id: str
    project_id: str
    project_grant_id: str | None = None
    role_keys: list[str] = Field(default_factory=list)


class Membership(BaseModel):
    """Org/project/instance manager membership (ownership moved during merge)."""

    membership_type: str  # "org" | "project" | "project_grant" | "instance"
    aggregate_id: str
    roles: list[str] = Field(default_factory=list)


class MatchDecision(BaseModel):
    matched: bool
    reason: MatchReason
    detail: str | None = None


class MergeRequest(BaseModel):
    """Request to merge ``duplicate_user_id`` into ``survivor_user_id``."""

    survivor_user_id: str
    duplicate_user_id: str
    # Operator asserts an explicit link (e.g. verified out-of-band). Even so,
    # the service refuses if the only tie is an UNVERIFIED email.
    explicit_link: bool = False
    reason_note: str | None = None
    actor: str = Field(..., description="who initiated the merge, for audit")


class MergeConflict(BaseModel):
    """A survivor-wins conflict recorded during merge."""

    kind: str  # "idp_link" | "grant" | "membership"
    identifier: str
    resolution: str = "survivor_wins"


class MergeResult(BaseModel):
    survivor_user_id: str
    duplicate_user_id: str
    match_reason: MatchReason
    moved_idp_links: list[str] = Field(default_factory=list)
    moved_grants: list[str] = Field(default_factory=list)
    moved_memberships: list[str] = Field(default_factory=list)
    conflicts: list[MergeConflict] = Field(default_factory=list)
    duplicate_tombstoned: bool = False
    audit_id: str | None = None
