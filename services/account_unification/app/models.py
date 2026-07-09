"""Domain models for identity linking and account merge (Keycloak-backed)."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class MatchReason(str, Enum):
    """Why two accounts are considered the same human."""

    EXACT_IDP_SUBJECT = "exact_idp_subject"
    VERIFIED_EMAIL = "verified_email"
    EXPLICIT_LINK = "explicit_link"
    NO_MATCH = "no_match"


class FederatedIdentity(BaseModel):
    """One external identity linked to a Keycloak user (a federated identity).

    Maps to Keycloak's ``FederatedIdentityRepresentation``:
    ``{identityProvider, userId, userName}``.
    """

    identity_provider: str = Field(
        ..., description="Keycloak IdP alias, e.g. 'employer-adfs'"
    )
    external_user_id: str = Field(..., description="subject / nameID at the external IdP")
    external_user_name: str | None = None


class RoleMapping(BaseModel):
    """A realm or client role mapped onto a user (moved during merge).

    Maps to Keycloak's ``RoleRepresentation`` plus the container it belongs to.
    ``client_id`` is ``None`` for a realm role; otherwise it is the Keycloak
    client UUID whose client role this is.
    """

    role_id: str
    role_name: str
    client_id: str | None = None


class GroupMembership(BaseModel):
    """A group the user belongs to (moved during merge).

    Maps to Keycloak's ``GroupRepresentation`` (``{id, name, path}``). Group
    membership carries Keycloak role/attribute inheritance, i.e. ownership.
    """

    group_id: str
    group_path: str
    group_name: str | None = None


class UserAccount(BaseModel):
    """A Keycloak user as seen by the unification service."""

    user_id: str
    user_name: str | None = None
    email: str | None = None
    is_email_verified: bool = False
    # Keycloak users are enabled/disabled; "active" mirrors enabled=true.
    state: str = "active"
    first_name: str | None = None
    last_name: str | None = None
    # SCIM provisioning source id, kept as a Keycloak user attribute.
    external_id: str | None = None
    federated_identities: list[FederatedIdentity] = Field(default_factory=list)


class MatchDecision(BaseModel):
    """Result of applying the account matching policy."""

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

    kind: str  # "federated_identity" | "role_mapping" | "group_membership"
    identifier: str
    resolution: str = "survivor_wins"


class MergeResult(BaseModel):
    """Audited outcome of a survivor-wins account merge."""

    survivor_user_id: str
    duplicate_user_id: str
    match_reason: MatchReason
    moved_federated_identities: list[str] = Field(default_factory=list)
    moved_role_mappings: list[str] = Field(default_factory=list)
    moved_group_memberships: list[str] = Field(default_factory=list)
    conflicts: list[MergeConflict] = Field(default_factory=list)
    duplicate_tombstoned: bool = False
    audit_id: str | None = None
