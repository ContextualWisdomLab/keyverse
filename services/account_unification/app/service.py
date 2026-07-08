"""UnificationService — the account-unification orchestrator.

Two capabilities the underlying engines do not provide natively:

  (a) one-user-to-many-external-identities: list/inspect a user's idp_links.
  (b) MERGE two pre-existing accounts into one survivor: move idp_links, role
      grants, and memberships/ownership to the survivor, resolve conflicts with
      a survivor-wins policy, tombstone the duplicate, and audit every step.

Matching precedence: exact (idp, subject) -> verified email -> explicit link.
Never merges on an unverified-email coincidence.
"""
from __future__ import annotations

from .audit import AuditLogger
from .config import ServiceConfig
from .errors import (
    InactiveAccountError,
    NoMatchError,
    SameUserError,
    UnverifiedEmailMergeError,
    UserNotFoundError,
)
from .matching import decide_match, have_matching_verified_email
from .models import (
    IdentityLink,
    MergeConflict,
    MergeRequest,
    MergeResult,
    UserAccount,
)
from .zitadel_client import ManagementApi

# Metadata key stamped on a tombstoned duplicate (two-word snake_case).
TOMBSTONE_METADATA_KEY = "merged_into_user_id"
_ACTIVE_STATES = {"active", "USER_STATE_ACTIVE", "USER_STATE_INITIAL"}


class UnificationService:
    def __init__(
        self,
        api: ManagementApi,
        audit: AuditLogger,
        config: ServiceConfig,
    ) -> None:
        self._api = api
        self._audit = audit
        self._config = config

    # -- (a) inspect identities -------------------------------------------
    def get_account(self, user_id: str) -> UserAccount:
        user = self._load_user(user_id)
        user.idp_links = self._api.list_idp_links(user_id)
        return user

    def list_identities(self, user_id: str) -> list[IdentityLink]:
        """List the external identities (idp_links) tied to one user."""
        self._load_user(user_id)  # existence check
        return self._api.list_idp_links(user_id)

    # -- (b) merge --------------------------------------------------------
    def merge_accounts(self, request: MergeRequest) -> MergeResult:
        if request.survivor_user_id == request.duplicate_user_id:
            raise SameUserError("survivor and duplicate are the same account")

        survivor = self._load_user(request.survivor_user_id)
        duplicate = self._load_user(request.duplicate_user_id)
        survivor.idp_links = self._api.list_idp_links(survivor.user_id)
        duplicate.idp_links = self._api.list_idp_links(duplicate.user_id)

        self._assert_active(survivor)
        self._assert_active(duplicate)

        decision = decide_match(
            survivor, duplicate, explicit_link=request.explicit_link
        )
        # Guard: refuse when the accounts only coincide on an unverified email.
        # (decide_match already refuses to *call* that a verified match; here we
        # produce the precise error for the operator + audit trail.)
        if not decision.matched:
            same_email = (
                (survivor.email or "").strip().lower()
                == (duplicate.email or "").strip().lower()
                and bool(survivor.email)
            )
            if same_email and not have_matching_verified_email(survivor, duplicate):
                raise UnverifiedEmailMergeError(
                    "refusing merge: accounts share only an UNVERIFIED email"
                )
            raise NoMatchError(decision.detail or "no matching rule satisfied")

        audit_id = self._audit.new_correlation_id()
        self._audit.emit(
            audit_id=audit_id,
            event_type="merge_started",
            actor=request.actor,
            survivor_user_id=survivor.user_id,
            duplicate_user_id=duplicate.user_id,
            payload={
                "match_reason": decision.reason.value,
                "match_detail": decision.detail,
                "reason_note": request.reason_note,
                "conflict_policy": self._config.merge_conflict_policy,
            },
        )

        conflicts: list[MergeConflict] = []
        moved_links = self._move_idp_links(survivor, duplicate, audit_id, request.actor, conflicts)
        moved_grants = self._move_grants(survivor, duplicate, audit_id, request.actor, conflicts)
        moved_memberships = self._move_memberships(
            survivor, duplicate, audit_id, request.actor, conflicts
        )
        self._tombstone(duplicate, survivor, audit_id, request.actor)

        result = MergeResult(
            survivor_user_id=survivor.user_id,
            duplicate_user_id=duplicate.user_id,
            match_reason=decision.reason,
            moved_idp_links=moved_links,
            moved_grants=moved_grants,
            moved_memberships=moved_memberships,
            conflicts=conflicts,
            duplicate_tombstoned=True,
            audit_id=audit_id,
        )
        self._audit.emit(
            audit_id=audit_id,
            event_type="merge_completed",
            actor=request.actor,
            survivor_user_id=survivor.user_id,
            duplicate_user_id=duplicate.user_id,
            payload={
                "moved_idp_links": moved_links,
                "moved_grants": moved_grants,
                "moved_memberships": moved_memberships,
                "conflicts": [c.model_dump() for c in conflicts],
            },
        )
        return result

    # -- move helpers (survivor-wins) -------------------------------------
    def _move_idp_links(self, survivor, duplicate, audit_id, actor, conflicts) -> list[str]:
        existing = {(link.idp_id, link.external_user_id) for link in survivor.idp_links}
        moved: list[str] = []
        for link in duplicate.idp_links:
            key = (link.idp_id, link.external_user_id)
            identifier = f"{link.idp_id}:{link.external_user_id}"
            if key in existing:
                conflicts.append(MergeConflict(kind="idp_link", identifier=identifier))
                # survivor-wins: keep survivor's link; still detach from duplicate.
                self._api.remove_idp_link(duplicate.user_id, link.idp_id, link.external_user_id)
                self._audit.emit(
                    audit_id=audit_id, event_type="idp_link_conflict", actor=actor,
                    survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                    payload={"identifier": identifier, "resolution": "survivor_wins"},
                )
                continue
            self._api.add_idp_link(survivor.user_id, link)
            self._api.remove_idp_link(duplicate.user_id, link.idp_id, link.external_user_id)
            moved.append(identifier)
            self._audit.emit(
                audit_id=audit_id, event_type="idp_link_moved", actor=actor,
                survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                payload={"identifier": identifier},
            )
        return moved

    def _move_grants(self, survivor, duplicate, audit_id, actor, conflicts) -> list[str]:
        survivor_projects = {g.project_id for g in self._api.list_user_grants(survivor.user_id)}
        moved: list[str] = []
        for grant in self._api.list_user_grants(duplicate.user_id):
            if grant.project_id in survivor_projects:
                conflicts.append(
                    MergeConflict(kind="grant", identifier=grant.project_id)
                )
                # survivor-wins: keep survivor's grant on that project; drop dup's.
                self._api.remove_user_grant(duplicate.user_id, grant.grant_id)
                self._audit.emit(
                    audit_id=audit_id, event_type="grant_conflict", actor=actor,
                    survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                    payload={"project_id": grant.project_id, "resolution": "survivor_wins"},
                )
                continue
            new_grant_id = self._api.add_user_grant(survivor.user_id, grant.project_id, grant.role_keys)
            self._api.remove_user_grant(duplicate.user_id, grant.grant_id)
            moved.append(grant.project_id)
            self._audit.emit(
                audit_id=audit_id, event_type="grant_moved", actor=actor,
                survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                payload={"project_id": grant.project_id, "new_grant_id": new_grant_id,
                         "role_keys": grant.role_keys},
            )
        return moved

    def _move_memberships(self, survivor, duplicate, audit_id, actor, conflicts) -> list[str]:
        survivor_keys = {
            (m.membership_type, m.aggregate_id)
            for m in self._api.list_memberships(survivor.user_id)
        }
        moved: list[str] = []
        for membership in self._api.list_memberships(duplicate.user_id):
            key = (membership.membership_type, membership.aggregate_id)
            identifier = f"{membership.membership_type}:{membership.aggregate_id}"
            if key in survivor_keys:
                conflicts.append(MergeConflict(kind="membership", identifier=identifier))
                self._api.remove_membership(duplicate.user_id, membership)
                self._audit.emit(
                    audit_id=audit_id, event_type="membership_conflict", actor=actor,
                    survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                    payload={"identifier": identifier, "resolution": "survivor_wins"},
                )
                continue
            self._api.add_membership(survivor.user_id, membership)
            self._api.remove_membership(duplicate.user_id, membership)
            moved.append(identifier)
            self._audit.emit(
                audit_id=audit_id, event_type="membership_moved", actor=actor,
                survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                payload={"identifier": identifier, "roles": membership.roles},
            )
        return moved

    def _tombstone(self, duplicate, survivor, audit_id, actor) -> None:
        # Stamp a pointer to the survivor, then deactivate the duplicate so it
        # can never authenticate again but remains for forensic history.
        self._api.set_user_metadata(
            duplicate.user_id, TOMBSTONE_METADATA_KEY, survivor.user_id
        )
        self._api.deactivate_user(duplicate.user_id)
        self._audit.emit(
            audit_id=audit_id, event_type="duplicate_tombstoned", actor=actor,
            survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
            payload={"metadata_key": TOMBSTONE_METADATA_KEY},
        )

    # -- guards -----------------------------------------------------------
    def _load_user(self, user_id: str) -> UserAccount:
        try:
            return self._api.get_user(user_id)
        except KeyError as exc:  # mock raises KeyError for unknown ids
            raise UserNotFoundError(user_id) from exc

    @staticmethod
    def _assert_active(user: UserAccount) -> None:
        if user.state not in _ACTIVE_STATES:
            raise InactiveAccountError(f"user {user.user_id} is not active ({user.state})")
