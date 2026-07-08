"""UnificationService — the account-unification orchestrator (Keycloak-backed).

Two capabilities the underlying engine does not provide natively:

  (a) one-user-to-many-external-identities: list/inspect a user's federated
      identities (Keycloak ``federated-identity`` links).
  (b) MERGE two pre-existing accounts into one survivor: move federated
      identities, role mappings (realm + client), and group memberships/ownership
      to the survivor, resolve conflicts with a survivor-wins policy, tombstone
      the duplicate, and audit every step.

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
from .keycloak_client import AdminApi
from .matching import decide_match, have_matching_verified_email
from .models import (
    FederatedIdentity,
    MergeConflict,
    MergeRequest,
    MergeResult,
    UserAccount,
)

# Keycloak user attribute stamped on a tombstoned duplicate (two-word snake_case).
TOMBSTONE_ATTRIBUTE_KEY = "merged_into_user_id"
_ACTIVE_STATES = {"active", "enabled"}


class UnificationService:
    def __init__(
        self,
        api: AdminApi,
        audit: AuditLogger,
        config: ServiceConfig,
    ) -> None:
        self._api = api
        self._audit = audit
        self._config = config

    # -- (a) inspect identities -------------------------------------------
    def get_account(self, user_id: str) -> UserAccount:
        user = self._load_user(user_id)
        user.federated_identities = self._api.list_federated_identities(user_id)
        return user

    def list_identities(self, user_id: str) -> list[FederatedIdentity]:
        """List the external identities (federated identities) tied to one user."""
        self._load_user(user_id)  # existence check
        return self._api.list_federated_identities(user_id)

    # -- (b) merge --------------------------------------------------------
    def merge_accounts(self, request: MergeRequest) -> MergeResult:
        if request.survivor_user_id == request.duplicate_user_id:
            raise SameUserError("survivor and duplicate are the same account")

        survivor = self._load_user(request.survivor_user_id)
        duplicate = self._load_user(request.duplicate_user_id)
        survivor.federated_identities = self._api.list_federated_identities(
            survivor.user_id
        )
        duplicate.federated_identities = self._api.list_federated_identities(
            duplicate.user_id
        )

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
        moved_links = self._move_federated_identities(
            survivor, duplicate, audit_id, request.actor, conflicts
        )
        moved_roles = self._move_role_mappings(
            survivor, duplicate, audit_id, request.actor, conflicts
        )
        moved_groups = self._move_group_memberships(
            survivor, duplicate, audit_id, request.actor, conflicts
        )
        self._tombstone(duplicate, survivor, audit_id, request.actor)

        result = MergeResult(
            survivor_user_id=survivor.user_id,
            duplicate_user_id=duplicate.user_id,
            match_reason=decision.reason,
            moved_federated_identities=moved_links,
            moved_role_mappings=moved_roles,
            moved_group_memberships=moved_groups,
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
                "moved_federated_identities": moved_links,
                "moved_role_mappings": moved_roles,
                "moved_group_memberships": moved_groups,
                "conflicts": [c.model_dump() for c in conflicts],
            },
        )
        return result

    # -- move helpers (survivor-wins) -------------------------------------
    def _move_federated_identities(
        self, survivor, duplicate, audit_id, actor, conflicts
    ) -> list[str]:
        existing = {
            (link.identity_provider, link.external_user_id)
            for link in survivor.federated_identities
        }
        moved: list[str] = []
        for link in duplicate.federated_identities:
            key = (link.identity_provider, link.external_user_id)
            identifier = f"{link.identity_provider}:{link.external_user_id}"
            # A Keycloak user can hold at most one link per provider alias, so a
            # conflict is any survivor link that already uses this provider.
            provider_taken = any(
                s.identity_provider == link.identity_provider
                for s in survivor.federated_identities
            )
            if key in existing or provider_taken:
                conflicts.append(
                    MergeConflict(kind="federated_identity", identifier=identifier)
                )
                # survivor-wins: keep survivor's link; still detach from duplicate.
                self._api.remove_federated_identity(
                    duplicate.user_id, link.identity_provider
                )
                self._audit.emit(
                    audit_id=audit_id, event_type="federated_identity_conflict",
                    actor=actor, survivor_user_id=survivor.user_id,
                    duplicate_user_id=duplicate.user_id,
                    payload={"identifier": identifier, "resolution": "survivor_wins"},
                )
                continue
            self._api.add_federated_identity(survivor.user_id, link)
            self._api.remove_federated_identity(
                duplicate.user_id, link.identity_provider
            )
            moved.append(identifier)
            self._audit.emit(
                audit_id=audit_id, event_type="federated_identity_moved", actor=actor,
                survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                payload={"identifier": identifier},
            )
        return moved

    def _move_role_mappings(
        self, survivor, duplicate, audit_id, actor, conflicts
    ) -> list[str]:
        survivor_roles = {
            (r.client_id, r.role_name)
            for r in self._api.list_role_mappings(survivor.user_id)
        }
        moved: list[str] = []
        for role in self._api.list_role_mappings(duplicate.user_id):
            key = (role.client_id, role.role_name)
            scope = role.client_id or "realm"
            identifier = f"{scope}:{role.role_name}"
            if key in survivor_roles:
                conflicts.append(
                    MergeConflict(kind="role_mapping", identifier=identifier)
                )
                # survivor-wins: survivor already has it; drop the duplicate's.
                self._api.remove_role_mapping(duplicate.user_id, role)
                self._audit.emit(
                    audit_id=audit_id, event_type="role_mapping_conflict", actor=actor,
                    survivor_user_id=survivor.user_id,
                    duplicate_user_id=duplicate.user_id,
                    payload={"identifier": identifier, "resolution": "survivor_wins"},
                )
                continue
            self._api.add_role_mapping(survivor.user_id, role)
            self._api.remove_role_mapping(duplicate.user_id, role)
            moved.append(identifier)
            self._audit.emit(
                audit_id=audit_id, event_type="role_mapping_moved", actor=actor,
                survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                payload={"identifier": identifier, "role_name": role.role_name,
                         "client_id": role.client_id},
            )
        return moved

    def _move_group_memberships(
        self, survivor, duplicate, audit_id, actor, conflicts
    ) -> list[str]:
        survivor_groups = {
            g.group_id for g in self._api.list_group_memberships(survivor.user_id)
        }
        moved: list[str] = []
        for group in self._api.list_group_memberships(duplicate.user_id):
            identifier = group.group_path or group.group_id
            if group.group_id in survivor_groups:
                conflicts.append(
                    MergeConflict(kind="group_membership", identifier=identifier)
                )
                self._api.remove_group_membership(duplicate.user_id, group)
                self._audit.emit(
                    audit_id=audit_id, event_type="group_membership_conflict",
                    actor=actor, survivor_user_id=survivor.user_id,
                    duplicate_user_id=duplicate.user_id,
                    payload={"identifier": identifier, "resolution": "survivor_wins"},
                )
                continue
            self._api.add_group_membership(survivor.user_id, group)
            self._api.remove_group_membership(duplicate.user_id, group)
            moved.append(identifier)
            self._audit.emit(
                audit_id=audit_id, event_type="group_membership_moved", actor=actor,
                survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
                payload={"identifier": identifier},
            )
        return moved

    def _tombstone(self, duplicate, survivor, audit_id, actor) -> None:
        # Stamp a pointer to the survivor, then disable the duplicate so it can
        # never authenticate again but remains for forensic history.
        self._api.set_user_attribute(
            duplicate.user_id, TOMBSTONE_ATTRIBUTE_KEY, survivor.user_id
        )
        self._api.deactivate_user(duplicate.user_id)
        self._audit.emit(
            audit_id=audit_id, event_type="duplicate_tombstoned", actor=actor,
            survivor_user_id=survivor.user_id, duplicate_user_id=duplicate.user_id,
            payload={"attribute_key": TOMBSTONE_ATTRIBUTE_KEY},
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
            raise InactiveAccountError(
                f"user {user.user_id} is not active ({user.state})"
            )
