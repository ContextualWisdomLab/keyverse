"""In-memory fake of the ZITADEL Management API for unit tests.

Implements the :class:`app.zitadel_client.ManagementApi` Protocol with plain
dicts so the merge engine can be exercised deterministically — including
create/link/merge, conflict handling, and tombstoning — without a live ZITADEL.
"""
from __future__ import annotations

import itertools

from app.models import IdentityLink, Membership, UserAccount, UserGrant


class MockManagementApi:
    def __init__(self) -> None:
        self.users: dict[str, UserAccount] = {}
        self.idp_links: dict[str, list[IdentityLink]] = {}
        self.grants: dict[str, list[UserGrant]] = {}
        self.memberships: dict[str, list[Membership]] = {}
        self.metadata: dict[tuple[str, str], str] = {}
        self.deactivated: set[str] = set()
        self._grant_ids = itertools.count(1)
        self.calls: list[str] = []

    # -- test fixtures ----------------------------------------------------
    def create_user(
        self,
        user_id: str,
        email: str | None = None,
        is_email_verified: bool = False,
        idp_links: list[IdentityLink] | None = None,
        grants: list[UserGrant] | None = None,
        memberships: list[Membership] | None = None,
    ) -> UserAccount:
        user = UserAccount(
            user_id=user_id,
            user_name=user_id,
            email=email,
            is_email_verified=is_email_verified,
            state="USER_STATE_ACTIVE",
        )
        self.users[user_id] = user
        self.idp_links[user_id] = list(idp_links or [])
        self.grants[user_id] = list(grants or [])
        self.memberships[user_id] = list(memberships or [])
        return user

    # -- reads ------------------------------------------------------------
    def get_user(self, user_id: str) -> UserAccount:
        self.calls.append(f"get_user:{user_id}")
        if user_id not in self.users:
            raise KeyError(user_id)
        return self.users[user_id].model_copy(deep=True)

    def find_users_by_email(self, email: str) -> list[UserAccount]:
        target = email.strip().lower()
        return [
            u.model_copy(deep=True)
            for u in self.users.values()
            if (u.email or "").strip().lower() == target
        ]

    def list_idp_links(self, user_id: str) -> list[IdentityLink]:
        return [link.model_copy(deep=True) for link in self.idp_links.get(user_id, [])]

    def list_user_grants(self, user_id: str) -> list[UserGrant]:
        return [g.model_copy(deep=True) for g in self.grants.get(user_id, [])]

    def list_memberships(self, user_id: str) -> list[Membership]:
        return [m.model_copy(deep=True) for m in self.memberships.get(user_id, [])]

    # -- writes -----------------------------------------------------------
    def add_idp_link(self, user_id: str, link: IdentityLink) -> None:
        self.calls.append(f"add_idp_link:{user_id}:{link.idp_id}:{link.external_user_id}")
        self.idp_links.setdefault(user_id, []).append(link.model_copy(deep=True))

    def remove_idp_link(self, user_id: str, idp_id: str, external_user_id: str) -> None:
        self.calls.append(f"remove_idp_link:{user_id}:{idp_id}:{external_user_id}")
        self.idp_links[user_id] = [
            link
            for link in self.idp_links.get(user_id, [])
            if not (link.idp_id == idp_id and link.external_user_id == external_user_id)
        ]

    def add_user_grant(self, user_id: str, project_id: str, role_keys: list[str]) -> str:
        grant_id = f"grant-{next(self._grant_ids)}"
        self.calls.append(f"add_user_grant:{user_id}:{project_id}")
        self.grants.setdefault(user_id, []).append(
            UserGrant(grant_id=grant_id, project_id=project_id, role_keys=list(role_keys))
        )
        return grant_id

    def remove_user_grant(self, user_id: str, grant_id: str) -> None:
        self.calls.append(f"remove_user_grant:{user_id}:{grant_id}")
        self.grants[user_id] = [
            g for g in self.grants.get(user_id, []) if g.grant_id != grant_id
        ]

    def add_membership(self, user_id: str, membership: Membership) -> None:
        self.calls.append(
            f"add_membership:{user_id}:{membership.membership_type}:{membership.aggregate_id}"
        )
        self.memberships.setdefault(user_id, []).append(membership.model_copy(deep=True))

    def remove_membership(self, user_id: str, membership: Membership) -> None:
        self.calls.append(
            f"remove_membership:{user_id}:{membership.membership_type}:{membership.aggregate_id}"
        )
        self.memberships[user_id] = [
            m
            for m in self.memberships.get(user_id, [])
            if not (
                m.membership_type == membership.membership_type
                and m.aggregate_id == membership.aggregate_id
            )
        ]

    def deactivate_user(self, user_id: str) -> None:
        self.calls.append(f"deactivate_user:{user_id}")
        self.deactivated.add(user_id)
        if user_id in self.users:
            self.users[user_id] = self.users[user_id].model_copy(
                update={"state": "USER_STATE_INACTIVE"}
            )

    def set_user_metadata(self, user_id: str, key: str, value: str) -> None:
        self.calls.append(f"set_user_metadata:{user_id}:{key}")
        self.metadata[(user_id, key)] = value
