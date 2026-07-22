"""In-memory fake of the Keycloak Admin REST API for unit tests.

Implements the :class:`app.keycloak_client.AdminApi` Protocol with plain dicts
so the merge engine and the SCIM shim can be exercised deterministically —
including create/link/merge, conflict handling, tombstoning, and inbound SCIM
provisioning — without a live Keycloak.
"""
from __future__ import annotations

import itertools

from app.models import FederatedIdentity, GroupMembership, RoleMapping, UserAccount


class MockKeycloakAdminApi:
    def __init__(self) -> None:
        self.users: dict[str, UserAccount] = {}
        self.federated: dict[str, list[FederatedIdentity]] = {}
        self.roles: dict[str, list[RoleMapping]] = {}
        self.groups: dict[str, list[GroupMembership]] = {}
        self.attributes: dict[tuple[str, str], str] = {}
        self.deactivated: set[str] = set()
        self._user_ids = itertools.count(1)
        self.calls: list[str] = []

    # -- test fixtures ----------------------------------------------------
    def create_test_user(
        self,
        user_id: str,
        email: str | None = None,
        is_email_verified: bool = False,
        federated_identities: list[FederatedIdentity] | None = None,
        role_mappings: list[RoleMapping] | None = None,
        group_memberships: list[GroupMembership] | None = None,
    ) -> UserAccount:
        user = UserAccount(
            user_id=user_id,
            user_name=user_id,
            email=email,
            is_email_verified=is_email_verified,
            state="active",
        )
        self.users[user_id] = user
        self.federated[user_id] = list(federated_identities or [])
        self.roles[user_id] = list(role_mappings or [])
        self.groups[user_id] = list(group_memberships or [])
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

    def find_user_by_username(self, username: str) -> UserAccount | None:
        for u in self.users.values():
            if (u.user_name or "").lower() == username.lower():
                return u.model_copy(deep=True)
        return None

    def list_federated_identities(self, user_id: str) -> list[FederatedIdentity]:
        return [f.model_copy(deep=True) for f in self.federated.get(user_id, [])]

    def list_role_mappings(self, user_id: str) -> list[RoleMapping]:
        return [r.model_copy(deep=True) for r in self.roles.get(user_id, [])]

    def list_group_memberships(self, user_id: str) -> list[GroupMembership]:
        return [g.model_copy(deep=True) for g in self.groups.get(user_id, [])]

    # -- provisioning (SCIM) ----------------------------------------------
    def create_user(self, user: UserAccount) -> str:
        user_id = user.user_id or f"kc-{next(self._user_ids)}"
        self.calls.append(f"create_user:{user.user_name}")
        stored = user.model_copy(deep=True, update={"user_id": user_id})
        self.users[user_id] = stored
        self.federated.setdefault(user_id, [])
        self.roles.setdefault(user_id, [])
        self.groups.setdefault(user_id, [])
        return user_id

    def replace_user(self, user_id: str, user: UserAccount) -> None:
        self.calls.append(f"replace_user:{user_id}")
        if user_id not in self.users:
            raise KeyError(user_id)
        self.users[user_id] = user.model_copy(deep=True, update={"user_id": user_id})

    # -- writes -----------------------------------------------------------
    def add_federated_identity(self, user_id: str, identity: FederatedIdentity) -> None:
        self.calls.append(
            f"add_federated_identity:{user_id}:{identity.identity_provider}:"
            f"{identity.external_user_id}"
        )
        self.federated.setdefault(user_id, []).append(identity.model_copy(deep=True))

    def remove_federated_identity(self, user_id: str, identity_provider: str) -> None:
        self.calls.append(f"remove_federated_identity:{user_id}:{identity_provider}")
        self.federated[user_id] = [
            f
            for f in self.federated.get(user_id, [])
            if f.identity_provider != identity_provider
        ]

    def add_role_mapping(self, user_id: str, role: RoleMapping) -> None:
        self.calls.append(f"add_role_mapping:{user_id}:{role.client_id}:{role.role_name}")
        self.roles.setdefault(user_id, []).append(role.model_copy(deep=True))

    def remove_role_mapping(self, user_id: str, role: RoleMapping) -> None:
        self.calls.append(
            f"remove_role_mapping:{user_id}:{role.client_id}:{role.role_name}"
        )
        self.roles[user_id] = [
            r
            for r in self.roles.get(user_id, [])
            if not (r.client_id == role.client_id and r.role_name == role.role_name)
        ]

    def add_group_membership(self, user_id: str, group: GroupMembership) -> None:
        self.calls.append(f"add_group_membership:{user_id}:{group.group_id}")
        self.groups.setdefault(user_id, []).append(group.model_copy(deep=True))

    def remove_group_membership(self, user_id: str, group: GroupMembership) -> None:
        self.calls.append(f"remove_group_membership:{user_id}:{group.group_id}")
        self.groups[user_id] = [
            g for g in self.groups.get(user_id, []) if g.group_id != group.group_id
        ]

    def deactivate_user(self, user_id: str) -> None:
        self.calls.append(f"deactivate_user:{user_id}")
        self.deactivated.add(user_id)
        if user_id in self.users:
            self.users[user_id] = self.users[user_id].model_copy(
                update={"state": "disabled"}
            )

    def set_user_attribute(self, user_id: str, key: str, value: str) -> None:
        self.calls.append(f"set_user_attribute:{user_id}:{key}")
        self.attributes[(user_id, key)] = value
        if key == "scim_external_id" and user_id in self.users:
            self.users[user_id] = self.users[user_id].model_copy(
                update={"external_id": value}
            )

    # -- identity providers (runtime federation registry) -------------------
    def get_identity_provider(self, provider_alias: str) -> dict | None:
        self.calls.append(f"get_identity_provider:{provider_alias}")
        return getattr(self, "identity_providers", {}).get(provider_alias)

    def create_identity_provider(self, provider_payload: dict) -> None:
        alias = provider_payload["alias"]
        self.calls.append(f"create_identity_provider:{alias}")
        if not hasattr(self, "identity_providers"):
            self.identity_providers: dict[str, dict] = {}
        self.identity_providers[alias] = dict(provider_payload)

    def update_identity_provider(
        self, provider_alias: str, provider_payload: dict
    ) -> None:
        self.calls.append(f"update_identity_provider:{provider_alias}")
        if not hasattr(self, "identity_providers"):
            self.identity_providers = {}
        self.identity_providers[provider_alias] = dict(provider_payload)

    def delete_identity_provider(self, provider_alias: str) -> None:
        self.calls.append(f"delete_identity_provider:{provider_alias}")
        getattr(self, "identity_providers", {}).pop(provider_alias, None)

    # -- self-registration support ------------------------------------------
    def list_users(self, first_result: int, max_results: int) -> list[UserAccount]:
        self.calls.append(f"list_users:{first_result}:{max_results}")
        ordered = list(self.users.values())
        return ordered[first_result : first_result + max_results]

    def reset_user_password(self, user_id: str, password_value: str) -> None:
        self.calls.append(f"reset_user_password:{user_id}")
        if user_id not in self.users:
            raise KeyError(user_id)
        if not hasattr(self, "credentials"):
            self.credentials: dict[str, list[dict]] = {}
        entries = self.credentials.setdefault(user_id, [])
        entries[:] = [item for item in entries if item.get("type") != "password"]
        entries.append({"id": f"cred-pw-{user_id}", "type": "password"})

    def set_user_required_actions(self, user_id: str, action_aliases: list[str]) -> None:
        self.calls.append(f"set_user_required_actions:{user_id}")
        if not hasattr(self, "required_actions"):
            self.required_actions: dict[str, list[str]] = {}
        self.required_actions[user_id] = list(action_aliases)

    def list_user_credentials(self, user_id: str) -> list[dict]:
        self.calls.append(f"list_user_credentials:{user_id}")
        return list(getattr(self, "credentials", {}).get(user_id, []))

    def delete_user_credential(self, user_id: str, credential_id: str) -> None:
        self.calls.append(f"delete_user_credential:{user_id}:{credential_id}")
        entries = getattr(self, "credentials", {}).get(user_id, [])
        entries[:] = [item for item in entries if item.get("id") != credential_id]

    def add_test_passkey(self, user_id: str) -> None:
        """Test fixture: mark a user as having enrolled a passkey."""
        if not hasattr(self, "credentials"):
            self.credentials = {}
        self.credentials.setdefault(user_id, []).append(
            {"id": f"cred-wa-{user_id}", "type": "webauthn-passwordless"}
        )
