"""Product-capable in-memory Keycloak Admin API test double."""
from __future__ import annotations

from .mock_keycloak import MockKeycloakAdminApi


class MockProductKeycloakAdminApi(MockKeycloakAdminApi):
    """Extend the core mock with registration and federation operations."""

    def __init__(self) -> None:
        """Create empty product-specific stores."""
        super().__init__()
        self.identity_providers: dict[str, dict] = {}
        self.credentials: dict[str, list[dict]] = {}
        self.required_actions: dict[str, list[str]] = {}

    def list_users(self, first_result: int, max_results: int):
        """Return one stable page of users."""
        self.calls.append(f"list_users:{first_result}:{max_results}")
        ordered = list(self.users.values())
        return [
            user.model_copy(deep=True)
            for user in ordered[first_result : first_result + max_results]
        ]

    def reset_user_password(
        self, user_id: str, password_value: str
    ) -> None:
        """Replace one user's password credential without storing its value."""
        self.calls.append(f"reset_user_password:{user_id}")
        if user_id not in self.users:
            raise KeyError(user_id)
        entries = self.credentials.setdefault(user_id, [])
        entries[:] = [
            item for item in entries
            if item.get("type") != "password"
        ]
        entries.append(
            {"id": f"cred-pw-{user_id}", "type": "password"}
        )

    def set_user_required_actions(
        self, user_id: str, action_aliases: list[str]
    ) -> None:
        """Replace one user's pending required actions."""
        self.calls.append(f"set_user_required_actions:{user_id}")
        if user_id not in self.users:
            raise KeyError(user_id)
        self.required_actions[user_id] = list(action_aliases)

    def list_user_credentials(self, user_id: str) -> list[dict]:
        """Return a copy of one user's stored credential metadata."""
        self.calls.append(f"list_user_credentials:{user_id}")
        return [
            dict(item) for item in self.credentials.get(user_id, [])
        ]

    def delete_user_credential(
        self, user_id: str, credential_id: str
    ) -> None:
        """Delete one stored credential by opaque id."""
        self.calls.append(
            f"delete_user_credential:{user_id}:{credential_id}"
        )
        entries = self.credentials.get(user_id, [])
        entries[:] = [
            item for item in entries
            if item.get("id") != credential_id
        ]

    def delete_user(self, user_id: str) -> None:
        """Delete a newly created account during rollback."""
        self.calls.append(f"delete_user:{user_id}")
        self.users.pop(user_id, None)
        self.federated.pop(user_id, None)
        self.roles.pop(user_id, None)
        self.groups.pop(user_id, None)
        self.credentials.pop(user_id, None)
        self.required_actions.pop(user_id, None)
        self.deactivated.discard(user_id)
        for attribute in [
            key for key in self.attributes if key[0] == user_id
        ]:
            self.attributes.pop(attribute, None)

    def get_identity_provider(
        self, provider_alias: str
    ) -> dict | None:
        """Return a defensive copy of one applied provider."""
        self.calls.append(
            f"get_identity_provider:{provider_alias}"
        )
        provider = self.identity_providers.get(provider_alias)
        return dict(provider) if provider is not None else None

    def create_identity_provider(
        self, provider_payload: dict
    ) -> None:
        """Create one applied identity provider."""
        alias = provider_payload["alias"]
        self.calls.append(
            f"create_identity_provider:{alias}"
        )
        self.identity_providers[alias] = dict(provider_payload)

    def update_identity_provider(
        self, provider_alias: str, provider_payload: dict
    ) -> None:
        """Replace one applied identity provider."""
        self.calls.append(
            f"update_identity_provider:{provider_alias}"
        )
        self.identity_providers[provider_alias] = dict(
            provider_payload
        )

    def delete_identity_provider(
        self, provider_alias: str
    ) -> None:
        """Delete one applied identity provider."""
        self.calls.append(
            f"delete_identity_provider:{provider_alias}"
        )
        self.identity_providers.pop(provider_alias, None)

    def add_test_passkey(self, user_id: str) -> None:
        """Mark a user as holding a passwordless WebAuthn credential."""
        self.credentials.setdefault(user_id, []).append(
            {
                "id": f"cred-wa-{user_id}",
                "type": "webauthn-passwordless",
            }
        )
