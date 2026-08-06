"""Product-capable in-memory Keycloak Admin API test double."""
from __future__ import annotations

from .mock_keycloak import MockKeycloakAdminApi


class MockProductKeycloakAdminApi(MockKeycloakAdminApi):
    """Extend the core mock with registration and federation operations."""

    def __init__(self) -> None:
        """Create empty product-specific stores."""
        super().__init__()
        self.identity_providers: dict[str, dict] = {}
        self.user_storage_components: dict[str, dict] = {}
        self.relying_party_clients: dict[str, dict] = {}
        self._directory_component_sequence = 0
        self._relying_party_sequence = 0
        self.action_emails: dict[str, dict] = {}

    @staticmethod
    def _clone_component(component: dict) -> dict:
        """Return a defensive copy of one component representation."""
        clone = dict(component)
        config = component.get("config")
        if isinstance(config, dict):
            clone["config"] = {
                key: list(values) if isinstance(values, list) else values
                for key, values in config.items()
            }
        return clone

    @staticmethod
    def _clone_client(client: dict) -> dict:
        """Return a defensive copy of one Keycloak client representation."""
        clone = dict(client)
        for field_name in ("redirectUris", "webOrigins", "defaultClientScopes"):
            values = client.get(field_name)
            if isinstance(values, list):
                clone[field_name] = list(values)
        attributes = client.get("attributes")
        if isinstance(attributes, dict):
            clone["attributes"] = dict(attributes)
        return clone

    def send_execute_actions_email(
        self,
        user_id: str,
        action_aliases: list[str],
        *,
        client_id: str,
        redirect_uri: str,
        lifespan_seconds: int,
    ) -> None:
        """Record one verification and passkey-enrollment email request."""
        self.calls.append(f"send_execute_actions_email:{user_id}")
        if user_id not in self.users:
            raise KeyError(user_id)
        self.action_emails[user_id] = {
            "action_aliases": list(action_aliases),
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "lifespan_seconds": lifespan_seconds,
        }

    def delete_user(self, user_id: str) -> None:
        """Delete a newly created account during rollback."""
        self.calls.append(f"delete_user:{user_id}")
        self.users.pop(user_id, None)
        self.federated.pop(user_id, None)
        self.roles.pop(user_id, None)
        self.groups.pop(user_id, None)
        self.action_emails.pop(user_id, None)
        self.deactivated.discard(user_id)
        for attribute in [
            key for key in self.attributes if key[0] == user_id
        ]:
            self.attributes.pop(attribute, None)

    def get_identity_provider(
        self, provider_alias: str
    ) -> dict | None:
        """Return a defensive copy of one applied provider."""
        self.calls.append(f"get_identity_provider:{provider_alias}")
        provider = self.identity_providers.get(provider_alias)
        return dict(provider) if provider is not None else None

    def create_identity_provider(self, provider_payload: dict) -> None:
        """Create one applied identity provider."""
        alias = provider_payload["alias"]
        self.calls.append(f"create_identity_provider:{alias}")
        self.identity_providers[alias] = dict(provider_payload)

    def update_identity_provider(
        self, provider_alias: str, provider_payload: dict
    ) -> None:
        """Replace one applied identity provider."""
        self.calls.append(f"update_identity_provider:{provider_alias}")
        self.identity_providers[provider_alias] = dict(provider_payload)

    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete one applied identity provider."""
        self.calls.append(f"delete_identity_provider:{provider_alias}")
        self.identity_providers.pop(provider_alias, None)

    def list_user_storage_components(self, component_name: str) -> list[dict]:
        """Return defensive copies of components with one exact name."""
        self.calls.append(f"list_user_storage_components:{component_name}")
        return [
            self._clone_component(component)
            for component in self.user_storage_components.values()
            if component.get("name") == component_name
        ]

    def create_user_storage_component(self, component_payload: dict) -> str:
        """Create one deterministic in-memory user-storage component."""
        self._directory_component_sequence += 1
        component_id = (
            f"directory-component-{self._directory_component_sequence}"
        )
        component = self._clone_component(component_payload)
        component["id"] = component_id
        component.setdefault("parentId", "cwl")
        self.user_storage_components[component_id] = component
        self.calls.append(f"create_user_storage_component:{component_id}")
        return component_id

    def update_user_storage_component(
        self, component_id: str, component_payload: dict
    ) -> None:
        """Replace one existing deterministic in-memory component."""
        if component_id not in self.user_storage_components:
            raise KeyError(component_id)
        component = self._clone_component(component_payload)
        component["id"] = component_id
        component.setdefault("parentId", "cwl")
        self.user_storage_components[component_id] = component
        self.calls.append(f"update_user_storage_component:{component_id}")

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one existing deterministic in-memory component."""
        del self.user_storage_components[component_id]
        self.calls.append(f"delete_user_storage_component:{component_id}")

    def list_relying_party_clients(self, client_id: str) -> list[dict]:
        """Return defensive copies of clients with one exact public ID."""
        self.calls.append(f"list_relying_party_clients:{client_id}")
        return [
            self._clone_client(client)
            for client in self.relying_party_clients.values()
            if client.get("clientId") == client_id
        ]

    def create_relying_party_client(self, client_payload: dict) -> str:
        """Create one deterministic in-memory relying-party client."""
        self._relying_party_sequence += 1
        client_uuid = f"relying-party-{self._relying_party_sequence}"
        client = self._clone_client(client_payload)
        client["id"] = client_uuid
        self.relying_party_clients[client_uuid] = client
        self.calls.append(f"create_relying_party_client:{client_uuid}")
        return client_uuid

    def update_relying_party_client(
        self,
        client_uuid: str,
        client_payload: dict,
    ) -> None:
        """Replace one existing deterministic in-memory relying party."""
        if client_uuid not in self.relying_party_clients:
            raise KeyError(client_uuid)
        client = self._clone_client(client_payload)
        client["id"] = client_uuid
        self.relying_party_clients[client_uuid] = client
        self.calls.append(f"update_relying_party_client:{client_uuid}")

    def delete_relying_party_client(self, client_uuid: str) -> None:
        """Delete one existing deterministic in-memory relying party."""
        del self.relying_party_clients[client_uuid]
        self.calls.append(f"delete_relying_party_client:{client_uuid}")
