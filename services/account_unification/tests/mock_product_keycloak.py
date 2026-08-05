"""Product-capable in-memory Keycloak Admin API test double."""
from __future__ import annotations

from .mock_keycloak import MockKeycloakAdminApi


class MockProductKeycloakAdminApi(MockKeycloakAdminApi):
    """Extend the core mock with registration and federation operations."""

    def __init__(self) -> None:
        """Create empty product-specific stores."""
        super().__init__()
        self.identity_providers: dict[str, dict] = {}
        self.action_emails: dict[str, dict] = {}

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

# Deterministic Keycloak component behavior for directory desired-state tests.
def _directory_component_store(self: MockProductAdminApi) -> dict[str, dict]:
    """Return the lazily initialized component store on the shared mock."""
    store = getattr(self, "user_storage_components", None)
    if store is None:
        store = {}
        setattr(self, "user_storage_components", store)
        setattr(self, "_directory_component_sequence", 0)
    return store


def _clone_directory_component(component: dict) -> dict:
    """Return a defensive copy of one component representation."""
    clone = dict(component)
    config = component.get("config")
    if isinstance(config, dict):
        clone["config"] = {
            key: list(values) if isinstance(values, list) else values
            for key, values in config.items()
        }
    return clone


def _mock_list_user_storage_components(
    self: MockProductAdminApi,
    name: str,
) -> list[dict]:
    """List every mock component with one exact name."""
    self.calls.append(f"list_user_storage_components:{name}")
    return [
        _clone_directory_component(component)
        for component in _directory_component_store(self).values()
        if component.get("name") == name
    ]


def _mock_create_user_storage_component(
    self: MockProductAdminApi,
    payload: dict,
) -> str:
    """Create one mock component with a deterministic identifier."""
    sequence = int(getattr(self, "_directory_component_sequence", 0)) + 1
    setattr(self, "_directory_component_sequence", sequence)
    component_id = f"directory-component-{sequence}"
    component = _clone_directory_component(payload)
    component["id"] = component_id
    _directory_component_store(self)[component_id] = component
    self.calls.append(f"create_user_storage_component:{component_id}")
    return component_id


def _mock_update_user_storage_component(
    self: MockProductAdminApi,
    component_id: str,
    payload: dict,
) -> None:
    """Replace one existing mock component."""
    store = _directory_component_store(self)
    if component_id not in store:
        raise KeyError(component_id)
    component = _clone_directory_component(payload)
    component["id"] = component_id
    store[component_id] = component
    self.calls.append(f"update_user_storage_component:{component_id}")


def _mock_delete_user_storage_component(
    self: MockProductAdminApi,
    component_id: str,
) -> None:
    """Delete one existing mock component."""
    del _directory_component_store(self)[component_id]
    self.calls.append(f"delete_user_storage_component:{component_id}")


setattr(
    MockProductAdminApi,
    "list_user_storage_components",
    _mock_list_user_storage_components,
)
setattr(
    MockProductAdminApi,
    "create_user_storage_component",
    _mock_create_user_storage_component,
)
setattr(
    MockProductAdminApi,
    "update_user_storage_component",
    _mock_update_user_storage_component,
)
setattr(
    MockProductAdminApi,
    "delete_user_storage_component",
    _mock_delete_user_storage_component,
)
