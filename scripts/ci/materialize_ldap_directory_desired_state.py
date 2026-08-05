"""Materialize the reviewed LDAP desired-state integration once.

This one-shot helper appends the narrow component transport and re-export hooks
needed by the already-authored stateful service. The workflow deletes this file
and itself before committing the resulting production tree.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _append_once(path: Path, marker: str, block: str) -> None:
    """Append ``block`` exactly once after confirming the expected module exists."""
    text = path.read_text(encoding="utf-8")
    if marker in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text + "\n" + block.rstrip() + "\n", encoding="utf-8")


def _materialize_directory_exports() -> None:
    """Import the state extension after the pure preflight module is defined."""
    path = ROOT / "services" / "account_unification" / "app" / "directory_federation.py"
    block = '''# Stateful desired-state routes are imported only after the pure preflight
# models, validator, and router above are fully defined. This avoids a circular
# initialization hazard while keeping the public module contract stable.
from .directory_federation_state import (  # noqa: E402,F401
    DIRECTORY_FEDERATION_NAMESPACE,
    DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
    DirectoryConvergenceState,
    DirectoryFederationService,
    DirectoryFederationStatus,
)
'''
    _append_once(path, "DirectoryFederationStatus,", block)


def _materialize_http_component_adapter() -> None:
    """Attach a narrow Keycloak component transport to the product Admin API."""
    path = (
        ROOT
        / "services"
        / "account_unification"
        / "app"
        / "product_keycloak_client.py"
    )
    block = '''# LDAP user-storage component transport. The methods deliberately reuse the
# existing client, admin URL builder, and exact one-shot 401 reauthentication
# boundary instead of creating a second token cache.
_DIRECTORY_COMPONENT_PROVIDER_TYPE = "org.keycloak.storage.UserStorageProvider"


def _validate_directory_component_id(component_id: str) -> str:
    """Return one opaque Keycloak component ID or reject unsafe path material."""
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~-"
    valid = (
        isinstance(component_id, str)
        and 1 <= len(component_id) <= 255
        and component_id not in {".", ".."}
        and all(character in allowed for character in component_id)
    )
    if not valid:
        raise ValueError("component_id is not a safe opaque path segment")
    return component_id


def _list_user_storage_components(
    self: ProductHttpAdminApi,
    name: str,
) -> list[dict]:
    """List Keycloak LDAP user-storage components matching one safe name."""
    if not isinstance(name, str) or not name or len(name) > 63:
        raise ValueError("directory name is invalid")
    response = self._send_with_reauth(
        lambda: self._client.get(
            self._admin_url("components"),
            params={
                "name": name,
                "type": _DIRECTORY_COMPONENT_PROVIDER_TYPE,
            },
        )
    )
    payload = response.json()
    if not isinstance(payload, list) or any(
        not isinstance(component, dict) for component in payload
    ):
        raise RuntimeError("Keycloak component list response is invalid")
    return [dict(component) for component in payload]


def _create_user_storage_component(
    self: ProductHttpAdminApi,
    payload: dict,
) -> str | None:
    """Create one Keycloak LDAP component and return its Location identifier."""
    response = self._send_with_reauth(
        lambda: self._client.post(
            self._admin_url("components"),
            json=payload,
        )
    )
    location = response.headers.get("Location")
    if not location:
        return None
    component_id = location.rstrip("/").rsplit("/", 1)[-1]
    return _validate_directory_component_id(component_id)


def _update_user_storage_component(
    self: ProductHttpAdminApi,
    component_id: str,
    payload: dict,
) -> None:
    """Replace one validated Keycloak LDAP component representation."""
    safe_component_id = _validate_directory_component_id(component_id)
    self._send_with_reauth(
        lambda: self._client.put(
            self._admin_url(f"components/{safe_component_id}"),
            json=payload,
        )
    )


def _delete_user_storage_component(
    self: ProductHttpAdminApi,
    component_id: str,
) -> None:
    """Delete one validated Keycloak LDAP component."""
    safe_component_id = _validate_directory_component_id(component_id)
    self._send_with_reauth(
        lambda: self._client.delete(
            self._admin_url(f"components/{safe_component_id}"),
        )
    )


setattr(
    ProductHttpAdminApi,
    "list_user_storage_components",
    _list_user_storage_components,
)
setattr(
    ProductHttpAdminApi,
    "create_user_storage_component",
    _create_user_storage_component,
)
setattr(
    ProductHttpAdminApi,
    "update_user_storage_component",
    _update_user_storage_component,
)
setattr(
    ProductHttpAdminApi,
    "delete_user_storage_component",
    _delete_user_storage_component,
)
'''
    _append_once(path, "_validate_directory_component_id", block)


def _materialize_mock_component_adapter() -> None:
    """Attach deterministic LDAP component behavior to the shared product mock."""
    path = (
        ROOT
        / "services"
        / "account_unification"
        / "tests"
        / "mock_product_keycloak.py"
    )
    block = '''# Deterministic Keycloak component behavior for directory desired-state tests.
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
'''
    _append_once(path, "_directory_component_store", block)


def main() -> int:
    """Materialize the bounded integration and return zero."""
    _materialize_directory_exports()
    _materialize_http_component_adapter()
    _materialize_mock_component_adapter()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
