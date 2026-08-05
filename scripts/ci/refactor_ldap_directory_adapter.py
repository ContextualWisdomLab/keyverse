"""Move LDAP component transport from dynamic hooks into typed classes once."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _insert_before_class_end(source: str, class_name: str, block: str) -> str:
    """Insert an indented method block after the final class statement."""
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == class_name
    )
    lines = source.splitlines(keepends=True)
    insertion_index = node.end_lineno
    if insertion_index and not lines[insertion_index - 1].endswith("\n"):
        lines[insertion_index - 1] += "\n"
    lines.insert(insertion_index, "\n" + block.rstrip() + "\n")
    return "".join(lines)


def _refactor_product_client() -> None:
    """Declare component methods on the protocol and concrete HTTP adapter."""
    path = (
        ROOT
        / "services"
        / "account_unification"
        / "app"
        / "product_keycloak_client.py"
    )
    text = path.read_text(encoding="utf-8")
    marker = "# LDAP user-storage component transport."
    if marker not in text:
        raise RuntimeError("dynamic LDAP transport marker was not found")
    base = text.split(marker, 1)[0].rstrip() + "\n"
    protocol = '''    def list_user_storage_components(self, name: str) -> list[dict]:
        """List LDAP user-storage components matching one directory name."""
        ...

    def create_user_storage_component(self, payload: dict) -> str | None:
        """Create one LDAP user-storage component and return its identifier."""
        ...

    def update_user_storage_component(
        self,
        component_id: str,
        payload: dict,
    ) -> None:
        """Replace one existing LDAP user-storage component."""
        ...

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one existing LDAP user-storage component."""
        ...
'''
    base = _insert_before_class_end(base, "ProductAdminApi", protocol)
    methods = '''    def list_user_storage_components(self, name: str) -> list[dict]:
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

    def create_user_storage_component(self, payload: dict) -> str | None:
        """Create one Keycloak LDAP component and parse its Location identifier."""
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

    def update_user_storage_component(
        self,
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

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one validated Keycloak LDAP component."""
        safe_component_id = _validate_directory_component_id(component_id)
        self._send_with_reauth(
            lambda: self._client.delete(
                self._admin_url(f"components/{safe_component_id}"),
            )
        )
'''
    base = _insert_before_class_end(base, "ProductHttpAdminApi", methods)
    tail = '''
# LDAP user-storage component transport uses the existing token and HTTP client.
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
'''
    path.write_text(base.rstrip() + tail, encoding="utf-8")


def _refactor_product_mock() -> None:
    """Declare deterministic component methods directly on the shared mock."""
    path = (
        ROOT
        / "services"
        / "account_unification"
        / "tests"
        / "mock_product_keycloak.py"
    )
    text = path.read_text(encoding="utf-8")
    marker = (
        "# Deterministic Keycloak component behavior for directory desired-state tests."
    )
    if marker not in text:
        raise RuntimeError("dynamic LDAP mock marker was not found")
    base = text.split(marker, 1)[0].rstrip() + "\n"
    methods = '''    def _directory_component_store(self) -> dict[str, dict]:
        """Return the lazily initialized component store."""
        store = getattr(self, "user_storage_components", None)
        if store is None:
            store = {}
            self.user_storage_components = store
            self._directory_component_sequence = 0
        return store

    @staticmethod
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

    def list_user_storage_components(self, name: str) -> list[dict]:
        """List every mock component with one exact name."""
        self.calls.append(f"list_user_storage_components:{name}")
        return [
            self._clone_directory_component(component)
            for component in self._directory_component_store().values()
            if component.get("name") == name
        ]

    def create_user_storage_component(self, payload: dict) -> str:
        """Create one mock component with a deterministic identifier."""
        sequence = int(getattr(self, "_directory_component_sequence", 0)) + 1
        self._directory_component_sequence = sequence
        component_id = f"directory-component-{sequence}"
        component = self._clone_directory_component(payload)
        component["id"] = component_id
        self._directory_component_store()[component_id] = component
        self.calls.append(f"create_user_storage_component:{component_id}")
        return component_id

    def update_user_storage_component(
        self,
        component_id: str,
        payload: dict,
    ) -> None:
        """Replace one existing mock component."""
        store = self._directory_component_store()
        if component_id not in store:
            raise KeyError(component_id)
        component = self._clone_directory_component(payload)
        component["id"] = component_id
        store[component_id] = component
        self.calls.append(f"update_user_storage_component:{component_id}")

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one existing mock component."""
        del self._directory_component_store()[component_id]
        self.calls.append(f"delete_user_storage_component:{component_id}")
'''
    path.write_text(
        _insert_before_class_end(base, "MockProductAdminApi", methods),
        encoding="utf-8",
    )


def main() -> int:
    """Materialize typed adapters and return zero."""
    _refactor_product_client()
    _refactor_product_mock()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
