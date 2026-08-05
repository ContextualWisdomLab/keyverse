"""Product-facing extensions for the Keycloak Admin REST API client.

The core merge/SCIM engine depends only on :class:`AdminApi`. Product features
such as passwordless registration and runtime federation require a wider
surface. This module keeps those concerns modular while preserving the same
authenticated transport, path-safety, and one-shot token refresh behavior.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from .identifiers import InvalidIdentifierError, validate_path_segment
from .keycloak_client import AdminApi, HttpAdminApi, _to_keycloak_user
from .models import (
    FederatedIdentity,
    GroupMembership,
    RoleMapping,
    UserAccount,
)

# ``None`` marks exactly one validated, caller-controlled path segment. The
# whitelist is a second line of defense after every public method validates its
# dynamic values before interpolation.
_ADMIN_PATH_PATTERNS: tuple[tuple[str | None, ...], ...] = (
    ("users",),
    ("users", None),
    ("users", None, "federated-identity"),
    ("users", None, "federated-identity", None),
    ("users", None, "role-mappings"),
    ("users", None, "role-mappings", "realm"),
    ("users", None, "role-mappings", "clients", None),
    ("users", None, "groups"),
    ("users", None, "groups", None),
    ("users", None, "execute-actions-email"),
    ("identity-provider", "instances"),
    ("identity-provider", "instances", None),
    ("components",),
    ("components", None),
)


_DIRECTORY_COMPONENT_PROVIDER_TYPE = "org.keycloak.storage.UserStorageProvider"
_DIRECTORY_NAME_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_DIRECTORY_NAME_EDGE_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")


def _validate_directory_name(name: str) -> str:
    """Return one bounded lowercase ASCII directory slug."""
    valid = (
        isinstance(name, str)
        and 1 <= len(name) <= 63
        and name[0] in _DIRECTORY_NAME_EDGE_ALPHABET
        and name[-1] in _DIRECTORY_NAME_EDGE_ALPHABET
        and all(character in _DIRECTORY_NAME_ALPHABET for character in name)
    )
    if not valid:
        raise ValueError("directory name is invalid")
    return name


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


class ProductAdminApi(AdminApi, Protocol):
    """Extended Keycloak contract used by registration and federation modules."""

    def send_execute_actions_email(
        self,
        user_id: str,
        action_aliases: list[str],
        *,
        client_id: str,
        redirect_uri: str,
        lifespan_seconds: int,
    ) -> None:
        """Send a one-time email link for verified passkey enrollment."""
        ...

    def delete_user(self, user_id: str) -> None:
        """Delete one user during failed registration rollback."""
        ...

    def get_identity_provider(self, provider_alias: str) -> dict | None:
        """Return one identity-provider instance or ``None`` when absent."""
        ...

    def create_identity_provider(self, provider_payload: dict) -> None:
        """Create an identity-provider instance from an admin representation."""
        ...

    def update_identity_provider(
        self, provider_alias: str, provider_payload: dict
    ) -> None:
        """Replace an identity-provider instance."""
        ...

    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete an identity-provider instance."""
        ...

    def list_user_storage_components(self, name: str) -> list[dict]:
        """List exact-name LDAP user-storage component candidates."""
        ...

    def create_user_storage_component(self, component_payload: dict) -> str | None:
        """Create one LDAP user-storage component and return its generated ID."""
        ...

    def update_user_storage_component(
        self, component_id: str, component_payload: dict
    ) -> None:
        """Replace one validated LDAP user-storage component."""
        ...

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one validated LDAP user-storage component."""
        ...


class ProductHttpAdminApi(HttpAdminApi):
    """Keycloak client with registration, federation, and hardened transport."""

    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        token_realm: str | None = None,
        timeout_seconds: float = 10.0,
        transport=None,
    ) -> None:
        """Create a product adapter after validating all configured realms."""
        validate_path_segment(realm, field_name="keycloak_realm")
        self._server_url = server_url.rstrip("/")
        if token_realm is not None:
            validate_path_segment(token_realm, field_name="token_realm")
        super().__init__(
            server_url=server_url,
            realm=realm,
            client_id=client_id,
            client_secret=client_secret,
            token_realm=token_realm,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )

    @staticmethod
    def _safe_segment(value: str, field_name: str) -> str:
        """Return one validated opaque Admin REST path segment."""
        return validate_path_segment(value, field_name=field_name)

    # -- hardened core API -------------------------------------------------
    def get_user(self, user_id: str) -> UserAccount:
        """Return one user after validating its opaque id."""
        return super().get_user(self._safe_segment(user_id, "user_id"))

    def replace_user(self, user_id: str, user: UserAccount) -> None:
        """Replace one user after validating its opaque id."""
        super().replace_user(self._safe_segment(user_id, "user_id"), user)

    def list_federated_identities(
        self, user_id: str
    ) -> list[FederatedIdentity]:
        """List external identities after validating the user id."""
        return super().list_federated_identities(
            self._safe_segment(user_id, "user_id")
        )

    def add_federated_identity(
        self, user_id: str, identity: FederatedIdentity
    ) -> None:
        """Attach an external identity using validated path segments."""
        safe_user_id = self._safe_segment(user_id, "user_id")
        self._safe_segment(identity.identity_provider, "identity_provider")
        super().add_federated_identity(safe_user_id, identity)

    def remove_federated_identity(
        self, user_id: str, identity_provider: str
    ) -> None:
        """Remove an external identity using validated path segments."""
        super().remove_federated_identity(
            self._safe_segment(user_id, "user_id"),
            self._safe_segment(identity_provider, "identity_provider"),
        )

    def list_role_mappings(self, user_id: str) -> list[RoleMapping]:
        """List role mappings after validating the user id."""
        return super().list_role_mappings(
            self._safe_segment(user_id, "user_id")
        )

    def add_role_mapping(self, user_id: str, role: RoleMapping) -> None:
        """Add a role mapping using validated path segments."""
        safe_user_id = self._safe_segment(user_id, "user_id")
        if role.client_id is not None:
            self._safe_segment(role.client_id, "client_id")
        super().add_role_mapping(safe_user_id, role)

    def remove_role_mapping(self, user_id: str, role: RoleMapping) -> None:
        """Remove a role mapping using validated path segments."""
        safe_user_id = self._safe_segment(user_id, "user_id")
        if role.client_id is not None:
            self._safe_segment(role.client_id, "client_id")
        super().remove_role_mapping(safe_user_id, role)

    def list_group_memberships(
        self, user_id: str
    ) -> list[GroupMembership]:
        """List group memberships after validating the user id."""
        return super().list_group_memberships(
            self._safe_segment(user_id, "user_id")
        )

    def add_group_membership(
        self, user_id: str, group: GroupMembership
    ) -> None:
        """Add a group membership using validated path segments."""
        self._safe_segment(group.group_id, "group_id")
        super().add_group_membership(
            self._safe_segment(user_id, "user_id"), group
        )

    def remove_group_membership(
        self, user_id: str, group: GroupMembership
    ) -> None:
        """Remove a group membership using validated path segments."""
        self._safe_segment(group.group_id, "group_id")
        super().remove_group_membership(
            self._safe_segment(user_id, "user_id"), group
        )

    def deactivate_user(self, user_id: str) -> None:
        """Disable one user after validating its opaque id."""
        super().deactivate_user(self._safe_segment(user_id, "user_id"))

    def set_user_attribute(self, user_id: str, key: str, value: str) -> None:
        """Set a user attribute after validating the user id."""
        super().set_user_attribute(
            self._safe_segment(user_id, "user_id"), key, value
        )

    def get_user_attribute(self, user_id: str, key: str) -> str | None:
        """Read a user attribute after validating the user id."""
        return super().get_user_attribute(
            self._safe_segment(user_id, "user_id"), key
        )

    # -- guarded transport -------------------------------------------------
    @staticmethod
    def _validate_admin_suffix(path_segments: tuple[str, ...]) -> None:
        """Require one known Admin REST suffix and validate dynamic segments."""
        for pattern in _ADMIN_PATH_PATTERNS:
            if len(path_segments) != len(pattern):
                continue
            if not all(
                expected is None or expected == actual
                for expected, actual in zip(pattern, path_segments, strict=True)
            ):
                continue
            for index, (expected, actual) in enumerate(
                zip(pattern, path_segments, strict=True)
            ):
                if expected is None:
                    validate_path_segment(
                        actual,
                        field_name=f"admin_path_segment_{index}",
                    )
            return
        raise InvalidIdentifierError(
            "request path is not an allowed Keycloak Admin REST route"
        )

    def _guard_path(self, path: str) -> str:
        """Accept only known Admin REST routes with opaque dynamic segments."""
        if not path.startswith("/"):
            raise InvalidIdentifierError("request path must be absolute")
        if any(character in path for character in ("%", "\\", "?", "#")):
            raise InvalidIdentifierError(
                "request path must not contain encoding or URI delimiters"
            )
        segments = path.split("/")
        if segments[0] != "" or any(segment == "" for segment in segments[1:]):
            raise InvalidIdentifierError(
                "request path must not contain empty segments"
            )
        if any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for segment in segments
            for character in segment
        ):
            raise InvalidIdentifierError(
                "request path must not contain control characters"
            )
        prefix = ("admin", "realms", self._realm)
        path_segments = tuple(segments[1:])
        if path_segments[:3] != prefix:
            raise InvalidIdentifierError(
                "request path must target the configured Keycloak realm"
            )
        self._validate_admin_suffix(path_segments[3:])
        return path

    def _send_with_reauth(
        self, make_request: Callable[[], httpx.Response]
    ) -> httpx.Response:
        """Send a request and retry exactly once after an expired-token 401."""
        response = make_request()
        if response.status_code == 401:
            self._token = None
            response = make_request()
        response.raise_for_status()
        return response

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        """Issue a guarded authenticated GET and parse JSON."""
        guarded_path = self._guard_path(path)
        response = self._send_with_reauth(
            lambda: self._client.get(
                guarded_path, params=params, headers=self._auth_header()
            )
        )
        return response.json()

    def _post(self, path: str, body) -> dict:
        """Issue a guarded authenticated POST and parse optional JSON."""
        guarded_path = self._guard_path(path)
        response = self._send_with_reauth(
            lambda: self._client.post(
                guarded_path, json=body, headers=self._auth_header()
            )
        )
        return response.json() if response.content else {}

    def _put(self, path: str, body: dict) -> None:
        """Issue a guarded authenticated PUT."""
        guarded_path = self._guard_path(path)
        self._send_with_reauth(
            lambda: self._client.put(
                guarded_path, json=body, headers=self._auth_header()
            )
        )

    def _delete(self, path: str, body=None) -> None:
        """Issue a guarded authenticated DELETE with optional JSON."""
        guarded_path = self._guard_path(path)

        def send_delete() -> httpx.Response:
            """Build and send one DELETE using the current bearer token."""
            request = self._client.build_request(
                "DELETE", guarded_path, json=body, headers=self._auth_header()
            )
            return self._client.send(request)

        self._send_with_reauth(send_delete)

    # -- product extensions ------------------------------------------------
    def create_user(self, user: UserAccount) -> str:
        """Create a user, refreshing an expired token before retrying once."""
        path = self._guard_path(f"/admin/realms/{self._realm}/users")
        response = self._send_with_reauth(
            lambda: self._client.post(
                path,
                json=_to_keycloak_user(user),
                headers=self._auth_header(),
            )
        )
        location = response.headers.get("Location", "")
        if location:
            created_user_id = location.rstrip("/").rsplit("/", 1)[-1]
            return validate_path_segment(
                created_user_id, field_name="created_user_id"
            )
        found = self.find_user_by_username(user.user_name or "")
        if found is None:
            return ""
        return validate_path_segment(
            found.user_id, field_name="created_user_id"
        )

    def send_execute_actions_email(
        self,
        user_id: str,
        action_aliases: list[str],
        *,
        client_id: str,
        redirect_uri: str,
        lifespan_seconds: int,
    ) -> None:
        """Send a bounded one-time email for verification and passkey setup."""
        safe_user_id = self._safe_segment(user_id, "user_id")
        safe_client_id = self._safe_segment(client_id, "client_id")
        parsed_redirect = urlsplit(redirect_uri)
        if (
            parsed_redirect.scheme != "https"
            or not parsed_redirect.hostname
            or parsed_redirect.username is not None
            or parsed_redirect.password is not None
            or parsed_redirect.fragment
        ):
            raise ValueError("redirect_uri must be an absolute HTTPS URI")
        if lifespan_seconds <= 0:
            raise ValueError("lifespan_seconds must be positive")
        if not action_aliases or any(
            not alias
            or len(alias) > 128
            or any(ord(character) < 0x20 for character in alias)
            for alias in action_aliases
        ):
            raise ValueError("action_aliases must contain bounded action names")
        path = self._guard_path(
            f"/admin/realms/{self._realm}/users/{safe_user_id}/"
            "execute-actions-email"
        )
        self._send_with_reauth(
            lambda: self._client.put(
                path,
                params={
                    "client_id": safe_client_id,
                    "redirect_uri": redirect_uri,
                    "lifespan": lifespan_seconds,
                },
                json=list(action_aliases),
                headers=self._auth_header(),
            )
        )

    def delete_user(self, user_id: str) -> None:
        """Delete one user during failed registration rollback."""
        safe_user_id = self._safe_segment(user_id, "user_id")
        self._delete(f"/admin/realms/{self._realm}/users/{safe_user_id}")

    def get_identity_provider(self, provider_alias: str) -> dict | None:
        """Return an identity provider or ``None`` for a Keycloak 404."""
        safe_alias = self._safe_segment(provider_alias, "provider_alias")
        try:
            data = self._get(
                f"/admin/realms/{self._realm}/identity-provider/instances/"
                f"{safe_alias}"
            )
        except httpx.HTTPStatusError as error:
            if error.response.status_code == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    def create_identity_provider(self, provider_payload: dict) -> None:
        """Create one Keycloak identity-provider instance."""
        self._safe_segment(provider_payload.get("alias"), "provider_alias")
        self._post(
            f"/admin/realms/{self._realm}/identity-provider/instances",
            provider_payload,
        )

    def update_identity_provider(
        self, provider_alias: str, provider_payload: dict
    ) -> None:
        """Replace one Keycloak identity-provider instance."""
        safe_alias = self._safe_segment(provider_alias, "provider_alias")
        self._put(
            f"/admin/realms/{self._realm}/identity-provider/instances/"
            f"{safe_alias}",
            provider_payload,
        )

    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete one Keycloak identity-provider instance."""
        safe_alias = self._safe_segment(provider_alias, "provider_alias")
        self._delete(
            f"/admin/realms/{self._realm}/identity-provider/instances/"
            f"{safe_alias}"
        )


    def _absolute_admin_url(self, path: str) -> str:
        """Return one guarded absolute Admin REST URL for direct response access."""
        return f"{self._server_url}{self._guard_path(path)}"

    def list_user_storage_components(self, name: str) -> list[dict]:
        """List Keycloak LDAP user-storage components matching one safe name."""
        safe_name = _validate_directory_name(name)
        response = self._send_with_reauth(
            lambda: self._client.get(
                self._absolute_admin_url(
                    f"/admin/realms/{self._realm}/components"
                ),
                params={
                    "name": safe_name,
                    "type": _DIRECTORY_COMPONENT_PROVIDER_TYPE,
                },
                headers=self._auth_header(),
            )
        )
        payload = response.json()
        if not isinstance(payload, list) or any(
            not isinstance(component, dict) for component in payload
        ):
            raise RuntimeError("Keycloak component list response is invalid")
        return [dict(component) for component in payload]

    def create_user_storage_component(
        self,
        component_payload: dict,
    ) -> str | None:
        """Create one LDAP component and return its validated Location identifier."""
        response = self._send_with_reauth(
            lambda: self._client.post(
                self._absolute_admin_url(
                    f"/admin/realms/{self._realm}/components"
                ),
                json=component_payload,
                headers=self._auth_header(),
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
        component_payload: dict,
    ) -> None:
        """Replace one validated LDAP user-storage component representation."""
        safe_component_id = _validate_directory_component_id(component_id)
        self._send_with_reauth(
            lambda: self._client.put(
                self._absolute_admin_url(
                    f"/admin/realms/{self._realm}/components/{safe_component_id}"
                ),
                json=component_payload,
                headers=self._auth_header(),
            )
        )

    def delete_user_storage_component(self, component_id: str) -> None:
        """Delete one validated LDAP user-storage component."""
        safe_component_id = _validate_directory_component_id(component_id)
        self._send_with_reauth(
            lambda: self._client.delete(
                self._absolute_admin_url(
                    f"/admin/realms/{self._realm}/components/{safe_component_id}"
                ),
                headers=self._auth_header(),
            )
        )
