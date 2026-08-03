"""Product-facing extensions for the Keycloak Admin REST API client.

The core merge/SCIM engine depends only on :class:`AdminApi`. Product features
such as self-registration and runtime federation require a wider surface. This
module keeps those concerns modular while preserving the same authenticated
transport, path-safety, and one-shot token refresh behavior.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

import httpx

from .identifiers import InvalidIdentifierError
from .keycloak_client import (
    AdminApi,
    HttpAdminApi,
    _parse_user,
    _to_keycloak_user,
)
from .models import UserAccount


class ProductAdminApi(AdminApi, Protocol):
    """Extended Keycloak contract used by registration and federation modules."""

    def list_users(self, first_result: int, max_results: int) -> list[UserAccount]:
        """Return one page of realm users."""
        ...

    def reset_user_password(self, user_id: str, password_value: str) -> None:
        """Set a non-temporary password credential on a user."""
        ...

    def set_user_required_actions(
        self, user_id: str, action_aliases: list[str]
    ) -> None:
        """Replace the pending required actions on a user."""
        ...

    def list_user_credentials(self, user_id: str) -> list[dict]:
        """List stored credential representations for a user."""
        ...

    def delete_user_credential(self, user_id: str, credential_id: str) -> None:
        """Delete one stored credential from a user."""
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


class ProductHttpAdminApi(HttpAdminApi):
    """Keycloak client with registration, federation, and hardened transport."""

    @staticmethod
    def _guard_path(path: str) -> str:
        """Reject encoded, navigational, malformed, or non-absolute paths."""
        if not path.startswith("/"):
            raise InvalidIdentifierError("request path must be absolute")
        if "%" in path or "\\" in path:
            raise InvalidIdentifierError(
                "request path must not contain encoding or backslashes"
            )
        segments = path.split("/")
        for index, segment in enumerate(segments):
            if segment in {".", ".."}:
                raise InvalidIdentifierError(
                    "request path must not navigate directories"
                )
            if segment == "" and 0 < index < len(segments) - 1:
                raise InvalidIdentifierError(
                    "request path must not contain empty segments"
                )
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in segment):
                raise InvalidIdentifierError(
                    "request path must not contain control characters"
                )
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
            return location.rstrip("/").rsplit("/", 1)[-1]
        found = self.find_user_by_username(user.user_name or "")
        return found.user_id if found else ""

    def list_users(self, first_result: int, max_results: int) -> list[UserAccount]:
        """Return one page of realm users."""
        data = self._get(
            f"/admin/realms/{self._realm}/users",
            params={"first": first_result, "max": max_results},
        )
        return [_parse_user(item) for item in data]

    def reset_user_password(self, user_id: str, password_value: str) -> None:
        """Set one non-temporary password credential."""
        self._put(
            f"/admin/realms/{self._realm}/users/{user_id}/reset-password",
            {"type": "password", "value": password_value, "temporary": False},
        )

    def set_user_required_actions(
        self, user_id: str, action_aliases: list[str]
    ) -> None:
        """Replace one user's pending required actions."""
        self._put(
            f"/admin/realms/{self._realm}/users/{user_id}",
            {"requiredActions": list(action_aliases)},
        )

    def list_user_credentials(self, user_id: str) -> list[dict]:
        """Return stored credential representations for one user."""
        data = self._get(
            f"/admin/realms/{self._realm}/users/{user_id}/credentials"
        )
        return [item for item in data if isinstance(item, dict)]

    def delete_user_credential(self, user_id: str, credential_id: str) -> None:
        """Delete one stored credential from one user."""
        self._delete(
            f"/admin/realms/{self._realm}/users/{user_id}/credentials/{credential_id}"
        )

    def delete_user(self, user_id: str) -> None:
        """Delete one user during failed registration rollback."""
        self._delete(f"/admin/realms/{self._realm}/users/{user_id}")

    def get_identity_provider(self, provider_alias: str) -> dict | None:
        """Return an identity provider or ``None`` for a Keycloak 404."""
        try:
            data = self._get(
                f"/admin/realms/{self._realm}/identity-provider/instances/"
                f"{provider_alias}"
            )
        except httpx.HTTPStatusError as error:
            if error.response.status_code == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    def create_identity_provider(self, provider_payload: dict) -> None:
        """Create one Keycloak identity-provider instance."""
        self._post(
            f"/admin/realms/{self._realm}/identity-provider/instances",
            provider_payload,
        )

    def update_identity_provider(
        self, provider_alias: str, provider_payload: dict
    ) -> None:
        """Replace one Keycloak identity-provider instance."""
        self._put(
            f"/admin/realms/{self._realm}/identity-provider/instances/"
            f"{provider_alias}",
            provider_payload,
        )

    def delete_identity_provider(self, provider_alias: str) -> None:
        """Delete one Keycloak identity-provider instance."""
        self._delete(
            f"/admin/realms/{self._realm}/identity-provider/instances/"
            f"{provider_alias}"
        )
