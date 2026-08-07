"""Keycloak Admin REST adapter for secret-free relying-party client lifecycle.

The adapter subclasses the existing product client so it shares the same httpx
connection pool, bearer-token cache, path hardening, and exactly-once HTTP 401
reauthentication boundary. It exposes only the client CRUD needed by durable
relying-party reconciliation.
"""
from __future__ import annotations

from typing import Protocol
from urllib.parse import urlsplit

from .identifiers import InvalidIdentifierError, validate_path_segment
from .product_keycloak_client import ProductHttpAdminApi


class RelyingPartyAdminApi(Protocol):
    """Narrow client-management port consumed by relying-party reconciliation."""

    def list_relying_party_clients(self, client_id: str) -> list[dict]:
        """List Keycloak client candidates for one exact public client ID."""
        ...

    def create_relying_party_client(self, client_payload: dict) -> str | None:
        """Create one Keycloak client and return its generated opaque UUID."""
        ...

    def update_relying_party_client(
        self,
        client_uuid: str,
        client_payload: dict,
    ) -> None:
        """Replace one Keycloak client at its validated opaque UUID."""
        ...

    def delete_relying_party_client(self, client_uuid: str) -> None:
        """Delete one Keycloak client at its validated opaque UUID."""
        ...


class RelyingPartyHttpAdminApi(ProductHttpAdminApi):
    """Product Keycloak client extended with guarded relying-party CRUD."""

    @staticmethod
    def _validate_admin_suffix(path_segments: tuple[str, ...]) -> None:
        """Allow the client collection/resource plus all inherited safe routes."""
        if path_segments == ("clients",):
            return
        if len(path_segments) == 2 and path_segments[0] == "clients":
            validate_path_segment(
                path_segments[1],
                field_name="keycloak_client_uuid",
            )
            return
        ProductHttpAdminApi._validate_admin_suffix(path_segments)

    def _created_client_uuid(self, location: str) -> str:
        """Extract one UUID from an exact absolute Keycloak client Location."""
        parsed = urlsplit(location)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise InvalidIdentifierError(
                "Keycloak client Location must be an absolute HTTP(S) resource URI"
            )
        guarded_path = self._guard_path(parsed.path)
        expected_prefix = f"/admin/realms/{self._realm}/clients/"
        if not guarded_path.startswith(expected_prefix):
            raise InvalidIdentifierError(
                "Keycloak client Location must target the configured realm client resource"
            )
        return validate_path_segment(
            guarded_path[len(expected_prefix) :],
            field_name="keycloak_client_uuid",
        )

    def list_relying_party_clients(self, client_id: str) -> list[dict]:
        """List client candidates using one validated exact client-ID query."""
        safe_client_id = self._safe_segment(client_id, "client_id")
        payload = self._get(
            f"/admin/realms/{self._realm}/clients",
            params={"clientId": safe_client_id, "exact": "true"},
        )
        if not isinstance(payload, list) or any(
            not isinstance(client, dict) for client in payload
        ):
            raise RuntimeError("Keycloak client list response is invalid")
        return [dict(client) for client in payload]

    def create_relying_party_client(self, client_payload: dict) -> str | None:
        """Create one client and parse only a validated Location UUID."""
        client_id = self._safe_segment(
            client_payload.get("clientId"),
            "client_id",
        )
        payload = dict(client_payload)
        payload["clientId"] = client_id
        path = self._guard_path(f"/admin/realms/{self._realm}/clients")
        response = self._send_with_reauth(
            lambda: self._client.post(
                path,
                json=payload,
                headers=self._auth_header(),
            )
        )
        location = response.headers.get("Location")
        if not location:
            return None
        return self._created_client_uuid(location)

    def update_relying_party_client(
        self,
        client_uuid: str,
        client_payload: dict,
    ) -> None:
        """Replace one client while pinning its body ID to the path UUID."""
        safe_uuid = validate_path_segment(
            client_uuid,
            field_name="keycloak_client_uuid",
        )
        payload = dict(client_payload)
        payload["id"] = safe_uuid
        self._put(
            f"/admin/realms/{self._realm}/clients/{safe_uuid}",
            payload,
        )

    def delete_relying_party_client(self, client_uuid: str) -> None:
        """Delete one client after validating its opaque UUID."""
        safe_uuid = validate_path_segment(
            client_uuid,
            field_name="keycloak_client_uuid",
        )
        self._delete(f"/admin/realms/{self._realm}/clients/{safe_uuid}")
