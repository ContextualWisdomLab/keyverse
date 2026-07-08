"""Keycloak Admin REST API client.

The unification service talks to Keycloak only through the :class:`AdminApi`
Protocol, so the merge engine is fully testable against an in-memory fake (see
``tests/mock_keycloak.py``). The HTTP implementation maps each method to a
documented Keycloak Admin REST API endpoint.

Endpoint references (Keycloak Admin REST API, realm ``{realm}``):
  GET    /admin/realms/{realm}/users/{id}                         get user
  GET    /admin/realms/{realm}/users?email={e}&exact=true         search by email
  GET    /admin/realms/{realm}/users/{id}/federated-identity      list linked IdPs
  POST   /admin/realms/{realm}/users/{id}/federated-identity/{a}  add IdP link
  DELETE /admin/realms/{realm}/users/{id}/federated-identity/{a}  remove IdP link
  GET    /admin/realms/{realm}/users/{id}/role-mappings          all role mappings
  POST   /admin/realms/{realm}/users/{id}/role-mappings/realm     add realm roles
  DELETE /admin/realms/{realm}/users/{id}/role-mappings/realm     remove realm roles
  POST   /admin/realms/{realm}/users/{id}/role-mappings/clients/{cid}  add client roles
  DELETE /admin/realms/{realm}/users/{id}/role-mappings/clients/{cid}  remove client roles
  GET    /admin/realms/{realm}/users/{id}/groups                 list group memberships
  PUT    /admin/realms/{realm}/users/{id}/groups/{gid}           join group
  DELETE /admin/realms/{realm}/users/{id}/groups/{gid}           leave group
  PUT    /admin/realms/{realm}/users/{id}                        update user (disable/attrs)

Access token is obtained from the realm token endpoint using a confidential
service-account client (client_credentials); its client id + secret come from
the KV config store, never from process environment.
"""
from __future__ import annotations

from typing import Protocol

from .models import FederatedIdentity, GroupMembership, RoleMapping, UserAccount


class AdminApi(Protocol):
    """Minimal Keycloak Admin REST API surface the merge engine needs."""

    def get_user(self, user_id: str) -> UserAccount: ...

    def find_users_by_email(self, email: str) -> list[UserAccount]: ...

    def find_user_by_username(self, username: str) -> UserAccount | None: ...

    def create_user(self, user: UserAccount) -> str: ...

    def replace_user(self, user_id: str, user: UserAccount) -> None: ...

    def list_federated_identities(self, user_id: str) -> list[FederatedIdentity]: ...

    def add_federated_identity(
        self, user_id: str, identity: FederatedIdentity
    ) -> None: ...

    def remove_federated_identity(
        self, user_id: str, identity_provider: str
    ) -> None: ...

    def list_role_mappings(self, user_id: str) -> list[RoleMapping]: ...

    def add_role_mapping(self, user_id: str, role: RoleMapping) -> None: ...

    def remove_role_mapping(self, user_id: str, role: RoleMapping) -> None: ...

    def list_group_memberships(self, user_id: str) -> list[GroupMembership]: ...

    def add_group_membership(self, user_id: str, group: GroupMembership) -> None: ...

    def remove_group_membership(self, user_id: str, group: GroupMembership) -> None: ...

    def deactivate_user(self, user_id: str) -> None: ...

    def set_user_attribute(self, user_id: str, key: str, value: str) -> None: ...


class HttpAdminApi:
    """httpx-backed :class:`AdminApi` for a live Keycloak instance.

    Authenticates with the realm token endpoint via a confidential
    service-account client (``client_credentials`` grant). The client must hold
    the ``realm-management`` roles ``view-users`` and ``manage-users``.
    """

    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        token_realm: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        import httpx  # local import keeps httpx optional for pure unit tests

        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        # The service-account client usually lives in the same realm it manages,
        # but a dedicated admin realm can be named explicitly.
        self._token_realm = token_realm or realm
        self._client = httpx.Client(
            base_url=server_url.rstrip("/"),
            timeout=timeout_seconds,
            headers={"Content-Type": "application/json"},
        )
        self._token: str | None = None

    # -- auth --------------------------------------------------------------
    def _authenticate(self) -> str:
        response = self._client.post(
            f"/realms/{self._token_realm}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]
        return self._token

    def _auth_header(self) -> dict[str, str]:
        token = self._token or self._authenticate()
        return {"Authorization": f"Bearer {token}"}

    # -- reads -------------------------------------------------------------
    def get_user(self, user_id: str) -> UserAccount:
        data = self._get(f"/admin/realms/{self._realm}/users/{user_id}")
        return _parse_user(data)

    def find_users_by_email(self, email: str) -> list[UserAccount]:
        data = self._get(
            f"/admin/realms/{self._realm}/users",
            params={"email": email, "exact": "true"},
        )
        return [_parse_user(item) for item in data]

    def find_user_by_username(self, username: str) -> UserAccount | None:
        data = self._get(
            f"/admin/realms/{self._realm}/users",
            params={"username": username, "exact": "true"},
        )
        for item in data:
            if (item.get("username") or "").lower() == username.lower():
                return _parse_user(item)
        return None

    def create_user(self, user: UserAccount) -> str:
        # Keycloak returns 201 with a Location header ending in the new user id.
        response = self._client.post(
            f"/admin/realms/{self._realm}/users",
            json=_to_keycloak_user(user),
            headers=self._auth_header(),
        )
        response.raise_for_status()
        location = response.headers.get("Location", "")
        if location:
            return location.rstrip("/").rsplit("/", 1)[-1]
        found = self.find_user_by_username(user.user_name or "")
        return found.user_id if found else ""

    def replace_user(self, user_id: str, user: UserAccount) -> None:
        self._put(
            f"/admin/realms/{self._realm}/users/{user_id}", _to_keycloak_user(user)
        )

    def list_federated_identities(self, user_id: str) -> list[FederatedIdentity]:
        data = self._get(
            f"/admin/realms/{self._realm}/users/{user_id}/federated-identity"
        )
        return [
            FederatedIdentity(
                identity_provider=item["identityProvider"],
                external_user_id=item["userId"],
                external_user_name=item.get("userName"),
            )
            for item in data
        ]

    def list_role_mappings(self, user_id: str) -> list[RoleMapping]:
        data = self._get(
            f"/admin/realms/{self._realm}/users/{user_id}/role-mappings"
        )
        mappings: list[RoleMapping] = []
        for role in data.get("realmMappings", []):
            mappings.append(
                RoleMapping(role_id=role["id"], role_name=role["name"], client_id=None)
            )
        for client_id, container in (data.get("clientMappings") or {}).items():
            container_id = container.get("id", client_id)
            for role in container.get("mappings", []):
                mappings.append(
                    RoleMapping(
                        role_id=role["id"],
                        role_name=role["name"],
                        client_id=container_id,
                    )
                )
        return mappings

    def list_group_memberships(self, user_id: str) -> list[GroupMembership]:
        data = self._get(
            f"/admin/realms/{self._realm}/users/{user_id}/groups"
        )
        return [
            GroupMembership(
                group_id=item["id"],
                group_path=item.get("path", item["id"]),
                group_name=item.get("name"),
            )
            for item in data
        ]

    # -- writes ------------------------------------------------------------
    def add_federated_identity(self, user_id: str, identity: FederatedIdentity) -> None:
        self._post(
            f"/admin/realms/{self._realm}/users/{user_id}/federated-identity/"
            f"{identity.identity_provider}",
            {
                "identityProvider": identity.identity_provider,
                "userId": identity.external_user_id,
                "userName": identity.external_user_name or identity.external_user_id,
            },
        )

    def remove_federated_identity(self, user_id: str, identity_provider: str) -> None:
        self._delete(
            f"/admin/realms/{self._realm}/users/{user_id}/federated-identity/"
            f"{identity_provider}"
        )

    def add_role_mapping(self, user_id: str, role: RoleMapping) -> None:
        payload = [{"id": role.role_id, "name": role.role_name}]
        if role.client_id is None:
            self._post(
                f"/admin/realms/{self._realm}/users/{user_id}/role-mappings/realm",
                payload,
            )
        else:
            self._post(
                f"/admin/realms/{self._realm}/users/{user_id}/role-mappings/"
                f"clients/{role.client_id}",
                payload,
            )

    def remove_role_mapping(self, user_id: str, role: RoleMapping) -> None:
        payload = [{"id": role.role_id, "name": role.role_name}]
        if role.client_id is None:
            self._delete(
                f"/admin/realms/{self._realm}/users/{user_id}/role-mappings/realm",
                body=payload,
            )
        else:
            self._delete(
                f"/admin/realms/{self._realm}/users/{user_id}/role-mappings/"
                f"clients/{role.client_id}",
                body=payload,
            )

    def add_group_membership(self, user_id: str, group: GroupMembership) -> None:
        self._put(
            f"/admin/realms/{self._realm}/users/{user_id}/groups/{group.group_id}", {}
        )

    def remove_group_membership(self, user_id: str, group: GroupMembership) -> None:
        self._delete(
            f"/admin/realms/{self._realm}/users/{user_id}/groups/{group.group_id}"
        )

    def deactivate_user(self, user_id: str) -> None:
        # Disable the user so it can never authenticate again (soft tombstone).
        self._put(
            f"/admin/realms/{self._realm}/users/{user_id}", {"enabled": False}
        )

    def set_user_attribute(self, user_id: str, key: str, value: str) -> None:
        current = self._get(f"/admin/realms/{self._realm}/users/{user_id}")
        attributes = dict(current.get("attributes") or {})
        attributes[key] = [value]
        self._put(
            f"/admin/realms/{self._realm}/users/{user_id}", {"attributes": attributes}
        )

    # -- transport ---------------------------------------------------------
    def _get(self, path: str, params: dict | None = None) -> dict | list:
        response = self._client.get(path, params=params, headers=self._auth_header())
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body) -> dict:
        response = self._client.post(path, json=body, headers=self._auth_header())
        response.raise_for_status()
        return response.json() if response.content else {}

    def _put(self, path: str, body: dict) -> None:
        response = self._client.put(path, json=body, headers=self._auth_header())
        response.raise_for_status()

    def _delete(self, path: str, body=None) -> None:
        request = self._client.build_request(
            "DELETE", path, json=body, headers=self._auth_header()
        )
        response = self._client.send(request)
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()


def _parse_user(data: dict) -> UserAccount:
    enabled = bool(data.get("enabled", True))
    attributes = data.get("attributes") or {}
    external = attributes.get("scim_external_id")
    return UserAccount(
        user_id=data["id"],
        user_name=data.get("username"),
        email=data.get("email"),
        is_email_verified=bool(data.get("emailVerified", False)),
        state="active" if enabled else "disabled",
        first_name=data.get("firstName"),
        last_name=data.get("lastName"),
        external_id=external[0] if isinstance(external, list) and external else None,
    )


def _to_keycloak_user(user: UserAccount) -> dict:
    payload: dict = {
        "username": user.user_name,
        "email": user.email,
        "emailVerified": user.is_email_verified,
        "enabled": user.state in {"active", "enabled"},
    }
    if user.first_name is not None:
        payload["firstName"] = user.first_name
    if user.last_name is not None:
        payload["lastName"] = user.last_name
    if user.external_id is not None:
        payload["attributes"] = {"scim_external_id": [user.external_id]}
    return payload
