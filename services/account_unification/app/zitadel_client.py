"""ZITADEL Management API client.

The unification service talks to ZITADEL only through the :class:`ManagementApi`
Protocol, so the merge engine is fully testable against an in-memory fake (see
``tests/mock_zitadel.py``). The HTTP implementation maps each method to a
documented ZITADEL Management API endpoint.

Endpoint references (ZITADEL v4 Management API):
  GET  /management/v1/users/{id}                       get user
  POST /management/v1/users/_search                    search users (by email)
  POST /management/v1/users/{id}/idps/_search          list idp links
  POST /management/v1/users/{id}/idps                  add idp link
  DELETE /management/v1/users/{id}/idps/{idpId}/{extId} remove idp link
  POST /management/v1/users/{id}/grants/_search        list user grants
  POST /management/v1/users/{id}/grants                add user grant
  DELETE /management/v1/users/{id}/grants/{grantId}    remove user grant
  POST /management/v1/users/{id}/memberships/_search   list memberships
  POST /management/v1/users/{id}/_deactivate           tombstone (deactivate)
  POST /management/v1/users/{id}/metadata/{key}        set metadata
"""
from __future__ import annotations

from typing import Protocol

from .models import IdentityLink, Membership, UserAccount, UserGrant


class ManagementApi(Protocol):
    """Minimal ZITADEL Management API surface the merge engine needs."""

    def get_user(self, user_id: str) -> UserAccount: ...

    def find_users_by_email(self, email: str) -> list[UserAccount]: ...

    def list_idp_links(self, user_id: str) -> list[IdentityLink]: ...

    def add_idp_link(self, user_id: str, link: IdentityLink) -> None: ...

    def remove_idp_link(
        self, user_id: str, idp_id: str, external_user_id: str
    ) -> None: ...

    def list_user_grants(self, user_id: str) -> list[UserGrant]: ...

    def add_user_grant(
        self, user_id: str, project_id: str, role_keys: list[str]
    ) -> str: ...

    def remove_user_grant(self, user_id: str, grant_id: str) -> None: ...

    def list_memberships(self, user_id: str) -> list[Membership]: ...

    def add_membership(self, user_id: str, membership: Membership) -> None: ...

    def remove_membership(self, user_id: str, membership: Membership) -> None: ...

    def deactivate_user(self, user_id: str) -> None: ...

    def set_user_metadata(self, user_id: str, key: str, value: str) -> None: ...


class HttpManagementApi:
    """httpx-backed :class:`ManagementApi` for a live ZITADEL instance."""

    def __init__(
        self,
        api_base: str,
        mgmt_token: str,
        org_id: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        import httpx  # local import keeps httpx optional for pure unit tests

        self._org_id = org_id
        self._client = httpx.Client(
            base_url=api_base.rstrip("/"),
            timeout=timeout_seconds,
            headers={
                "Authorization": f"Bearer {mgmt_token}",
                "x-zitadel-orgid": org_id,
                "Content-Type": "application/json",
            },
        )

    # -- reads -------------------------------------------------------------
    def get_user(self, user_id: str) -> UserAccount:
        data = self._get(f"/management/v1/users/{user_id}")["user"]
        return _parse_user(data)

    def find_users_by_email(self, email: str) -> list[UserAccount]:
        body = {
            "queries": [
                {"emailQuery": {"emailAddress": email, "method": "TEXT_QUERY_METHOD_EQUALS"}}
            ]
        }
        data = self._post("/management/v1/users/_search", body)
        return [_parse_user(item) for item in data.get("result", [])]

    def list_idp_links(self, user_id: str) -> list[IdentityLink]:
        data = self._post(f"/management/v1/users/{user_id}/idps/_search", {})
        return [
            IdentityLink(
                idp_id=item["idpId"],
                idp_name=item.get("idpName"),
                external_user_id=item["providedUserId"],
                external_user_name=item.get("providedUserName"),
            )
            for item in data.get("result", [])
        ]

    def list_user_grants(self, user_id: str) -> list[UserGrant]:
        body = {"queries": [{"userIdQuery": {"userId": user_id}}]}
        data = self._post(f"/management/v1/users/{user_id}/grants/_search", body)
        return [
            UserGrant(
                grant_id=item["id"],
                project_id=item["projectId"],
                project_grant_id=item.get("projectGrantId"),
                role_keys=item.get("roleKeys", []),
            )
            for item in data.get("result", [])
        ]

    def list_memberships(self, user_id: str) -> list[Membership]:
        data = self._post(f"/management/v1/users/{user_id}/memberships/_search", {})
        result: list[Membership] = []
        for item in data.get("result", []):
            result.append(
                Membership(
                    membership_type=_membership_type(item),
                    aggregate_id=_membership_aggregate(item),
                    roles=item.get("roles", []),
                )
            )
        return result

    # -- writes ------------------------------------------------------------
    def add_idp_link(self, user_id: str, link: IdentityLink) -> None:
        self._post(
            f"/management/v1/users/{user_id}/idps",
            {
                "idpId": link.idp_id,
                "userId": link.external_user_id,
                "userName": link.external_user_name or link.external_user_id,
            },
        )

    def remove_idp_link(self, user_id: str, idp_id: str, external_user_id: str) -> None:
        self._delete(f"/management/v1/users/{user_id}/idps/{idp_id}/{external_user_id}")

    def add_user_grant(self, user_id: str, project_id: str, role_keys: list[str]) -> str:
        data = self._post(
            f"/management/v1/users/{user_id}/grants",
            {"projectId": project_id, "roleKeys": role_keys},
        )
        return data.get("grantId", "")

    def remove_user_grant(self, user_id: str, grant_id: str) -> None:
        self._delete(f"/management/v1/users/{user_id}/grants/{grant_id}")

    def add_membership(self, user_id: str, membership: Membership) -> None:
        self._post(
            f"/management/v1/users/{user_id}/memberships",
            {
                "type": membership.membership_type,
                "aggregateId": membership.aggregate_id,
                "roles": membership.roles,
            },
        )

    def remove_membership(self, user_id: str, membership: Membership) -> None:
        self._delete(
            f"/management/v1/users/{user_id}/memberships/"
            f"{membership.membership_type}/{membership.aggregate_id}"
        )

    def deactivate_user(self, user_id: str) -> None:
        self._post(f"/management/v1/users/{user_id}/_deactivate", {})

    def set_user_metadata(self, user_id: str, key: str, value: str) -> None:
        import base64

        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        self._post(
            f"/management/v1/users/{user_id}/metadata/{key}", {"value": encoded}
        )

    # -- transport ---------------------------------------------------------
    def _get(self, path: str) -> dict:
        response = self._client.get(path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict) -> dict:
        response = self._client.post(path, json=body)
        response.raise_for_status()
        return response.json() if response.content else {}

    def _delete(self, path: str) -> None:
        response = self._client.delete(path)
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()


def _parse_user(data: dict) -> UserAccount:
    human = data.get("human", {})
    email = human.get("email", {})
    return UserAccount(
        user_id=data["id"],
        user_name=data.get("userName"),
        email=email.get("email"),
        is_email_verified=bool(email.get("isEmailVerified", False)),
        state=data.get("state", "USER_STATE_ACTIVE"),
    )


def _membership_type(item: dict) -> str:
    if "orgId" in item:
        return "org"
    if "projectGrantId" in item:
        return "project_grant"
    if "projectId" in item:
        return "project"
    return "instance"


def _membership_aggregate(item: dict) -> str:
    return (
        item.get("orgId")
        or item.get("projectGrantId")
        or item.get("projectId")
        or item.get("iam", "instance")
    )
