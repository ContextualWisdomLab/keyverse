"""Minimal SCIM 2.0 (RFC 7644) inbound provisioning server shim.

Keycloak's native SCIM support is experimental and the only mature plugin
(scim-for-keycloak) is commercial, so this repo ships a small, permissive,
Apache-2.0 SCIM v2 *server* that upstream HR/IGA systems POST to. It translates
SCIM ``User`` resource operations into Keycloak Admin REST API calls
(create/replace/deactivate), provisioning users into the realm.

Supported: ServiceProviderConfig, Users create/get/replace/patch(active)/delete
and a ``userName eq`` filter search. Groups are intentionally out of scope for
this shim (managed in Keycloak directly / via the merge service).

References: RFC 7644 (SCIM Protocol), RFC 7643 (SCIM Core Schema).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from .keycloak_client import AdminApi
from .models import UserAccount

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_SPC_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_CONTENT_TYPE = "application/scim+json"

scim_router = APIRouter(prefix="/scim/v2", tags=["scim"])


def get_provisioner(request: Request) -> AdminApi:
    """Return the Keycloak provisioner wired into app state."""
    api = getattr(request.app.state, "keycloak_api", None)
    if api is None:  # pragma: no cover - only when misconfigured / test wiring
        raise HTTPException(status_code=503, detail="keycloak provisioner not wired")
    return api


def _scim_error(status: int, detail: str) -> HTTPException:
    """Build a SCIM-shaped HTTP error."""
    return HTTPException(
        status_code=status,
        detail={"schemas": [SCIM_ERROR_SCHEMA], "detail": detail, "status": str(status)},
    )


def _primary_email(resource: dict[str, Any]) -> str | None:
    """Return the primary SCIM email, falling back to the first email."""
    emails = resource.get("emails") or []
    if not emails:
        return None
    for entry in emails:
        if entry.get("primary"):
            return entry.get("value")
    return emails[0].get("value")


def _to_user_account(resource: dict[str, Any], user_id: str = "") -> UserAccount:
    """Translate a SCIM User resource into the domain user model."""
    name = resource.get("name") or {}
    return UserAccount(
        user_id=user_id,
        user_name=resource.get("userName"),
        email=_primary_email(resource),
        # SCIM has no per-email verification bit here; provisioned mail from an
        # authoritative HR/IGA source is treated as verified.
        is_email_verified=True,
        state="active" if resource.get("active", True) else "disabled",
        first_name=name.get("givenName"),
        last_name=name.get("familyName"),
        external_id=resource.get("externalId"),
    )


def _to_scim_resource(user: UserAccount) -> dict[str, Any]:
    """Translate a domain user into a SCIM User resource."""
    resource: dict[str, Any] = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.user_id,
        "userName": user.user_name,
        "active": user.state in {"active", "enabled"},
        "name": {"givenName": user.first_name, "familyName": user.last_name},
        "meta": {"resourceType": "User", "location": f"/scim/v2/Users/{user.user_id}"},
    }
    if user.external_id:
        resource["externalId"] = user.external_id
    if user.email:
        resource["emails"] = [{"value": user.email, "primary": True}]
    return resource


def _scim_response(body: dict[str, Any], status_code: int = 200) -> Response:
    """Serialize a SCIM JSON response with the SCIM media type."""
    import json

    return Response(
        content=json.dumps(body),
        status_code=status_code,
        media_type=SCIM_CONTENT_TYPE,
    )


@scim_router.get("/ServiceProviderConfig")
def service_provider_config() -> Response:
    """Return the service capabilities advertised to SCIM clients."""
    return _scim_response(
        {
            "schemas": [SCIM_SPC_SCHEMA],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication via OAuth2 bearer token at the WAF edge.",
                }
            ],
        }
    )


@scim_router.post("/Users")
def create_user(
    resource: dict[str, Any], provisioner: AdminApi = Depends(get_provisioner)
) -> Response:
    """Provision a Keycloak user from a SCIM create request."""
    username = resource.get("userName")
    if not username:
        raise _scim_error(400, "userName is required")
    if provisioner.find_user_by_username(username) is not None:
        raise _scim_error(409, f"user '{username}' already exists")
    account = _to_user_account(resource)
    user_id = provisioner.create_user(account)
    created = provisioner.get_user(user_id)
    return _scim_response(_to_scim_resource(created), status_code=201)


@scim_router.get("/Users/{user_id}")
def get_user(
    user_id: str, provisioner: AdminApi = Depends(get_provisioner)
) -> Response:
    """Return one provisioned user as a SCIM resource."""
    try:
        user = provisioner.get_user(user_id)
    except KeyError as exc:
        raise _scim_error(404, f"user '{user_id}' not found") from exc
    return _scim_response(_to_scim_resource(user))


@scim_router.get("/Users")
def search_users(
    request: Request, provisioner: AdminApi = Depends(get_provisioner)
) -> Response:
    """Search users with the supported ``userName eq`` SCIM filter."""
    scim_filter = request.query_params.get("filter")
    results: list[UserAccount] = []
    if scim_filter:
        # Minimal filter support: userName eq "value".
        parts = scim_filter.split(" ", 2)
        if len(parts) == 3 and parts[0] == "userName" and parts[1].lower() == "eq":
            username = parts[2].strip().strip('"')
            found = provisioner.find_user_by_username(username)
            if found is not None:
                results = [found]
        else:
            raise _scim_error(400, "only 'userName eq' filter is supported")
    return _scim_response(
        {
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": len(results),
            "startIndex": 1,
            "itemsPerPage": len(results),
            "Resources": [_to_scim_resource(u) for u in results],
        }
    )


@scim_router.put("/Users/{user_id}")
def replace_user(
    user_id: str,
    resource: dict[str, Any],
    provisioner: AdminApi = Depends(get_provisioner),
) -> Response:
    """Replace a provisioned user from a SCIM PUT request."""
    try:
        provisioner.get_user(user_id)
    except KeyError as exc:
        raise _scim_error(404, f"user '{user_id}' not found") from exc
    account = _to_user_account(resource, user_id=user_id)
    provisioner.replace_user(user_id, account)
    return _scim_response(_to_scim_resource(provisioner.get_user(user_id)))


@scim_router.patch("/Users/{user_id}")
def patch_user(
    user_id: str,
    body: dict[str, Any],
    provisioner: AdminApi = Depends(get_provisioner),
) -> Response:
    """Apply the supported SCIM PATCH operations to one user."""
    try:
        provisioner.get_user(user_id)
    except KeyError as exc:
        raise _scim_error(404, f"user '{user_id}' not found") from exc
    # Minimal PATCH: support toggling 'active' (the common deprovision path).
    for operation in body.get("Operations", []):
        if operation.get("op", "").lower() not in {"replace", "add"}:
            continue
        if operation.get("path") == "active" or "active" in (
            operation.get("value") or {}
        ):
            value = operation.get("value")
            active = value.get("active") if isinstance(value, dict) else value
            if active in (False, "false", "False"):
                provisioner.deactivate_user(user_id)
    return _scim_response(_to_scim_resource(provisioner.get_user(user_id)))


@scim_router.delete("/Users/{user_id}", status_code=204)
def delete_user(
    user_id: str, provisioner: AdminApi = Depends(get_provisioner)
) -> Response:
    """Soft-delete a user by disabling the Keycloak account."""
    try:
        provisioner.get_user(user_id)
    except KeyError as exc:
        raise _scim_error(404, f"user '{user_id}' not found") from exc
    # Soft-delete: SCIM DELETE deprovisions by disabling the Keycloak user.
    provisioner.deactivate_user(user_id)
    return Response(status_code=204)
