"""Durable authorization grants, SSO combinations, and PDP HTTP surface.

Grants persist in the KV/DB store under descriptive two-word namespaces. The
decision endpoints evaluate inheritance locally and never contact Orgmetra or
Keycloak. Every decision reminds the caller that the relying party remains the
PEP (ADR-0008).
"""
from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, ValidationError

from .auth import operator_auth_dependency
from .errors import AuthorizationPolicyError
from .kv_store import KvStore
from .org_authorization import (
    AuthorizationDecision,
    AuthorizationGrant,
    AssignmentSnapshot,
    SsoCombinationDecision,
    SsoCombinationScope,
    decide_menu,
    decide_software_unit,
    decide_sso_combination,
    validate_combination,
    validate_grant,
    validate_slug,
    validate_snapshot,
)
from .path_security import admin_path_security_dependency

SOFTWARE_UNIT_GRANT_NAMESPACE = "authorization_software_unit_grants"
MENU_GRANT_NAMESPACE = "authorization_menu_grants"
SSO_COMBINATION_NAMESPACE = "authorization_sso_combination_scopes"

authorization_router = APIRouter(
    prefix="/authorization",
    tags=["authorization"],
    dependencies=[operator_auth_dependency, admin_path_security_dependency],
)


class SoftwareUnitDecisionRequest(BaseModel):
    """Ask whether one subject may use one software unit."""

    model_config = ConfigDict(extra="forbid")

    snapshot: AssignmentSnapshot
    software_unit_id: str


class MenuDecisionRequest(BaseModel):
    """Ask whether one subject may use one software menu path."""

    model_config = ConfigDict(extra="forbid")

    snapshot: AssignmentSnapshot
    software_unit_id: str
    menu_path: str


class SsoCombinationDecisionRequest(BaseModel):
    """Ask whether one Keyverse session may cover a named RP combination."""

    model_config = ConfigDict(extra="forbid")

    snapshot: AssignmentSnapshot
    combination_name: str


class AuthorizationPlaneService:
    """Persist closed grants and evaluate issuer-side authorization decisions."""

    def __init__(self, store: KvStore) -> None:
        """Create one service around the configured KV/DB backend."""
        self._store = store
        self._state_lock = threading.RLock()

    def put_software_unit_grant(self, grant_key: str, grant: AuthorizationGrant) -> AuthorizationGrant:
        """Validate and store one software-unit grant."""
        return self._put_grant(
            grant_key,
            grant,
            expected_scope="software_unit",
            namespace=SOFTWARE_UNIT_GRANT_NAMESPACE,
        )

    def put_menu_grant(self, grant_key: str, grant: AuthorizationGrant) -> AuthorizationGrant:
        """Validate and store one menu grant."""
        return self._put_grant(
            grant_key,
            grant,
            expected_scope="menu",
            namespace=MENU_GRANT_NAMESPACE,
        )

    def get_software_unit_grant(self, grant_key: str) -> AuthorizationGrant:
        """Return one stored software-unit grant."""
        return self._get_grant(SOFTWARE_UNIT_GRANT_NAMESPACE, grant_key)

    def get_menu_grant(self, grant_key: str) -> AuthorizationGrant:
        """Return one stored menu grant."""
        return self._get_grant(MENU_GRANT_NAMESPACE, grant_key)

    def list_software_unit_grants(self) -> list[AuthorizationGrant]:
        """Return every stored software-unit grant."""
        return self._list_grants(SOFTWARE_UNIT_GRANT_NAMESPACE)

    def list_menu_grants(self) -> list[AuthorizationGrant]:
        """Return every stored menu grant."""
        return self._list_grants(MENU_GRANT_NAMESPACE)

    def delete_software_unit_grant(self, grant_key: str) -> None:
        """Remove one software-unit grant."""
        self._delete_grant(SOFTWARE_UNIT_GRANT_NAMESPACE, grant_key)

    def delete_menu_grant(self, grant_key: str) -> None:
        """Remove one menu grant."""
        self._delete_grant(MENU_GRANT_NAMESPACE, grant_key)

    def put_combination(
        self, combination_name: str, combination: SsoCombinationScope
    ) -> SsoCombinationScope:
        """Validate and store one SSO combination scope."""
        validate_slug(combination_name, field_name="combination_name")
        if combination.combination_name != combination_name:
            raise AuthorizationPolicyError(
                "path combination_name and body combination_name must match"
            )
        validated = validate_combination(combination)
        with self._state_lock:
            self._store.put(
                SSO_COMBINATION_NAMESPACE,
                self._scoped_key(
                    validated.tenant_deployment_id,
                    combination_name,
                ),
                validated.model_dump_json(),
            )
        return validated

    def get_combination(
        self,
        combination_name: str,
        *,
        tenant_deployment_id: str | None = None,
    ) -> SsoCombinationScope:
        """Return one stored SSO combination."""
        validate_slug(combination_name, field_name="combination_name")
        if tenant_deployment_id is not None:
            validate_slug(
                tenant_deployment_id,
                field_name="tenant_deployment_id",
            )
        combinations = [
            combination
            for combination in self.list_combinations()
            if combination.combination_name == combination_name
            and (
                tenant_deployment_id is None
                or combination.tenant_deployment_id == tenant_deployment_id
            )
        ]
        if not combinations:
            raise AuthorizationPolicyError(
                "sso combination is not registered",
                status_code=404,
            )
        if len(combinations) > 1:
            raise AuthorizationPolicyError(
                "tenant_deployment_id is required for an ambiguous sso combination",
                status_code=409,
            )
        return combinations[0]

    def list_combinations(self) -> list[SsoCombinationScope]:
        """Return every stored SSO combination."""
        with self._state_lock:
            raw_values = list(self._store.get_all(SSO_COMBINATION_NAMESPACE).values())
        combinations = [self._parse_combination(raw_value) for raw_value in raw_values]
        return sorted(combinations, key=lambda item: item.combination_name)

    def delete_combination(
        self,
        combination_name: str,
        *,
        tenant_deployment_id: str | None = None,
    ) -> None:
        """Remove one SSO combination."""
        validate_slug(combination_name, field_name="combination_name")
        if tenant_deployment_id is not None:
            validate_slug(
                tenant_deployment_id,
                field_name="tenant_deployment_id",
            )
        with self._state_lock:
            matches = []
            for entry_key, raw_value in self._store.get_all(
                SSO_COMBINATION_NAMESPACE
            ).items():
                combination = self._parse_combination(raw_value)
                if (
                    combination.combination_name == combination_name
                    and (
                        tenant_deployment_id is None
                        or combination.tenant_deployment_id == tenant_deployment_id
                    )
                ):
                    matches.append((entry_key, combination))
            if not matches:
                raise AuthorizationPolicyError(
                    "sso combination is not registered",
                    status_code=404,
                )
            if len(matches) > 1:
                raise AuthorizationPolicyError(
                    "tenant_deployment_id is required for an ambiguous sso combination",
                    status_code=409,
                )
            self._store.delete(SSO_COMBINATION_NAMESPACE, matches[0][0])

    def decide_software_unit(
        self, request: SoftwareUnitDecisionRequest
    ) -> AuthorizationDecision:
        """Evaluate software-unit access from stored grants and a snapshot."""
        snapshot = validate_snapshot(request.snapshot)
        return decide_software_unit(
            self.list_software_unit_grants(),
            snapshot,
            request.software_unit_id,
        )

    def decide_menu(self, request: MenuDecisionRequest) -> AuthorizationDecision:
        """Evaluate menu access from stored software-unit and menu grants."""
        snapshot = validate_snapshot(request.snapshot)
        return decide_menu(
            self.list_software_unit_grants() + self.list_menu_grants(),
            snapshot,
            request.software_unit_id,
            request.menu_path,
        )

    def decide_combination(
        self, request: SsoCombinationDecisionRequest
    ) -> SsoCombinationDecision:
        """Evaluate whether every member of a stored combination is allowed."""
        snapshot = validate_snapshot(request.snapshot)
        combination = self.get_combination(
            request.combination_name,
            tenant_deployment_id=snapshot.tenant_deployment_id,
        )
        return decide_sso_combination(
            self.list_software_unit_grants(),
            snapshot,
            combination,
        )

    def _put_grant(
        self,
        grant_key: str,
        grant: AuthorizationGrant,
        *,
        expected_scope: str,
        namespace: str,
    ) -> AuthorizationGrant:
        """Validate uniqueness and persist one grant."""
        validate_slug(grant_key, field_name="grant_key")
        if grant.grant_key != grant_key:
            raise AuthorizationPolicyError("path grant_key and body grant_key must match")
        if grant.grant_scope_code != expected_scope:
            raise AuthorizationPolicyError(
                f"this collection accepts only {expected_scope} grants"
            )
        validated = validate_grant(grant)
        identity = (
            validated.tenant_deployment_id,
            validated.grant_scope_code,
            validated.org_path,
            validated.software_unit_id,
            validated.menu_path or "",
        )
        with self._state_lock:
            for existing in self._list_grants(namespace):
                existing_identity = (
                    existing.tenant_deployment_id,
                    existing.grant_scope_code,
                    existing.org_path,
                    existing.software_unit_id,
                    existing.menu_path or "",
                )
                if existing.grant_key != grant_key and existing_identity == identity:
                    raise AuthorizationPolicyError(
                        "an equivalent authorization grant already exists",
                        status_code=409,
                    )
            self._store.put(
                namespace,
                self._scoped_key(validated.tenant_deployment_id, grant_key),
                validated.model_dump_json(),
            )
        return validated

    def _get_grant(self, namespace: str, grant_key: str) -> AuthorizationGrant:
        """Return one stored grant or raise a 404 policy error."""
        validate_slug(grant_key, field_name="grant_key")
        grants = [grant for grant in self._list_grants(namespace) if grant.grant_key == grant_key]
        if not grants:
            raise AuthorizationPolicyError(
                "authorization grant is not registered",
                status_code=404,
            )
        if len(grants) > 1:
            raise AuthorizationPolicyError(
                "tenant_deployment_id is required for an ambiguous authorization grant",
                status_code=409,
            )
        return grants[0]

    def _list_grants(self, namespace: str) -> list[AuthorizationGrant]:
        """Return every grant in one namespace, fail-closed on corrupt rows."""
        with self._state_lock:
            raw_values = list(self._store.get_all(namespace).values())
        grants = [self._parse_grant(raw_value) for raw_value in raw_values]
        return sorted(grants, key=lambda item: item.grant_key)

    def _delete_grant(self, namespace: str, grant_key: str) -> None:
        """Delete one grant after proving it exists."""
        validate_slug(grant_key, field_name="grant_key")
        grant = self._get_grant(namespace, grant_key)
        with self._state_lock:
            self._store.delete(
                namespace,
                self._scoped_key(grant.tenant_deployment_id, grant_key),
            )

    @staticmethod
    def _scoped_key(tenant_deployment_id: str, identifier: str) -> str:
        """Return one collision-free KV key within a tenant namespace."""
        return f"{tenant_deployment_id}::{identifier}"

    def _parse_grant(self, raw_value: str) -> AuthorizationGrant:
        """Parse one stored grant or fail closed."""
        try:
            grant = AuthorizationGrant.model_validate_json(raw_value)
        except ValidationError as exc:
            raise AuthorizationPolicyError(
                "authorization grant store is corrupt",
                status_code=500,
            ) from exc
        return validate_grant(grant)

    def _parse_combination(self, raw_value: str) -> SsoCombinationScope:
        """Parse one stored combination or fail closed."""
        try:
            combination = SsoCombinationScope.model_validate_json(raw_value)
        except ValidationError as exc:
            raise AuthorizationPolicyError(
                "sso combination store is corrupt",
                status_code=500,
            ) from exc
        return validate_combination(combination)


def get_authorization_service(request: Request) -> AuthorizationPlaneService:
    """Return the wired authorization-plane service from application state."""
    service = getattr(request.app.state, "authorization_service", None)
    if service is None:
        raise HTTPException(
            status_code=503, detail="authorization service not ready"
        )
    return service


def _raise_policy_error(exc: AuthorizationPolicyError) -> None:
    """Translate a closed policy failure into an HTTP error."""
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@authorization_router.put(
    "/software-unit-grants/{grant_key}",
    response_model=AuthorizationGrant,
)
def put_software_unit_grant(
    grant_key: str,
    grant: AuthorizationGrant,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> AuthorizationGrant:
    """Create or replace one software-unit grant."""
    try:
        return service.put_software_unit_grant(grant_key, grant)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.get(
    "/software-unit-grants",
    response_model=list[AuthorizationGrant],
)
def list_software_unit_grants(
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> list[AuthorizationGrant]:
    """List stored software-unit grants."""
    try:
        return service.list_software_unit_grants()
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.get(
    "/software-unit-grants/{grant_key}",
    response_model=AuthorizationGrant,
)
def get_software_unit_grant(
    grant_key: str,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> AuthorizationGrant:
    """Return one stored software-unit grant."""
    try:
        return service.get_software_unit_grant(grant_key)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.delete("/software-unit-grants/{grant_key}", status_code=204)
def delete_software_unit_grant(
    grant_key: str,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> None:
    """Delete one software-unit grant."""
    try:
        service.delete_software_unit_grant(grant_key)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.post(
    "/software-units:decide",
    response_model=AuthorizationDecision,
)
def decide_software_unit_endpoint(
    body: SoftwareUnitDecisionRequest,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> AuthorizationDecision:
    """Decide software-unit access from stored grants and an assignment snapshot."""
    try:
        return service.decide_software_unit(body)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.put("/menu-grants/{grant_key}", response_model=AuthorizationGrant)
def put_menu_grant(
    grant_key: str,
    grant: AuthorizationGrant,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> AuthorizationGrant:
    """Create or replace one menu grant."""
    try:
        return service.put_menu_grant(grant_key, grant)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.get("/menu-grants", response_model=list[AuthorizationGrant])
def list_menu_grants(
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> list[AuthorizationGrant]:
    """List stored menu grants."""
    try:
        return service.list_menu_grants()
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.get("/menu-grants/{grant_key}", response_model=AuthorizationGrant)
def get_menu_grant(
    grant_key: str,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> AuthorizationGrant:
    """Return one stored menu grant."""
    try:
        return service.get_menu_grant(grant_key)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.delete("/menu-grants/{grant_key}", status_code=204)
def delete_menu_grant(
    grant_key: str,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> None:
    """Delete one menu grant."""
    try:
        service.delete_menu_grant(grant_key)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.post("/menus:decide", response_model=AuthorizationDecision)
def decide_menu_endpoint(
    body: MenuDecisionRequest,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> AuthorizationDecision:
    """Decide menu access from stored grants and an assignment snapshot."""
    try:
        return service.decide_menu(body)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.put(
    "/sso-combination-scopes/{combination_name}",
    response_model=SsoCombinationScope,
)
def put_sso_combination(
    combination_name: str,
    combination: SsoCombinationScope,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> SsoCombinationScope:
    """Create or replace one SSO combination of software units."""
    try:
        return service.put_combination(combination_name, combination)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.get(
    "/sso-combination-scopes",
    response_model=list[SsoCombinationScope],
)
def list_sso_combinations(
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> list[SsoCombinationScope]:
    """List stored SSO combinations."""
    try:
        return service.list_combinations()
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.get(
    "/sso-combination-scopes/{combination_name}",
    response_model=SsoCombinationScope,
)
def get_sso_combination(
    combination_name: str,
    tenant_deployment_id: str | None = Query(default=None),
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> SsoCombinationScope:
    """Return one stored SSO combination."""
    try:
        return service.get_combination(
            combination_name,
            tenant_deployment_id=tenant_deployment_id,
        )
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.delete(
    "/sso-combination-scopes/{combination_name}",
    status_code=204,
)
def delete_sso_combination(
    combination_name: str,
    tenant_deployment_id: str | None = Query(default=None),
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> None:
    """Delete one SSO combination."""
    try:
        service.delete_combination(
            combination_name,
            tenant_deployment_id=tenant_deployment_id,
        )
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)


@authorization_router.post(
    "/sso-combinations:decide",
    response_model=SsoCombinationDecision,
)
def decide_sso_combination_endpoint(
    body: SsoCombinationDecisionRequest,
    service: AuthorizationPlaneService = Depends(get_authorization_service),
) -> SsoCombinationDecision:
    """Decide whether one Keyverse session may cover a stored RP combination."""
    try:
        return service.decide_combination(body)
    except AuthorizationPolicyError as exc:
        _raise_policy_error(exc)
