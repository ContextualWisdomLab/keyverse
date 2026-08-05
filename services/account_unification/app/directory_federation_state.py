"""Durable LDAP desired state and Keycloak component reconciliation.

This module extends the side-effect-free directory preflight with a separate
stateful lifecycle. Private rendered components are stored in the configured KV
backend, while every operator response redacts bind identity and credentials.
Storage critical sections never include Keycloak network I/O.
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
from enum import StrEnum
from typing import Final

from fastapi import Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from .directory_federation import (
    DirectoryFederationRegistration,
    DirectoryFederationView,
    directory_federation_router,
    validate_directory_registration,
)
from .kv_store import KvStore
from .product_keycloak_client import ProductAdminApi

logger = logging.getLogger(__name__)

DIRECTORY_FEDERATION_NAMESPACE: Final = "directory_federation_sources"
DIRECTORY_FEDERATION_RECEIPT_NAMESPACE: Final = (
    "directory_federation_apply_receipts"
)
_DIRECTORY_PROVIDER_ID: Final = "ldap"
_DIRECTORY_PROVIDER_TYPE: Final = "org.keycloak.storage.UserStorageProvider"
_DIRECTORY_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SECRET_CONFIG_KEYS: Final = frozenset({"bindCredential", "bindDn"})


class DirectoryConvergenceState(StrEnum):
    """Observable relationship between desired state and Keycloak."""

    IN_SYNC = "in_sync"
    DRIFTED = "drifted"
    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"
    APPLY_FAILED = "apply_failed"


class DirectoryFederationStatus(BaseModel):
    """Redacted desired-state and convergence receipt for one directory."""

    model_config = ConfigDict(use_enum_values=False)

    registration: DirectoryFederationView
    desired_state_stored: bool = True
    convergence_state: DirectoryConvergenceState
    component_id: str | None = None
    secret_observation: str = "not_observable"
    last_apply_receipt_matches: bool = False
    last_convergence_error_code: str | None = None


class DirectoryFederationService:
    """Persist private directory intent and reconcile exact Keycloak components."""

    def __init__(self, store: KvStore, api: ProductAdminApi) -> None:
        """Create one service around a KV backend and Keycloak Admin adapter."""
        self._store = store
        self._api = api
        self._state_lock = threading.RLock()
        self._convergence_lock = threading.RLock()

    def list_registrations(self) -> list[DirectoryFederationStatus]:
        """Return every stored directory with a live redacted status."""
        with self._state_lock:
            snapshot = list(
                self._store.get_all(DIRECTORY_FEDERATION_NAMESPACE).values()
            )
        registrations = [self._parse_registration(value) for value in snapshot]
        statuses = [self._status_for(registration) for registration in registrations]
        return sorted(statuses, key=lambda item: item.registration.name)

    def get_registration(self, directory_name: str) -> DirectoryFederationStatus:
        """Return one stored directory or raise bounded HTTP 404."""
        _validate_directory_name(directory_name)
        registration = self._get_stored_registration(directory_name)
        return self._status_for(registration)

    def put_registration(
        self,
        directory_name: str,
        registration: DirectoryFederationRegistration,
    ) -> DirectoryFederationStatus:
        """Validate, store, and attempt to converge one private registration."""
        _validate_directory_name(directory_name)
        if registration.name != directory_name:
            raise HTTPException(
                status_code=400,
                detail="path name and body name must match",
            )
        validate_directory_registration(registration)
        serialized = registration.model_dump_json(by_alias=True)
        with self._convergence_lock:
            with self._state_lock:
                self._store.put(
                    DIRECTORY_FEDERATION_NAMESPACE,
                    directory_name,
                    serialized,
                )
            return self._converge(registration)

    def delete_registration(self, directory_name: str) -> None:
        """Delete Keycloak first, then remove desired state and its receipt."""
        _validate_directory_name(directory_name)
        with self._convergence_lock:
            registration = self._get_stored_registration(directory_name)
            try:
                matches = self._exact_components(registration)
            except Exception:
                logger.warning(
                    "directory observation failed name=%s code=keycloak_unavailable",
                    directory_name,
                )
                raise HTTPException(
                    status_code=503,
                    detail="keycloak_unavailable",
                ) from None
            if len(matches) > 1:
                raise HTTPException(
                    status_code=409,
                    detail="duplicate_components",
                )
            if matches:
                component_id = _component_id(matches[0])
                try:
                    self._api.delete_user_storage_component(component_id)
                except Exception:
                    logger.warning(
                        "directory delete failed name=%s code=component_delete_failed",
                        directory_name,
                    )
                    raise HTTPException(
                        status_code=502,
                        detail="component_delete_failed",
                    ) from None
            with self._state_lock:
                self._store.delete(
                    DIRECTORY_FEDERATION_NAMESPACE,
                    directory_name,
                )
                self._store.delete(
                    DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
                    directory_name,
                )

    def reconcile_all(self) -> list[DirectoryFederationStatus]:
        """Reconcile a storage snapshot without lock-held network requests."""
        with self._state_lock:
            snapshot = list(
                self._store.get_all(DIRECTORY_FEDERATION_NAMESPACE).values()
            )
        registrations = [self._parse_registration(value) for value in snapshot]
        statuses: list[DirectoryFederationStatus] = []
        with self._convergence_lock:
            for registration in registrations:
                statuses.append(self._converge(registration))
        return sorted(statuses, key=lambda item: item.registration.name)

    def _get_stored_registration(
        self,
        directory_name: str,
    ) -> DirectoryFederationRegistration:
        """Read and validate one private desired-state record."""
        with self._state_lock:
            raw_value = self._store.get(
                DIRECTORY_FEDERATION_NAMESPACE,
                directory_name,
            )
        if raw_value is None:
            raise HTTPException(
                status_code=404,
                detail="directory desired state not found",
            )
        registration = self._parse_registration(raw_value)
        if registration.name != directory_name:
            raise HTTPException(
                status_code=500,
                detail="stored_state_invalid",
            )
        return registration

    def _parse_registration(self, raw_value: str) -> DirectoryFederationRegistration:
        """Parse stored private JSON and fail closed without reflecting it."""
        try:
            registration = DirectoryFederationRegistration.model_validate_json(
                raw_value
            )
            validate_directory_registration(registration)
        except Exception:
            logger.warning("stored directory desired state is invalid")
            raise HTTPException(
                status_code=500,
                detail="stored_state_invalid",
            ) from None
        return registration

    def _status_for(
        self,
        registration: DirectoryFederationRegistration,
    ) -> DirectoryFederationStatus:
        """Observe live non-secret state while preserving private desired intent."""
        receipt_matches = self._receipt_matches(registration)
        try:
            matches = self._exact_components(registration)
        except Exception:
            logger.warning(
                "directory observation failed name=%s code=keycloak_unavailable",
                registration.name,
            )
            return _directory_status(
                registration,
                DirectoryConvergenceState.UNAVAILABLE,
                receipt_matches=receipt_matches,
                error_code="keycloak_unavailable",
            )
        if not matches:
            return _directory_status(
                registration,
                DirectoryConvergenceState.ABSENT,
                receipt_matches=receipt_matches,
            )
        if len(matches) > 1:
            return _directory_status(
                registration,
                DirectoryConvergenceState.AMBIGUOUS,
                receipt_matches=receipt_matches,
                error_code="duplicate_components",
            )
        component = matches[0]
        observable_matches = _observable_component_matches(
            registration,
            component,
        )
        convergence_state = (
            DirectoryConvergenceState.IN_SYNC
            if observable_matches and receipt_matches
            else DirectoryConvergenceState.DRIFTED
        )
        return _directory_status(
            registration,
            convergence_state,
            component_id=_component_id(component),
            receipt_matches=receipt_matches,
        )

    def _converge(
        self,
        registration: DirectoryFederationRegistration,
    ) -> DirectoryFederationStatus:
        """Create or update one exact component and record the applied revision."""
        receipt_matches = self._receipt_matches(registration)
        try:
            matches = self._exact_components(registration)
        except Exception:
            logger.warning(
                "directory convergence unavailable name=%s code=keycloak_unavailable",
                registration.name,
            )
            return _directory_status(
                registration,
                DirectoryConvergenceState.UNAVAILABLE,
                receipt_matches=receipt_matches,
                error_code="keycloak_unavailable",
            )
        if len(matches) > 1:
            return _directory_status(
                registration,
                DirectoryConvergenceState.AMBIGUOUS,
                receipt_matches=receipt_matches,
                error_code="duplicate_components",
            )

        payload = registration.model_dump(by_alias=True)
        if not matches:
            try:
                component_id = self._api.create_user_storage_component(payload)
            except Exception:
                logger.warning(
                    "directory create failed name=%s code=component_create_failed",
                    registration.name,
                )
                return _directory_status(
                    registration,
                    DirectoryConvergenceState.APPLY_FAILED,
                    receipt_matches=False,
                    error_code="component_create_failed",
                )
            self._record_receipt(registration)
            return _directory_status(
                registration,
                DirectoryConvergenceState.IN_SYNC,
                component_id=component_id,
                receipt_matches=True,
            )

        component = matches[0]
        component_id = _component_id(component)
        if _observable_component_matches(registration, component) and receipt_matches:
            return _directory_status(
                registration,
                DirectoryConvergenceState.IN_SYNC,
                component_id=component_id,
                receipt_matches=True,
            )
        try:
            self._api.update_user_storage_component(component_id, payload)
        except Exception:
            logger.warning(
                "directory update failed name=%s code=component_update_failed",
                registration.name,
            )
            return _directory_status(
                registration,
                DirectoryConvergenceState.APPLY_FAILED,
                component_id=component_id,
                receipt_matches=False,
                error_code="component_update_failed",
            )
        self._record_receipt(registration)
        return _directory_status(
            registration,
            DirectoryConvergenceState.IN_SYNC,
            component_id=component_id,
            receipt_matches=True,
        )

    def _exact_components(
        self,
        registration: DirectoryFederationRegistration,
    ) -> list[dict]:
        """Return exact LDAP user-storage components for one desired name."""
        candidates = self._api.list_user_storage_components(registration.name)
        return [
            component
            for component in candidates
            if component.get("name") == registration.name
            and component.get("providerId") == _DIRECTORY_PROVIDER_ID
            and component.get("providerType") == _DIRECTORY_PROVIDER_TYPE
        ]

    def _receipt_matches(
        self,
        registration: DirectoryFederationRegistration,
    ) -> bool:
        """Return whether the last successful apply used this exact private input."""
        with self._state_lock:
            receipt = self._store.get(
                DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
                registration.name,
            )
        return receipt == _desired_digest(registration)

    def _record_receipt(
        self,
        registration: DirectoryFederationRegistration,
    ) -> None:
        """Persist a non-secret digest after a successful exact private apply."""
        with self._state_lock:
            self._store.put(
                DIRECTORY_FEDERATION_RECEIPT_NAMESPACE,
                registration.name,
                _desired_digest(registration),
            )


def _validate_directory_name(directory_name: str) -> None:
    """Require the path name to use the same closed ASCII slug profile."""
    if _DIRECTORY_NAME.fullmatch(directory_name) is None:
        raise HTTPException(
            status_code=400,
            detail="directory_name must be a lowercase ASCII slug",
        )


def _desired_digest(registration: DirectoryFederationRegistration) -> str:
    """Return one deterministic SHA-256 receipt for the private desired state."""
    serialized = registration.model_dump_json(by_alias=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _component_id(component: dict) -> str:
    """Return one non-empty Keycloak component identifier or fail closed."""
    component_id = component.get("id")
    if not isinstance(component_id, str) or not component_id:
        raise HTTPException(
            status_code=500,
            detail="keycloak component omitted its identifier",
        )
    return component_id


def _observable_component_matches(
    registration: DirectoryFederationRegistration,
    component: dict,
) -> bool:
    """Compare every observable non-secret field in the closed profile."""
    if (
        component.get("name") != registration.name
        or component.get("providerId") != registration.provider_id
        or component.get("providerType") != registration.provider_type
    ):
        return False
    observed_config = component.get("config")
    if not isinstance(observed_config, dict):
        return False
    for key, desired_values in registration.config.items():
        if key in _SECRET_CONFIG_KEYS:
            continue
        if observed_config.get(key) != desired_values:
            return False
    return True


def _directory_status(
    registration: DirectoryFederationRegistration,
    convergence_state: DirectoryConvergenceState,
    *,
    component_id: str | None = None,
    receipt_matches: bool,
    error_code: str | None = None,
) -> DirectoryFederationStatus:
    """Build one consistently redacted status model."""
    return DirectoryFederationStatus(
        registration=DirectoryFederationView.from_registration(registration),
        convergence_state=convergence_state,
        component_id=component_id,
        last_apply_receipt_matches=receipt_matches,
        last_convergence_error_code=error_code,
    )


def get_directory_federation_service(request: Request) -> DirectoryFederationService:
    """Return or lazily construct the wired directory desired-state service."""
    service = getattr(request.app.state, "directory_federation_service", None)
    if service is not None:
        return service
    store = getattr(request.app.state, "config_store", None)
    api = getattr(request.app.state, "keycloak_api", None)
    if store is None or api is None:
        raise HTTPException(
            status_code=503,
            detail="directory federation service not ready",
        )
    service = DirectoryFederationService(store, api)
    request.app.state.directory_federation_service = service
    return service


@directory_federation_router.get(
    "/user-directories",
    response_model=list[DirectoryFederationStatus],
)
def list_user_directories(
    service: DirectoryFederationService = Depends(get_directory_federation_service),
) -> list[DirectoryFederationStatus]:
    """List every stored directory with a redacted live status."""
    return service.list_registrations()


@directory_federation_router.post(
    "/user-directories:reconcile",
    response_model=list[DirectoryFederationStatus],
)
def reconcile_user_directories(
    service: DirectoryFederationService = Depends(get_directory_federation_service),
) -> list[DirectoryFederationStatus]:
    """Reconcile every stored directory from one desired-state snapshot."""
    return service.reconcile_all()


@directory_federation_router.get(
    "/user-directories/{directory_name}",
    response_model=DirectoryFederationStatus,
)
def get_user_directory(
    directory_name: str,
    service: DirectoryFederationService = Depends(get_directory_federation_service),
) -> DirectoryFederationStatus:
    """Return one stored directory with a redacted live status."""
    return service.get_registration(directory_name)


@directory_federation_router.put(
    "/user-directories/{directory_name}",
    response_model=DirectoryFederationStatus,
)
def put_user_directory(
    directory_name: str,
    registration: DirectoryFederationRegistration,
    service: DirectoryFederationService = Depends(get_directory_federation_service),
) -> DirectoryFederationStatus:
    """Store and attempt to converge one private directory registration."""
    return service.put_registration(directory_name, registration)


@directory_federation_router.delete(
    "/user-directories/{directory_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_user_directory(
    directory_name: str,
    service: DirectoryFederationService = Depends(get_directory_federation_service),
) -> Response:
    """Delete live and desired directory state in safe remote-first order."""
    service.delete_registration(directory_name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
