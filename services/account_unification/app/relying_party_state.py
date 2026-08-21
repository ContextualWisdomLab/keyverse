"""Durable, secret-free OIDC relying-party desired-state reconciliation.

The pure preflight in :mod:`app.relying_party` remains the policy boundary for
rendered Keycloak client representations. This module separately stores
validated operator intent, reconciles exact Keycloak clients, and returns only
observable non-secret status. Storage locks never cover Keycloak network I/O.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from enum import StrEnum
from typing import Any, Final

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from .identifiers import InvalidIdentifierError, validate_path_segment
from .kv_store import KvStore
from .relying_party import (
    RelyingPartyRegistration,
    _parse_registration,
    validate_relying_party_registration,
)
from .relying_party_admin import RelyingPartyAdminApi

logger = logging.getLogger(__name__)

RELYING_PARTY_NAMESPACE: Final = "relying_party_sources"
RELYING_PARTY_RECEIPT_NAMESPACE: Final = "relying_party_apply_receipts"


class RelyingPartyConvergenceState(StrEnum):
    """Observable relationship between desired state and Keycloak."""

    IN_SYNC = "in_sync"
    DRIFTED = "drifted"
    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"
    APPLY_FAILED = "apply_failed"


class RelyingPartyStatus(BaseModel):
    """Secret-free desired-state and convergence receipt for one client."""

    model_config = ConfigDict(use_enum_values=False)

    registration: RelyingPartyRegistration
    desired_state_stored: bool = True
    convergence_state: RelyingPartyConvergenceState
    client_uuid: str | None = None
    last_apply_receipt_matches: bool = False
    last_convergence_error_code: str | None = None


class RelyingPartyService:
    """Persist validated RP intent and reconcile exact Keycloak clients."""

    def __init__(self, store: KvStore, api: RelyingPartyAdminApi) -> None:
        """Create one service around a KV backend and Keycloak client port."""
        self._store = store
        self._api = api
        self._state_lock = threading.RLock()
        self._client_locks_guard = threading.RLock()
        self._client_locks: dict[str, threading.RLock] = {}

    def list_registrations(self) -> list[RelyingPartyStatus]:
        """Return every stored relying party with a live observable status."""
        with self._state_lock:
            snapshot = list(self._store.get_all(RELYING_PARTY_NAMESPACE).items())
        registrations: list[RelyingPartyRegistration] = []
        for stored_client_id, raw_value in snapshot:
            registration = self._parse_registration(raw_value)
            if registration.client_id != stored_client_id:
                raise HTTPException(status_code=500, detail="stored_state_invalid")
            registrations.append(registration)
        statuses = [self._status_for(registration) for registration in registrations]
        return sorted(statuses, key=lambda item: item.registration.client_id)

    def get_registration(self, client_id: str) -> RelyingPartyStatus:
        """Return one stored relying party or a bounded HTTP error."""
        _validate_client_id(client_id)
        registration = self._get_stored_registration(client_id)
        return self._status_for(registration)

    def put_registration(
        self,
        client_id: str,
        registration: RelyingPartyRegistration,
    ) -> RelyingPartyStatus:
        """Validate, store, and attempt to converge one secret-free client."""
        _validate_client_id(client_id)
        if registration.client_id != client_id:
            raise HTTPException(
                status_code=400,
                detail="path client_id and body clientId must match",
            )
        validate_relying_party_registration(registration)
        serialized = registration.model_dump_json(by_alias=True)
        with self._client_lock(client_id):
            with self._state_lock:
                self._store.put(RELYING_PARTY_NAMESPACE, client_id, serialized)
            return self._converge(registration)

    def delete_registration(self, client_id: str) -> None:
        """Delete Keycloak first, then remove desired state and its receipt."""
        _validate_client_id(client_id)
        with self._client_lock(client_id):
            registration = self._get_stored_registration(client_id)
            try:
                matches = self._exact_clients(registration)
            except Exception:
                logger.warning(
                    "relying-party observation failed client_id=%s code=keycloak_unavailable",
                    client_id,
                )
                raise HTTPException(
                    status_code=503,
                    detail="keycloak_unavailable",
                ) from None
            if len(matches) > 1:
                raise HTTPException(status_code=409, detail="duplicate_clients")
            if matches:
                client_uuid = _client_uuid(matches[0])
                try:
                    self._api.delete_relying_party_client(client_uuid)
                except Exception:
                    logger.warning(
                        "relying-party delete failed client_id=%s code=client_delete_failed",
                        client_id,
                    )
                    raise HTTPException(
                        status_code=502,
                        detail="client_delete_failed",
                    ) from None
            with self._state_lock:
                self._store.delete(RELYING_PARTY_NAMESPACE, client_id)
                self._store.delete(RELYING_PARTY_RECEIPT_NAMESPACE, client_id)

    def reconcile_all(self) -> list[RelyingPartyStatus]:
        """Reconcile current records without applying a stale value snapshot."""
        with self._state_lock:
            client_ids = sorted(
                self._store.get_all(RELYING_PARTY_NAMESPACE).keys()
            )
        statuses: list[RelyingPartyStatus] = []
        for client_id in client_ids:
            with self._client_lock(client_id):
                try:
                    registration = self._get_stored_registration(client_id)
                except HTTPException as error:
                    if error.status_code == 404:
                        continue
                    raise
                statuses.append(self._converge(registration))
        return statuses

    def _client_lock(self, client_id: str) -> threading.RLock:
        """Return the process-local mutation lock for one stable client ID."""
        with self._client_locks_guard:
            return self._client_locks.setdefault(client_id, threading.RLock())

    def _get_stored_registration(self, client_id: str) -> RelyingPartyRegistration:
        """Read and validate one stored desired-state record."""
        with self._state_lock:
            raw_value = self._store.get(RELYING_PARTY_NAMESPACE, client_id)
        if raw_value is None:
            raise HTTPException(
                status_code=404,
                detail="relying-party desired state not found",
            )
        registration = self._parse_registration(raw_value)
        if registration.client_id != client_id:
            raise HTTPException(status_code=500, detail="stored_state_invalid")
        return registration

    @staticmethod
    def _parse_registration(raw_value: str) -> RelyingPartyRegistration:
        """Parse stored JSON and fail closed without reflecting its content."""
        try:
            registration = RelyingPartyRegistration.model_validate_json(raw_value)
            validate_relying_party_registration(registration)
        except Exception:
            logger.warning("stored relying-party desired state is invalid")
            raise HTTPException(
                status_code=500,
                detail="stored_state_invalid",
            ) from None
        return registration

    def _status_for(self, registration: RelyingPartyRegistration) -> RelyingPartyStatus:
        """Observe one live client while preserving stored operator intent."""
        receipt_matches = self._receipt_matches(registration)
        try:
            matches = self._exact_clients(registration)
        except Exception:
            logger.warning(
                "relying-party observation failed client_id=%s code=keycloak_unavailable",
                registration.client_id,
            )
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.UNAVAILABLE,
                receipt_matches=receipt_matches,
                error_code="keycloak_unavailable",
            )
        if not matches:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.ABSENT,
                receipt_matches=receipt_matches,
            )
        if len(matches) > 1:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.AMBIGUOUS,
                receipt_matches=receipt_matches,
                error_code="duplicate_clients",
            )
        client = matches[0]
        observable_matches = _observable_client_matches(registration, client)
        convergence_state = (
            RelyingPartyConvergenceState.IN_SYNC
            if observable_matches and receipt_matches
            else RelyingPartyConvergenceState.DRIFTED
        )
        return _relying_party_status(
            registration,
            convergence_state,
            client_uuid=_client_uuid(client),
            receipt_matches=receipt_matches,
        )

    def _converge(self, registration: RelyingPartyRegistration) -> RelyingPartyStatus:
        """Create or update one exact client and verify its observable state."""
        receipt_matches = self._receipt_matches(registration)
        try:
            matches = self._exact_clients(registration)
        except Exception:
            logger.warning(
                "relying-party convergence unavailable client_id=%s code=keycloak_unavailable",
                registration.client_id,
            )
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.UNAVAILABLE,
                receipt_matches=receipt_matches,
                error_code="keycloak_unavailable",
            )
        if len(matches) > 1:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.AMBIGUOUS,
                receipt_matches=receipt_matches,
                error_code="duplicate_clients",
            )

        payload = registration.model_dump(by_alias=True)
        if not matches:
            try:
                created_uuid = self._api.create_relying_party_client(payload)
            except Exception:
                logger.warning(
                    "relying-party create failed client_id=%s code=client_create_failed",
                    registration.client_id,
                )
                return _relying_party_status(
                    registration,
                    RelyingPartyConvergenceState.APPLY_FAILED,
                    receipt_matches=False,
                    error_code="client_create_failed",
                )
            return self._verify_mutation(registration, created_uuid)

        client = matches[0]
        client_uuid = _client_uuid(client)
        if _observable_client_matches(registration, client) and receipt_matches:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.IN_SYNC,
                client_uuid=client_uuid,
                receipt_matches=True,
            )
        try:
            self._api.update_relying_party_client(client_uuid, payload)
        except Exception:
            logger.warning(
                "relying-party update failed client_id=%s code=client_update_failed",
                registration.client_id,
            )
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.APPLY_FAILED,
                client_uuid=client_uuid,
                receipt_matches=False,
                error_code="client_update_failed",
            )
        return self._verify_mutation(registration, client_uuid)

    def _verify_mutation(
        self,
        registration: RelyingPartyRegistration,
        expected_uuid: str | None,
    ) -> RelyingPartyStatus:
        """Re-observe a mutation before recording its canonical apply receipt."""
        try:
            matches = self._exact_clients(registration)
        except Exception:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.APPLY_FAILED,
                receipt_matches=False,
                error_code="post_apply_observation_failed",
            )
        if len(matches) > 1:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.AMBIGUOUS,
                receipt_matches=False,
                error_code="duplicate_clients_after_apply",
            )
        if not matches:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.APPLY_FAILED,
                receipt_matches=False,
                error_code="client_missing_after_apply",
            )
        client = matches[0]
        observed_uuid = _client_uuid(client)
        if expected_uuid is not None and observed_uuid != expected_uuid:
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.APPLY_FAILED,
                client_uuid=observed_uuid,
                receipt_matches=False,
                error_code="client_identity_changed_after_apply",
            )
        if not _observable_client_matches(registration, client):
            return _relying_party_status(
                registration,
                RelyingPartyConvergenceState.APPLY_FAILED,
                client_uuid=observed_uuid,
                receipt_matches=False,
                error_code="client_state_mismatch_after_apply",
            )
        self._record_receipt(registration)
        return _relying_party_status(
            registration,
            RelyingPartyConvergenceState.IN_SYNC,
            client_uuid=observed_uuid,
            receipt_matches=True,
        )

    def _exact_clients(self, registration: RelyingPartyRegistration) -> list[dict]:
        """Return exact Keycloak client candidates for one stable client ID."""
        candidates = self._api.list_relying_party_clients(registration.client_id)
        return [
            client
            for client in candidates
            if client.get("clientId") == registration.client_id
        ]

    def _receipt_matches(self, registration: RelyingPartyRegistration) -> bool:
        """Return whether the last verified apply used this exact revision."""
        with self._state_lock:
            receipt = self._store.get(
                RELYING_PARTY_RECEIPT_NAMESPACE,
                registration.client_id,
            )
        return receipt == _desired_digest(registration)

    def _record_receipt(self, registration: RelyingPartyRegistration) -> None:
        """Persist a non-secret digest after successful live re-observation."""
        with self._state_lock:
            self._store.put(
                RELYING_PARTY_RECEIPT_NAMESPACE,
                registration.client_id,
                _desired_digest(registration),
            )


def parse_relying_party_registration(payload: Any) -> RelyingPartyRegistration:
    """Parse untrusted HTTP JSON through the non-reflective preflight parser."""
    return _parse_registration(payload)


def _validate_client_id(client_id: str) -> None:
    """Require the same bounded lowercase slug accepted by preflight."""
    try:
        registration = _parse_registration(
            {
                "clientId": client_id,
                "name": client_id,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": True,
                "clientAuthenticatorType": "none",
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "redirectUris": ["https://path-validation.invalid/callback"],
                "webOrigins": ["https://path-validation.invalid"],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "post.logout.redirect.uris": "https://path-validation.invalid/logout",
                    "access.token.lifespan": "300",
                    "backchannel.logout.session.required": "true",
                    "require.pushed.authorization.requests": "false",
                },
                "fullScopeAllowed": False,
                "defaultClientScopes": ["basic", "profile", "email"],
            }
        )
        validate_relying_party_registration(registration)
    except HTTPException:
        raise HTTPException(
            status_code=400,
            detail="client_id must be a lowercase ASCII slug",
        ) from None


def _desired_digest(registration: RelyingPartyRegistration) -> str:
    """Return a deterministic SHA-256 receipt for secret-free desired state."""
    serialized = json.dumps(
        registration.model_dump(by_alias=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _client_uuid(client: dict) -> str:
    """Return one bounded safe live Keycloak UUID or fail closed."""
    client_uuid = client.get("id")
    if not isinstance(client_uuid, str) or not client_uuid:
        raise HTTPException(
            status_code=500,
            detail="keycloak client omitted its identifier",
        )
    try:
        return validate_path_segment(
            client_uuid,
            field_name="keycloak_client_uuid",
        )
    except InvalidIdentifierError:
        raise HTTPException(
            status_code=500,
            detail="keycloak client identifier is invalid",
        ) from None


_OBSERVED_MAPPER_FIELDS: Final = frozenset(
    {"name", "protocol", "protocolMapper", "consentRequired", "config"}
)
_OBSERVED_CLAIM_RANKS: Final = {"role": 1, "org": 2, "workspace": 3}


def _observed_mapper_rank(mapper: dict) -> int | None:
    """Return the canonical rank for one structurally valid live mapper."""
    mapper_type = mapper.get("protocolMapper")
    if not isinstance(mapper_type, str):
        return None
    if mapper_type == "oidc-audience-mapper":
        return 0
    if mapper_type not in {
        "oidc-hardcoded-claim-mapper",
        "oidc-usermodel-client-role-mapper",
        "oidc-usermodel-attribute-mapper",
    }:
        return None
    config = mapper["config"]
    claim_name = config.get("claim.name")
    return _OBSERVED_CLAIM_RANKS.get(claim_name)


def _normalized_observed_mappers(
    value: object,
    registration: RelyingPartyRegistration,
) -> list[dict] | None:
    """Normalize safe Keycloak mapper output or return ``None`` on drift."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 4:
        return None

    ranked_mappers: list[tuple[int, dict]] = []
    seen_ranks: set[int] = set()
    for raw_mapper in value:
        if not isinstance(raw_mapper, dict):
            return None
        if any(not isinstance(key, str) for key in raw_mapper):
            return None
        mapper = dict(raw_mapper)
        mapper_id = mapper.pop("id", None)
        if mapper_id is not None and (
            not isinstance(mapper_id, str) or not mapper_id
        ):
            return None
        if set(mapper) != _OBSERVED_MAPPER_FIELDS:
            return None
        config = mapper.get("config")
        if not isinstance(config, dict):
            return None
        if any(not isinstance(key, str) for key in config):
            return None
        if any(not isinstance(item, str) for item in config.values()):
            return None
        mapper["config"] = dict(config)
        rank = _observed_mapper_rank(mapper)
        if rank is None or rank in seen_ranks:
            return None
        if (
            mapper["protocolMapper"] == "oidc-usermodel-client-role-mapper"
            and mapper["config"].get("claim.name") == "role"
            and "usermodel.clientRoleMapping.rolePrefix" not in mapper["config"]
        ):
            mapper["config"]["usermodel.clientRoleMapping.rolePrefix"] = ""
        seen_ranks.add(rank)
        ranked_mappers.append((rank, mapper))

    ranked_mappers.sort(key=lambda item: item[0])
    ordered = [mapper for _, mapper in ranked_mappers]
    candidate_data = registration.model_dump(by_alias=True)
    candidate_data["protocolMappers"] = ordered
    try:
        candidate = RelyingPartyRegistration.model_validate(candidate_data)
        validate_relying_party_registration(candidate)
    except Exception:
        return None
    return [
        mapper.model_dump(by_alias=True)
        for mapper in candidate.protocol_mappers
    ]

def _observable_client_matches(
    registration: RelyingPartyRegistration,
    client: dict,
) -> bool:
    """Compare closed client state after normalizing vendor mapper output."""
    desired = registration.model_dump(by_alias=True)
    observed_mappers = _normalized_observed_mappers(
        client.get("protocolMappers"),
        registration,
    )
    if observed_mappers is None:
        return False
    if observed_mappers != desired["protocolMappers"]:
        return False
    return all(
        key == "protocolMappers" or client.get(key) == value
        for key, value in desired.items()
    )


def _relying_party_status(
    registration: RelyingPartyRegistration,
    convergence_state: RelyingPartyConvergenceState,
    *,
    client_uuid: str | None = None,
    receipt_matches: bool,
    error_code: str | None = None,
) -> RelyingPartyStatus:
    """Build one consistently secret-free status model."""
    return RelyingPartyStatus(
        registration=registration,
        convergence_state=convergence_state,
        client_uuid=client_uuid,
        last_apply_receipt_matches=receipt_matches,
        last_convergence_error_code=error_code,
    )


relying_party_state_router = APIRouter(prefix="/clients", tags=["relying-parties"])


def get_relying_party_service(request: Request) -> RelyingPartyService:
    """Return or lazily construct the wired relying-party state service."""
    service = getattr(request.app.state, "relying_party_service", None)
    if service is not None:
        return service
    store = getattr(request.app.state, "config_store", None)
    api = getattr(request.app.state, "keycloak_api", None)
    if store is None or api is None:
        raise HTTPException(
            status_code=503,
            detail="relying-party service not ready",
        )
    service = RelyingPartyService(store, api)
    request.app.state.relying_party_service = service
    return service


@relying_party_state_router.get(
    "/relying-parties",
    response_model=list[RelyingPartyStatus],
    response_model_by_alias=True,
)
def list_relying_parties(
    service: RelyingPartyService = Depends(get_relying_party_service),
) -> list[RelyingPartyStatus]:
    """List every stored relying party with observable convergence state."""
    return service.list_registrations()


@relying_party_state_router.post(
    "/relying-parties:reconcile",
    response_model=list[RelyingPartyStatus],
    response_model_by_alias=True,
)
def reconcile_relying_parties(
    service: RelyingPartyService = Depends(get_relying_party_service),
) -> list[RelyingPartyStatus]:
    """Reconcile every current relying-party desired-state record."""
    return service.reconcile_all()


@relying_party_state_router.get(
    "/relying-parties/{client_id}",
    response_model=RelyingPartyStatus,
    response_model_by_alias=True,
)
def get_relying_party(
    client_id: str,
    service: RelyingPartyService = Depends(get_relying_party_service),
) -> RelyingPartyStatus:
    """Return one stored relying party and its observable status."""
    return service.get_registration(client_id)


@relying_party_state_router.put(
    "/relying-parties/{client_id}",
    response_model=RelyingPartyStatus,
    response_model_by_alias=True,
)
def put_relying_party(
    client_id: str,
    payload: Any = Body(...),
    service: RelyingPartyService = Depends(get_relying_party_service),
) -> RelyingPartyStatus:
    """Store and reconcile one validated secret-free relying party."""
    return service.put_registration(
        client_id,
        parse_relying_party_registration(payload),
    )


@relying_party_state_router.delete(
    "/relying-parties/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_relying_party(
    client_id: str,
    service: RelyingPartyService = Depends(get_relying_party_service),
) -> Response:
    """Delete one live client first, then remove its recovery intent."""
    service.delete_registration(client_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
