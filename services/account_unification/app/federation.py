"""Runtime federation registry: external IdPs are DB-backed data, not realm code.

External identity providers — the employer ADFS, LDAP-fronting brokers,
optional personal OIDC — are DEPLOYMENT configuration. The committed realm
ships with none of them; operators register providers at runtime through this
API. The desired state is persisted in the KV/DB config store (the source of
truth) and applied to Keycloak through the Admin REST API, so a rebuilt realm
can be re-converged with the ``apply`` endpoint instead of editing JSON.

Secrets in provider config (client secrets, signing keys) live only in the
store and Keycloak; responses echo configuration back without masking because
this surface is operator-scoped admin API behind the service network boundary,
matching the SCIM shim posture.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .keycloak_client import AdminApi
from .kv_store import KvStore

FEDERATION_PROVIDER_NAMESPACE = "federation_identity_providers"
_PROVIDER_ALIAS_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_SUPPORTED_PROVIDER_IDS = {"saml", "oidc", "keycloak-oidc"}


class IdentityProviderRegistration(BaseModel):
    """Desired state for one external identity provider."""

    provider_alias: str = Field(description="Keycloak IdP alias (URL-safe slug).")
    display_name: str = Field(min_length=1, max_length=120)
    provider_id: str = Field(description="Keycloak provider id: saml | oidc | keycloak-oidc.")
    enabled: bool = True
    trust_email: bool = Field(
        default=False,
        description="Trust the asserted email as verified (auto-link anchor).",
    )
    provider_config: dict[str, str] = Field(
        default_factory=dict,
        description="Keycloak IdP config map (e.g. singleSignOnServiceUrl).",
    )


class IdentityProviderStatus(BaseModel):
    """Stored registration plus whether it is applied to Keycloak."""

    registration: IdentityProviderRegistration
    applied_to_keycloak: bool


class FederationService:
    """Persist desired IdP state in the KV/DB store and converge Keycloak."""

    def __init__(self, store: KvStore, api: AdminApi) -> None:
        self._store = store
        self._api = api

    # -- registry ----------------------------------------------------------
    def list_registrations(self) -> list[IdentityProviderStatus]:
        """Return every stored registration with its applied state."""
        statuses: list[IdentityProviderStatus] = []
        for raw_value in self._store.get_all(FEDERATION_PROVIDER_NAMESPACE).values():
            registration = IdentityProviderRegistration.model_validate_json(raw_value)
            statuses.append(self._status_for(registration))
        return sorted(statuses, key=lambda s: s.registration.provider_alias)

    def get_registration(self, provider_alias: str) -> IdentityProviderStatus:
        """Return one stored registration or raise 404."""
        raw_value = self._store.get(FEDERATION_PROVIDER_NAMESPACE, provider_alias)
        if raw_value is None:
            raise HTTPException(status_code=404, detail="identity provider not registered")
        registration = IdentityProviderRegistration.model_validate_json(raw_value)
        return self._status_for(registration)

    def put_registration(
        self, provider_alias: str, registration: IdentityProviderRegistration
    ) -> IdentityProviderStatus:
        """Validate, persist to the store, and converge Keycloak."""
        if registration.provider_alias != provider_alias:
            raise HTTPException(
                status_code=400, detail="path alias and body provider_alias must match"
            )
        _validate_registration(registration)
        self._store.put(
            FEDERATION_PROVIDER_NAMESPACE,
            provider_alias,
            registration.model_dump_json(),
        )
        self._apply(registration)
        return self._status_for(registration)

    def delete_registration(self, provider_alias: str) -> None:
        """Remove the registration from Keycloak and the store."""
        raw_value = self._store.get(FEDERATION_PROVIDER_NAMESPACE, provider_alias)
        if raw_value is None:
            raise HTTPException(status_code=404, detail="identity provider not registered")
        if self._api.get_identity_provider(provider_alias) is not None:
            self._api.delete_identity_provider(provider_alias)
        self._store.delete(FEDERATION_PROVIDER_NAMESPACE, provider_alias)

    def apply_all(self) -> list[IdentityProviderStatus]:
        """Re-converge Keycloak from the stored desired state (e.g. after a realm rebuild)."""
        statuses: list[IdentityProviderStatus] = []
        for raw_value in self._store.get_all(FEDERATION_PROVIDER_NAMESPACE).values():
            registration = IdentityProviderRegistration.model_validate_json(raw_value)
            self._apply(registration)
            statuses.append(self._status_for(registration))
        return sorted(statuses, key=lambda s: s.registration.provider_alias)

    # -- convergence -------------------------------------------------------
    def _apply(self, registration: IdentityProviderRegistration) -> None:
        payload = _to_keycloak_payload(registration)
        existing = self._api.get_identity_provider(registration.provider_alias)
        if existing is None:
            self._api.create_identity_provider(payload)
        else:
            self._api.update_identity_provider(registration.provider_alias, payload)

    def _status_for(
        self, registration: IdentityProviderRegistration
    ) -> IdentityProviderStatus:
        applied = self._api.get_identity_provider(registration.provider_alias) is not None
        return IdentityProviderStatus(
            registration=registration, applied_to_keycloak=applied
        )


def _validate_registration(registration: IdentityProviderRegistration) -> None:
    if not _PROVIDER_ALIAS_PATTERN.fullmatch(registration.provider_alias):
        raise HTTPException(
            status_code=400,
            detail="provider_alias must be a lowercase URL-safe slug",
        )
    if registration.provider_id not in _SUPPORTED_PROVIDER_IDS:
        raise HTTPException(
            status_code=400,
            detail="provider_id must be one of: saml, oidc, keycloak-oidc",
        )


def _to_keycloak_payload(registration: IdentityProviderRegistration) -> dict:
    return {
        "alias": registration.provider_alias,
        "displayName": registration.display_name,
        "providerId": registration.provider_id,
        "enabled": registration.enabled,
        "trustEmail": registration.trust_email,
        "storeToken": False,
        "addReadTokenRoleOnCreate": False,
        "authenticateByDefault": False,
        "linkOnly": False,
        "config": dict(registration.provider_config),
    }


federation_router = APIRouter(prefix="/federation", tags=["federation"])


def get_federation_service(request: Request) -> FederationService:
    """Return the wired federation service from application state."""
    service = getattr(request.app.state, "federation_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="federation service not ready")
    return service


@federation_router.get(
    "/identity-providers", response_model=list[IdentityProviderStatus]
)
def list_identity_providers(
    service: FederationService = Depends(get_federation_service),
) -> list[IdentityProviderStatus]:
    """List every registered external identity provider."""
    return service.list_registrations()


@federation_router.get(
    "/identity-providers/{provider_alias}", response_model=IdentityProviderStatus
)
def get_identity_provider(
    provider_alias: str,
    service: FederationService = Depends(get_federation_service),
) -> IdentityProviderStatus:
    """Return one registered external identity provider."""
    return service.get_registration(provider_alias)


@federation_router.put(
    "/identity-providers/{provider_alias}", response_model=IdentityProviderStatus
)
def put_identity_provider(
    provider_alias: str,
    registration: IdentityProviderRegistration,
    service: FederationService = Depends(get_federation_service),
) -> IdentityProviderStatus:
    """Register or update an external identity provider (store + converge)."""
    return service.put_registration(provider_alias, registration)


@federation_router.delete("/identity-providers/{provider_alias}", status_code=204)
def delete_identity_provider(
    provider_alias: str,
    service: FederationService = Depends(get_federation_service),
) -> None:
    """Remove an external identity provider from Keycloak and the store."""
    service.delete_registration(provider_alias)


@federation_router.post(
    "/identity-providers:apply", response_model=list[IdentityProviderStatus]
)
def apply_identity_providers(
    service: FederationService = Depends(get_federation_service),
) -> list[IdentityProviderStatus]:
    """Re-converge Keycloak from the stored desired state."""
    return service.apply_all()
