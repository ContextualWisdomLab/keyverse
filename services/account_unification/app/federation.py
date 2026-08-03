"""DB-backed runtime federation registry with redacted operator responses.

External identity providers are deployment configuration, never committed realm
code. Desired state is stored in the KV/DB backend and converged into Keycloak.
Secrets remain in the store and Keycloak payloads but are redacted from every
HTTP response and status object.
"""
from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .kv_store import KvStore
from .product_keycloak_client import ProductAdminApi

FEDERATION_PROVIDER_NAMESPACE = "federation_identity_providers"
_SUPPORTED_PROVIDER_IDS = {"saml", "oidc", "keycloak-oidc"}
_MAX_PROVIDER_ALIAS_LENGTH = 63
_MAX_PROVIDER_CONFIG_ENTRIES = 64
_MAX_PROVIDER_CONFIG_KEY_LENGTH = 128
_MAX_PROVIDER_CONFIG_VALUE_LENGTH = 16_384
_REDACTED_VALUE = "<redacted>"
_SENSITIVE_CONFIG_KEY_FRAGMENTS = (
    "secret",
    "password",
    "privatekey",
    "signingkey",
    "clientassertion",
    "apikey",
    "accesskey",
    "credential",
)


class IdentityProviderRegistration(BaseModel):
    """Desired state for one external identity provider."""

    provider_alias: str = Field(description="Keycloak IdP alias (URL-safe slug).")
    display_name: str = Field(min_length=1, max_length=120)
    provider_id: str = Field(
        description="Keycloak provider id: saml | oidc | keycloak-oidc."
    )
    enabled: bool = True
    trust_email: bool = Field(
        default=False,
        description="Trust the asserted email as verified.",
    )
    provider_config: dict[str, str] = Field(
        default_factory=dict,
        description="Keycloak IdP configuration map.",
    )


class IdentityProviderView(BaseModel):
    """Safe operator view of a provider registration with secrets redacted."""

    provider_alias: str
    display_name: str
    provider_id: str
    enabled: bool
    trust_email: bool
    provider_config: dict[str, str]

    @classmethod
    def from_registration(
        cls, registration: IdentityProviderRegistration
    ) -> "IdentityProviderView":
        """Build a redacted view from stored desired state."""
        return cls(
            provider_alias=registration.provider_alias,
            display_name=registration.display_name,
            provider_id=registration.provider_id,
            enabled=registration.enabled,
            trust_email=registration.trust_email,
            provider_config=_redacted_provider_config(
                registration.provider_config
            ),
        )


class IdentityProviderStatus(BaseModel):
    """Redacted stored registration plus its Keycloak convergence status."""

    registration: IdentityProviderView
    applied_to_keycloak: bool


class FederationService:
    """Persist desired IdP state and converge Keycloak under one process lock."""

    def __init__(self, store: KvStore, api: ProductAdminApi) -> None:
        """Create a federation service around one store and Keycloak client."""
        self._store = store
        self._api = api
        self._lock = threading.RLock()

    def list_registrations(self) -> list[IdentityProviderStatus]:
        """Return all stored registrations with redacted configuration."""
        with self._lock:
            statuses = [
                self._status_for(self._parse_registration(raw_value))
                for raw_value in self._store.get_all(
                    FEDERATION_PROVIDER_NAMESPACE
                ).values()
            ]
        return sorted(statuses, key=lambda item: item.registration.provider_alias)

    def get_registration(self, provider_alias: str) -> IdentityProviderStatus:
        """Return one stored registration or raise HTTP 404."""
        _validate_provider_alias(provider_alias)
        with self._lock:
            raw_value = self._store.get(
                FEDERATION_PROVIDER_NAMESPACE, provider_alias
            )
            if raw_value is None:
                raise HTTPException(
                    status_code=404,
                    detail="identity provider not registered",
                )
            return self._status_for(self._parse_registration(raw_value))

    def put_registration(
        self,
        provider_alias: str,
        registration: IdentityProviderRegistration,
    ) -> IdentityProviderStatus:
        """Validate, persist, and converge one provider registration."""
        if registration.provider_alias != provider_alias:
            raise HTTPException(
                status_code=400,
                detail="path alias and body provider_alias must match",
            )
        _validate_registration(registration)
        with self._lock:
            self._store.put(
                FEDERATION_PROVIDER_NAMESPACE,
                provider_alias,
                registration.model_dump_json(),
            )
            self._apply(registration)
            return self._status_for(registration)

    def delete_registration(self, provider_alias: str) -> None:
        """Remove one provider from Keycloak and the desired-state store."""
        _validate_provider_alias(provider_alias)
        with self._lock:
            raw_value = self._store.get(
                FEDERATION_PROVIDER_NAMESPACE, provider_alias
            )
            if raw_value is None:
                raise HTTPException(
                    status_code=404,
                    detail="identity provider not registered",
                )
            if self._api.get_identity_provider(provider_alias) is not None:
                self._api.delete_identity_provider(provider_alias)
            self._store.delete(FEDERATION_PROVIDER_NAMESPACE, provider_alias)

    def apply_all(self) -> list[IdentityProviderStatus]:
        """Re-converge Keycloak from all stored desired state."""
        with self._lock:
            registrations = [
                self._parse_registration(raw_value)
                for raw_value in self._store.get_all(
                    FEDERATION_PROVIDER_NAMESPACE
                ).values()
            ]
            statuses: list[IdentityProviderStatus] = []
            for registration in registrations:
                self._apply(registration)
                statuses.append(self._status_for(registration))
        return sorted(statuses, key=lambda item: item.registration.provider_alias)

    def _parse_registration(self, raw_value: str) -> IdentityProviderRegistration:
        """Parse and validate one stored registration."""
        registration = IdentityProviderRegistration.model_validate_json(raw_value)
        _validate_registration(registration)
        return registration

    def _apply(self, registration: IdentityProviderRegistration) -> None:
        """Create or replace one Keycloak identity-provider instance."""
        payload = _to_keycloak_payload(registration)
        existing = self._api.get_identity_provider(
            registration.provider_alias
        )
        if existing is None:
            self._api.create_identity_provider(payload)
        else:
            self._api.update_identity_provider(
                registration.provider_alias, payload
            )

    def _status_for(
        self, registration: IdentityProviderRegistration
    ) -> IdentityProviderStatus:
        """Build a redacted status from desired and applied state."""
        applied = (
            self._api.get_identity_provider(registration.provider_alias)
            is not None
        )
        return IdentityProviderStatus(
            registration=IdentityProviderView.from_registration(registration),
            applied_to_keycloak=applied,
        )


def _validate_provider_alias(provider_alias: str) -> None:
    """Validate a lowercase alphanumeric-and-hyphen provider alias."""
    valid = (
        1 <= len(provider_alias) <= _MAX_PROVIDER_ALIAS_LENGTH
        and provider_alias[0].isalnum()
        and provider_alias[-1].isalnum()
        and all(
            character.islower()
            or character.isdigit()
            or character == "-"
            for character in provider_alias
        )
    )
    if not valid:
        raise HTTPException(
            status_code=400,
            detail="provider_alias must be a lowercase URL-safe slug",
        )


def _validate_registration(
    registration: IdentityProviderRegistration,
) -> None:
    """Validate one provider registration and bounded config map."""
    _validate_provider_alias(registration.provider_alias)
    if registration.provider_id not in _SUPPORTED_PROVIDER_IDS:
        raise HTTPException(
            status_code=400,
            detail="provider_id must be one of: saml, oidc, keycloak-oidc",
        )
    if len(registration.provider_config) > _MAX_PROVIDER_CONFIG_ENTRIES:
        raise HTTPException(
            status_code=400,
            detail="provider_config contains too many entries",
        )
    for config_key, config_value in registration.provider_config.items():
        if (
            not config_key
            or len(config_key) > _MAX_PROVIDER_CONFIG_KEY_LENGTH
            or len(config_value) > _MAX_PROVIDER_CONFIG_VALUE_LENGTH
        ):
            raise HTTPException(
                status_code=400,
                detail="provider_config key or value exceeds allowed bounds",
            )


def _normalized_config_key(config_key: str) -> str:
    """Normalize one config key for deterministic sensitivity checks."""
    return "".join(
        character
        for character in config_key.lower()
        if character.isalnum()
    )


def _is_sensitive_config_key(config_key: str) -> bool:
    """Return whether a provider config key conventionally carries a secret."""
    normalized = _normalized_config_key(config_key)
    return any(
        fragment in normalized
        for fragment in _SENSITIVE_CONFIG_KEY_FRAGMENTS
    )


def _redacted_provider_config(
    provider_config: dict[str, str],
) -> dict[str, str]:
    """Return a copy with credential-bearing values replaced."""
    return {
        config_key: (
            _REDACTED_VALUE
            if _is_sensitive_config_key(config_key)
            else config_value
        )
        for config_key, config_value in provider_config.items()
    }


def _to_keycloak_payload(
    registration: IdentityProviderRegistration,
) -> dict:
    """Convert desired state to a Keycloak Admin API representation."""
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
        raise HTTPException(
            status_code=503, detail="federation service not ready"
        )
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
    "/identity-providers/{provider_alias}",
    response_model=IdentityProviderStatus,
)
def get_identity_provider(
    provider_alias: str,
    service: FederationService = Depends(get_federation_service),
) -> IdentityProviderStatus:
    """Return one registered external identity provider."""
    return service.get_registration(provider_alias)


@federation_router.put(
    "/identity-providers/{provider_alias}",
    response_model=IdentityProviderStatus,
)
def put_identity_provider(
    provider_alias: str,
    registration: IdentityProviderRegistration,
    service: FederationService = Depends(get_federation_service),
) -> IdentityProviderStatus:
    """Register or update one provider and converge Keycloak."""
    return service.put_registration(provider_alias, registration)


@federation_router.delete(
    "/identity-providers/{provider_alias}", status_code=204
)
def delete_identity_provider(
    provider_alias: str,
    service: FederationService = Depends(get_federation_service),
) -> None:
    """Remove one provider from Keycloak and desired state."""
    service.delete_registration(provider_alias)


@federation_router.post(
    "/identity-providers:apply",
    response_model=list[IdentityProviderStatus],
)
def apply_identity_providers(
    service: FederationService = Depends(get_federation_service),
) -> list[IdentityProviderStatus]:
    """Re-converge Keycloak from the stored desired state."""
    return service.apply_all()
