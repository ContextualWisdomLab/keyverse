"""DB-backed runtime federation registry with redacted operator responses.

External identity providers are deployment configuration, never committed realm
code. Desired state is stored in the KV/DB backend and converged into Keycloak.
Stored and applied secrets never enter HTTP responses: only explicitly approved,
non-secret provider fields are disclosed to operators.
"""
from __future__ import annotations

import logging
import threading
from urllib.parse import SplitResult, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .kv_store import KvStore
from .product_keycloak_client import ProductAdminApi

logger = logging.getLogger(__name__)

FEDERATION_PROVIDER_NAMESPACE = "federation_identity_providers"
_SUPPORTED_PROVIDER_IDS = {"saml", "oidc", "keycloak-oidc"}
_MAX_PROVIDER_ALIAS_LENGTH = 63
_MAX_PROVIDER_CONFIG_ENTRIES = 64
_MAX_PROVIDER_CONFIG_KEY_LENGTH = 128
_MAX_PROVIDER_CONFIG_VALUE_LENGTH = 16_384
_REDACTED_VALUE = "<redacted>"
_ALIAS_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_ALIAS_EDGE_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_HTTP_SCHEMES = frozenset({"http", "https"})
_SAML_ENTITY_ID_MAX_LENGTH = 1_024
_UNRESOLVED_TEMPLATE_MARKERS = ("{{", "}}")
# Unknown fields are redacted. This allowlist contains only values that are
# useful for operator diagnosis and are not credential material.
_EXPOSED_PROVIDER_CONFIG_KEYS = frozenset(
    {
        "alias",
        "authorizationUrl",
        "backchannelSupported",
        "defaultScope",
        "entityId",
        "guiOrder",
        "hideOnLoginPage",
        "idpEntityId",
        "issuer",
        "logoutUrl",
        "metadataDescriptorUrl",
        "principalAttribute",
        "principalType",
        "signatureAlgorithm",
        "singleLogoutServiceUrl",
        "singleSignOnServiceUrl",
        "syncMode",
        "tokenUrl",
        "useJwksUrl",
        "useMetadataDescriptorUrl",
        "userInfoUrl",
        "validateSignature",
    }
)


class IdentityProviderRegistration(BaseModel):
    """Desired state for one external identity provider."""

    model_config = ConfigDict(extra="forbid")

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


class IdentityProviderValidationResult(BaseModel):
    """Redacted result proving a registration is ready for persistence."""

    registration: IdentityProviderView
    ready_to_apply: bool = True


class IdentityProviderStatus(BaseModel):
    """Redacted stored registration plus its Keycloak convergence status."""

    registration: IdentityProviderView
    applied_to_keycloak: bool


class FederationService:
    """Persist desired IdP state and reconcile Keycloak without lock-held I/O."""

    def __init__(self, store: KvStore, api: ProductAdminApi) -> None:
        """Create a federation service around one store and Keycloak client."""
        self._store = store
        self._api = api
        self._state_lock = threading.RLock()
        self._convergence_lock = threading.RLock()

    def validate_registration(
        self, registration: IdentityProviderRegistration
    ) -> IdentityProviderValidationResult:
        """Validate desired state without storage or Keycloak side effects."""
        _validate_registration(registration)
        return IdentityProviderValidationResult(
            registration=IdentityProviderView.from_registration(registration)
        )

    def list_registrations(self) -> list[IdentityProviderStatus]:
        """Return all stored registrations with live convergence status."""
        with self._state_lock:
            raw_values = list(
                self._store.get_all(FEDERATION_PROVIDER_NAMESPACE).values()
            )
        registrations = [
            self._parse_registration(raw_value) for raw_value in raw_values
        ]
        statuses = [
            self._status_for(registration) for registration in registrations
        ]
        return sorted(statuses, key=lambda item: item.registration.provider_alias)

    def get_registration(self, provider_alias: str) -> IdentityProviderStatus:
        """Return one stored registration or raise HTTP 404."""
        _validate_provider_alias(provider_alias)
        with self._state_lock:
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
        """Validate, persist, and attempt to converge one provider."""
        if registration.provider_alias != provider_alias:
            raise HTTPException(
                status_code=400,
                detail="path alias and body provider_alias must match",
            )
        _validate_registration(registration)
        with self._convergence_lock:
            with self._state_lock:
                self._store.put(
                    FEDERATION_PROVIDER_NAMESPACE,
                    provider_alias,
                    registration.model_dump_json(),
                )
            applied = self._try_apply(registration)
        return self._status_for(registration, applied=applied)

    def delete_registration(self, provider_alias: str) -> None:
        """Remove one provider from Keycloak and the desired-state store."""
        _validate_provider_alias(provider_alias)
        with self._convergence_lock:
            with self._state_lock:
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
            with self._state_lock:
                self._store.delete(
                    FEDERATION_PROVIDER_NAMESPACE, provider_alias
                )

    def apply_all(self) -> list[IdentityProviderStatus]:
        """Re-converge Keycloak from a snapshot of stored desired state."""
        with self._state_lock:
            raw_values = list(
                self._store.get_all(FEDERATION_PROVIDER_NAMESPACE).values()
            )
        registrations = [
            self._parse_registration(raw_value) for raw_value in raw_values
        ]
        statuses: list[IdentityProviderStatus] = []
        with self._convergence_lock:
            for registration in registrations:
                statuses.append(
                    self._status_for(
                        registration,
                        applied=self._try_apply(registration),
                    )
                )
        return sorted(statuses, key=lambda item: item.registration.provider_alias)

    def _parse_registration(self, raw_value: str) -> IdentityProviderRegistration:
        """Parse and validate one stored registration."""
        registration = IdentityProviderRegistration.model_validate_json(raw_value)
        _validate_registration(registration)
        return registration

    def _apply(self, registration: IdentityProviderRegistration) -> None:
        """Create or replace one Keycloak identity-provider instance."""
        payload = _to_keycloak_payload(registration)
        existing = self._api.get_identity_provider(registration.provider_alias)
        if existing is None:
            self._api.create_identity_provider(payload)
        else:
            self._api.update_identity_provider(
                registration.provider_alias, payload
            )

    def _try_apply(self, registration: IdentityProviderRegistration) -> bool:
        """Attempt convergence and report failure without losing desired state."""
        try:
            self._apply(registration)
        except Exception:
            logger.exception(
                "identity-provider convergence failed alias=%s",
                registration.provider_alias,
            )
            return False
        return True

    def _status_for(
        self,
        registration: IdentityProviderRegistration,
        *,
        applied: bool | None = None,
    ) -> IdentityProviderStatus:
        """Build a redacted status, tolerating temporary Keycloak outages."""
        if applied is None:
            try:
                applied = (
                    self._api.get_identity_provider(
                        registration.provider_alias
                    )
                    is not None
                )
            except Exception:
                logger.warning(
                    "identity-provider status unavailable alias=%s",
                    registration.provider_alias,
                    exc_info=True,
                )
                applied = False
        return IdentityProviderStatus(
            registration=IdentityProviderView.from_registration(registration),
            applied_to_keycloak=applied,
        )


def _validate_provider_alias(provider_alias: str) -> None:
    """Validate one ASCII lowercase alphanumeric-and-hyphen provider alias."""
    valid = (
        isinstance(provider_alias, str)
        and 1 <= len(provider_alias) <= _MAX_PROVIDER_ALIAS_LENGTH
        and provider_alias[0] in _ALIAS_EDGE_ALPHABET
        and provider_alias[-1] in _ALIAS_EDGE_ALPHABET
        and all(character in _ALIAS_ALPHABET for character in provider_alias)
    )
    if not valid:
        raise HTTPException(
            status_code=400,
            detail="provider_alias must be an ASCII lowercase URL-safe slug",
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
        if any(
            marker in config_value
            for marker in _UNRESOLVED_TEMPLATE_MARKERS
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "provider_config contains unresolved template placeholders"
                ),
            )
    if registration.provider_id == "saml":
        _validate_saml_registration(registration.provider_config)


def _provider_config_error(field_name: str, requirement: str) -> None:
    """Raise one bounded non-secret provider configuration error."""
    raise HTTPException(
        status_code=400,
        detail=f"{field_name} {requirement}",
    )


def _validate_provider_boolean(
    provider_config: dict[str, str], field_name: str
) -> bool:
    """Parse one required Keycloak configuration boolean strictly."""
    raw_value = provider_config.get(field_name)
    if raw_value is None:
        _provider_config_error(field_name, "is required and must be true or false")
    normalized = raw_value.strip().lower()
    if normalized not in {"true", "false"}:
        _provider_config_error(field_name, "must be true or false")
    return normalized == "true"


def _validate_absolute_uri(
    provider_config: dict[str, str],
    field_name: str,
    *,
    maximum_length: int,
) -> SplitResult:
    """Validate one bounded absolute URI without dereferencing it."""
    value = provider_config.get(field_name, "")
    invalid_text = (
        not value
        or len(value) > maximum_length
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    )
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    invalid_uri = (
        parsed is None
        or not parsed.scheme
        or parsed.username is not None
        or parsed.password is not None
        or (
            parsed.scheme.lower() in _HTTP_SCHEMES
            and parsed.hostname is None
        )
    )
    if invalid_text or invalid_uri:
        _provider_config_error(field_name, "must be a bounded absolute URI")
    return parsed


def _validate_http_url(
    provider_config: dict[str, str], field_name: str
) -> None:
    """Validate one HTTP(S) network location without fetching it."""
    parsed = _validate_absolute_uri(
        provider_config,
        field_name,
        maximum_length=_MAX_PROVIDER_CONFIG_VALUE_LENGTH,
    )
    if (
        parsed.scheme.lower() not in _HTTP_SCHEMES
        or parsed.hostname is None
        or bool(parsed.fragment)
    ):
        _provider_config_error(
            field_name,
            "must be an absolute HTTP(S) URL without a fragment",
        )


def _validate_saml_registration(provider_config: dict[str, str]) -> None:
    """Enforce issuer, endpoint, signature, and certificate-source policy."""
    _validate_absolute_uri(
        provider_config,
        "entityId",
        maximum_length=_SAML_ENTITY_ID_MAX_LENGTH,
    )
    _validate_absolute_uri(
        provider_config,
        "idpEntityId",
        maximum_length=_SAML_ENTITY_ID_MAX_LENGTH,
    )
    _validate_http_url(provider_config, "singleSignOnServiceUrl")
    if not _validate_provider_boolean(provider_config, "validateSignature"):
        _provider_config_error(
            "validateSignature",
            "must be true for SAML identity providers",
        )
    use_metadata = _validate_provider_boolean(
        provider_config, "useMetadataDescriptorUrl"
    )
    if use_metadata:
        _validate_http_url(provider_config, "metadataDescriptorUrl")
        return
    if not provider_config.get("signingCertificate", "").strip():
        _provider_config_error(
            "signingCertificate",
            "is required when metadata certificate refresh is disabled",
        )

def _redacted_provider_config(
    provider_config: dict[str, str],
) -> dict[str, str]:
    """Expose only explicitly safe provider configuration values."""
    return {
        config_key: (
            config_value
            if config_key in _EXPOSED_PROVIDER_CONFIG_KEYS
            else _REDACTED_VALUE
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


@federation_router.post(
    "/identity-providers:validate",
    response_model=IdentityProviderValidationResult,
)
def validate_identity_provider(
    registration: IdentityProviderRegistration,
    service: FederationService = Depends(get_federation_service),
) -> IdentityProviderValidationResult:
    """Validate provider desired state without writing or converging it."""
    return service.validate_registration(registration)


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
